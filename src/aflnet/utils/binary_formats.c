/* binary_formats.c - load binary message probes from .binary-formats.json

   This is deliberately a small JSON reader for the companion file written by
   utils/AI-agent/pro-template/gen_templates.py.  It accepts normal JSON and
   ignores fields the fuzzer does not need (layout, example_hex, framing).
   Probe value/mask fields follow the Python formats.py spelling: 0xNN strings,
   \\xNN strings, arrays of byte values, or integers. */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "alloc-inl.h"
#include "binary_formats.h"

#define JSON_MAX_DEPTH 64

typedef enum {

  JSON_NULL,
  JSON_BOOL,
  JSON_NUMBER,
  JSON_STRING,
  JSON_ARRAY,
  JSON_OBJECT

} json_type_t;

typedef struct json_value json_value_t;

typedef struct {
  char         *key;
  json_value_t *value;

} json_member_t;

struct json_value {
  json_type_t type;
  u8          number_is_integer;

  union {
    u8        boolean;
    long long number;
    char     *string;
    struct {
      json_value_t **items;
      u32            count;

    } array;
    struct {
      json_member_t *members;
      u32            count;

    } object;

  } value;
};

typedef struct {
  const char *data;
  size_t      len;
  size_t      pos;
  u32         depth;
  char       *err;
  size_t      err_len;

} json_parser_t;

static void json_error(json_parser_t *p, const char *message) {
  if (!p->err || !p->err_len || p->err[0]) { return; }

  snprintf(p->err, p->err_len, "%s at byte %zu", message, p->pos);
}

static void json_skip_ws(json_parser_t *p) {
  while (p->pos < p->len &&
         (p->data[p->pos] == ' ' || p->data[p->pos] == '\t' ||
          p->data[p->pos] == '\r' || p->data[p->pos] == '\n')) {
    ++p->pos;
  }
}

static json_value_t *json_new(json_type_t type) {
  json_value_t *v = (json_value_t *)ck_alloc(sizeof(json_value_t));
  v->type = type;
  return v;
}

static void json_free(json_value_t *v);

static void json_free_array(json_value_t *v) {
  for (u32 i = 0; i < v->value.array.count; ++i) {
    json_free(v->value.array.items[i]);
  }

  ck_free(v->value.array.items);
}

static void json_free_object(json_value_t *v) {
  for (u32 i = 0; i < v->value.object.count; ++i) {
    ck_free(v->value.object.members[i].key);
    json_free(v->value.object.members[i].value);
  }

  ck_free(v->value.object.members);
}

static void json_free(json_value_t *v) {
  if (!v) { return; }

  switch (v->type) {
    case JSON_STRING:
      ck_free(v->value.string);
      break;

    case JSON_ARRAY:
      json_free_array(v);
      break;

    case JSON_OBJECT:
      json_free_object(v);
      break;

    default:
      break;
  }

  ck_free(v);
}

static int json_hex(char c) {
  if (c >= '0' && c <= '9') { return c - '0'; }
  if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
  if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
  return -1;
}

static int json_hex4(json_parser_t *p, u32 *out) {
  u32 value = 0;

  if (p->pos + 4 > p->len) {
    json_error(p, "truncated \\u escape");
    return 0;
  }

  for (u32 i = 0; i < 4; ++i) {
    int digit = json_hex(p->data[p->pos + i]);

    if (digit < 0) {
      json_error(p, "invalid \\u escape");
      return 0;
    }

    value = (value << 4) | (u32)digit;
  }

  p->pos += 4;
  *out = value;
  return 1;
}

static void json_utf8(char **out, size_t *out_len, u32 codepoint) {
  char bytes[4];
  u32  count;

  if (codepoint <= 0x7f) {
    bytes[0] = (char)codepoint;
    count = 1;

  } else if (codepoint <= 0x7ff) {
    bytes[0] = (char)(0xc0 | (codepoint >> 6));
    bytes[1] = (char)(0x80 | (codepoint & 0x3f));
    count = 2;

  } else if (codepoint <= 0xffff) {
    bytes[0] = (char)(0xe0 | (codepoint >> 12));
    bytes[1] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
    bytes[2] = (char)(0x80 | (codepoint & 0x3f));
    count = 3;
  } else {
    bytes[0] = (char)(0xf0 | (codepoint >> 18));
    bytes[1] = (char)(0x80 | ((codepoint >> 12) & 0x3f));
    bytes[2] = (char)(0x80 | ((codepoint >> 6) & 0x3f));
    bytes[3] = (char)(0x80 | (codepoint & 0x3f));
    count = 4;
  }

  for (u32 i = 0; i < count; ++i) {
    (*out)[(*out_len)++] = bytes[i];
  }
}

static char *json_parse_string(json_parser_t *p) {
  if (p->pos >= p->len || p->data[p->pos] != '"') {
    json_error(p, "expected string");
    return NULL;
  }

  ++p->pos;

  size_t cap = 32;
  size_t len = 0;
  char  *out = (char *)ck_alloc(cap);

  while (p->pos < p->len) {
    u8 c = (u8)p->data[p->pos++];

    if (c == '"') {
      out[len] = 0;
      return out;
    }

    if (c < 0x20) {
      json_error(p, "control character in string");
      goto fail;
    }

    if (c == '\\') {
      if (p->pos >= p->len) {
        json_error(p, "truncated string escape");
        goto fail;
      }

      c = (u8)p->data[p->pos++];

      switch (c) {
        case '"':
        case '\\':
        case '/':
          break;
        case 'b':
          c = '\b';
          break;
        case 'f':
          c = '\f';
          break;
        case 'n':
          c = '\n';
          break;
        case 'r':
          c = '\r';
          break;
        case 't':
          c = '\t';
          break;
        case 'u': {
          u32 codepoint;
          if (!json_hex4(p, &codepoint)) { goto fail; }

          if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
            u32 low;
            if (p->pos + 2 > p->len || p->data[p->pos] != '\\' ||
                p->data[p->pos + 1] != 'u') {
              json_error(p, "missing low surrogate");
              goto fail;
            }

            p->pos += 2;
            if (!json_hex4(p, &low) || low < 0xdc00 || low > 0xdfff) {
              json_error(p, "invalid low surrogate");
              goto fail;
            }

            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + (low - 0xdc00);
          }

          if (codepoint > 0x10ffff) {
            json_error(p, "invalid unicode codepoint");
            goto fail;
          }

          if (len + 4 + 1 > cap) {
            while (len + 4 + 1 > cap) {
              cap *= 2;
            }
            out = (char *)ck_realloc(out, cap);
          }

          json_utf8(&out, &len, codepoint);
          continue;
        }
        default:
          json_error(p, "invalid string escape");
          goto fail;
      }
    }

    if (len + 2 > cap) {
      cap *= 2;
      out = (char *)ck_realloc(out, cap);
    }

    out[len++] = (char)c;
  }

  json_error(p, "unterminated string");

fail:
  ck_free(out);
  return NULL;
}

static json_value_t *json_parse_value(json_parser_t *p);

static json_value_t *json_parse_array(json_parser_t *p) {
  json_value_t *out = json_new(JSON_ARRAY);

  ++p->pos;
  json_skip_ws(p);

  if (p->pos < p->len && p->data[p->pos] == ']') {
    ++p->pos;
    return out;
  }

  for (;;) {
    json_value_t *item = json_parse_value(p);
    if (!item) { goto fail; }

    out->value.array.items = (json_value_t **)ck_realloc(
        out->value.array.items,
        (out->value.array.count + 1) * sizeof(json_value_t *));
    out->value.array.items[out->value.array.count++] = item;

    json_skip_ws(p);
    if (p->pos >= p->len) {
      json_error(p, "unterminated array");
      goto fail;
    }

    if (p->data[p->pos] == ']') {
      ++p->pos;
      return out;
    }

    if (p->data[p->pos] != ',') {
      json_error(p, "expected ',' or ']'");
      goto fail;
    }

    ++p->pos;
    json_skip_ws(p);
  }

fail:
  json_free(out);
  return NULL;
}

static json_value_t *json_parse_object(json_parser_t *p) {
  json_value_t *out = json_new(JSON_OBJECT);

  ++p->pos;
  json_skip_ws(p);

  if (p->pos < p->len && p->data[p->pos] == '}') {
    ++p->pos;
    return out;
  }

  for (;;) {
    char *key = json_parse_string(p);
    if (!key) { goto fail; }

    json_skip_ws(p);
    if (p->pos >= p->len || p->data[p->pos] != ':') {
      ck_free(key);
      json_error(p, "expected ':'");
      goto fail;
    }

    ++p->pos;
    json_skip_ws(p);

    json_value_t *value = json_parse_value(p);
    if (!value) {
      ck_free(key);
      goto fail;
    }

    out->value.object.members = (json_member_t *)ck_realloc(
        out->value.object.members,
        (out->value.object.count + 1) * sizeof(json_member_t));
    json_member_t *member =
        &out->value.object.members[out->value.object.count++];
    member->key = key;
    member->value = value;

    json_skip_ws(p);
    if (p->pos >= p->len) {
      json_error(p, "unterminated object");
      goto fail;
    }

    if (p->data[p->pos] == '}') {
      ++p->pos;
      return out;
    }

    if (p->data[p->pos] != ',') {
      json_error(p, "expected ',' or '}'");
      goto fail;
    }

    ++p->pos;
    json_skip_ws(p);
  }

fail:
  json_free(out);
  return NULL;
}

static json_value_t *json_parse_number(json_parser_t *p) {
  size_t start = p->pos;
  u8     integer = 1;

  if (p->data[p->pos] == '-') { ++p->pos; }

  if (p->pos >= p->len || !isdigit((unsigned char)p->data[p->pos])) {
    json_error(p, "invalid number");
    return NULL;
  }

  if (p->data[p->pos] == '0') {
    ++p->pos;

  } else {
    while (p->pos < p->len && isdigit((unsigned char)p->data[p->pos])) {
      ++p->pos;
    }
  }

  if (p->pos < p->len && p->data[p->pos] == '.') {
    integer = 0;
    ++p->pos;
    if (p->pos >= p->len || !isdigit((unsigned char)p->data[p->pos])) {
      json_error(p, "invalid number fraction");
      return NULL;
    }

    while (p->pos < p->len && isdigit((unsigned char)p->data[p->pos])) {
      ++p->pos;
    }
  }

  if (p->pos < p->len && (p->data[p->pos] == 'e' || p->data[p->pos] == 'E')) {
    integer = 0;
    ++p->pos;
    if (p->pos < p->len && (p->data[p->pos] == '+' || p->data[p->pos] == '-')) {
      ++p->pos;
    }

    if (p->pos >= p->len || !isdigit((unsigned char)p->data[p->pos])) {
      json_error(p, "invalid number exponent");
      return NULL;
    }

    while (p->pos < p->len && isdigit((unsigned char)p->data[p->pos])) {
      ++p->pos;
    }
  }

  json_value_t *out = json_new(JSON_NUMBER);
  out->number_is_integer = integer;

  if (integer) {
    char *end = NULL;
    out->value.number = strtoll(p->data + start, &end, 10);

    if (!end || (size_t)(end - (p->data + start)) != p->pos - start) {
      json_error(p, "invalid integer");
      json_free(out);
      return NULL;
    }

  } else {
    /* Only offsets and byte values need integer JSON numbers. */
    out->value.number = 0;
  }

  return out;
}

static json_value_t *json_parse_value(json_parser_t *p) {
  json_skip_ws(p);

  if (p->pos >= p->len) {
    json_error(p, "unexpected end of JSON");
    return NULL;
  }

  if (p->depth++ >= JSON_MAX_DEPTH) {
    json_error(p, "JSON nesting is too deep");
    --p->depth;
    return NULL;
  }

  json_value_t *out = NULL;

  switch (p->data[p->pos]) {
    case '"': {
      out = json_new(JSON_STRING);
      out->value.string = json_parse_string(p);
      if (!out->value.string) {
        ck_free(out);
        out = NULL;
      }

      break;
    }

    case '{':
      out = json_parse_object(p);
      break;

    case '[':
      out = json_parse_array(p);
      break;

    case 't':
      if (p->len - p->pos >= 4 && !memcmp(p->data + p->pos, "true", 4)) {
        out = json_new(JSON_BOOL);
        out->value.boolean = 1;
        p->pos += 4;
      }

      break;

    case 'f':
      if (p->len - p->pos >= 5 && !memcmp(p->data + p->pos, "false", 5)) {
        out = json_new(JSON_BOOL);
        p->pos += 5;
      }

      break;

    case 'n':
      if (p->len - p->pos >= 4 && !memcmp(p->data + p->pos, "null", 4)) {
        out = json_new(JSON_NULL);
        p->pos += 4;
      }

      break;

    default:
      if (p->data[p->pos] == '-' || isdigit((unsigned char)p->data[p->pos])) {
        out = json_parse_number(p);
      }

      break;
  }

  --p->depth;
  if (!out && !p->err[0]) { json_error(p, "invalid JSON value"); }
  return out;
}

static json_value_t *json_parse(const char *data, size_t len, char *err,
                                size_t err_len) {
  json_parser_t p;
  memset(&p, 0, sizeof(p));
  p.data = data;
  p.len = len;
  p.err = err;
  p.err_len = err_len;

  json_value_t *root = json_parse_value(&p);
  if (!root) { return NULL; }

  json_skip_ws(&p);
  if (p.pos != p.len) {
    json_error(&p, "trailing data after JSON value");
    json_free(root);
    return NULL;
  }

  return root;
}

static json_value_t *json_member(json_value_t *object, const char *key) {
  if (!object || object->type != JSON_OBJECT) { return NULL; }

  for (u32 i = object->value.object.count; i; --i) {
    json_member_t *member = &object->value.object.members[i - 1];
    if (!strcmp(member->key, key)) { return member->value; }
  }

  return NULL;
}

static u8 json_u32(json_value_t *value, u32 *out) {
  if (!value || value->type != JSON_NUMBER || !value->number_is_integer ||
      value->value.number < 0 || value->value.number > 0xffffffffLL) {
    return 0;
  }

  *out = (u32)value->value.number;
  return 1;
}

static u8 *decode_byte_string(const char *text, u32 *out_len) {
  size_t len = strlen(text);

  if (len >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
    const char *digits = text + 2;
    size_t      digits_len = len - 2;

    if (!digits_len) { return NULL; }

    for (size_t i = 0; i < digits_len; ++i) {
      if (json_hex(digits[i]) < 0) { return NULL; }
    }

    size_t byte_len = (digits_len + 1) / 2;
    u8    *out = (u8 *)ck_alloc((u32)byte_len);
    size_t first = digits_len & 1;
    size_t pos = 0;

    if (first) { out[pos++] = (u8)json_hex(digits[0]); }

    for (size_t i = first; i < digits_len; i += 2) {
      out[pos++] = (u8)((json_hex(digits[i]) << 4) | json_hex(digits[i + 1]));
    }

    *out_len = (u32)byte_len;
    return out;
  }

  u8 *out = (u8 *)ck_alloc((u32)(len ? len : 1));
  u32 pos = 0;

  for (size_t i = 0; i < len;) {
    if (text[i] == '\\' && i + 3 < len &&
        (text[i + 1] == 'x' || text[i + 1] == 'X')) {
      int hi = json_hex(text[i + 2]);
      int lo = json_hex(text[i + 3]);

      if (hi < 0 || lo < 0) {
        ck_free(out);
        return NULL;
      }

      out[pos++] = (u8)((hi << 4) | lo);
      i += 4;

    } else {
      out[pos++] = (u8)text[i++];
    }
  }

  *out_len = pos;
  return out;
}

static u8 *decode_byte_value(json_value_t *value, u32 *out_len) {
  *out_len = 0;

  if (!value) { return NULL; }

  if (value->type == JSON_STRING) {
    return decode_byte_string(value->value.string, out_len);
  }

  if (value->type == JSON_NUMBER) {
    if (!value->number_is_integer || value->value.number < 0 ||
        value->value.number > 0xff) {
      return NULL;
    }

    u8 *out = (u8 *)ck_alloc(1);
    out[0] = (u8)value->value.number;
    *out_len = 1;
    return out;
  }

  if (value->type == JSON_ARRAY) {
    u32 count = value->value.array.count;
    if (!count) { return NULL; }

    u8 *out = (u8 *)ck_alloc(count);

    for (u32 i = 0; i < count; ++i) {
      json_value_t *item = value->value.array.items[i];
      u32           byte;
      if (!json_u32(item, &byte) || byte > 0xff) {
        ck_free(out);
        return NULL;
      }

      out[i] = (u8)byte;
    }

    *out_len = count;
    return out;
  }

  return NULL;
}

static void set_error(char *err, size_t err_len, const char *message) {
  if (err && err_len) { snprintf(err, err_len, "%s", message); }
}

static u8 format_add_probe(binary_format_t *format, json_value_t *value) {
  if (!value || value->type != JSON_OBJECT) { return 0; }

  u32 offset;
  if (!json_u32(json_member(value, "offset"), &offset)) { return 0; }

  u32 value_len = 0;
  u8 *probe_value = decode_byte_value(json_member(value, "value"), &value_len);
  if (!probe_value || !value_len || offset > 0xffffffffU - value_len + 1) {
    ck_free(probe_value);
    return 0;
  }

  u32 mask_len = 0;
  u8 *mask = decode_byte_value(json_member(value, "mask"), &mask_len);

  if (mask && mask_len != value_len) {
    ck_free(probe_value);
    ck_free(mask);
    return 0;
  }

  format->probes = (binary_probe_t *)ck_realloc(
      format->probes, (format->probe_count + 1) * sizeof(binary_probe_t));
  binary_probe_t *probe = &format->probes[format->probe_count++];
  probe->offset = offset;
  probe->value = probe_value;
  probe->mask = mask;
  probe->len = value_len;
  return 1;
}

static u8 load_formats_object(json_value_t *root, const char *expected_protocol,
                              binary_format_t **out, u32 *out_count, char *err,
                              size_t err_len) {
  if (!root || root->type != JSON_OBJECT) {
    set_error(err, err_len, "top-level JSON value is not an object");
    return 0;
  }

  json_value_t *protocol = json_member(root, "protocol");
  if (expected_protocol && expected_protocol[0] && protocol &&
      protocol->type == JSON_STRING &&
      strcasecmp(protocol->value.string, expected_protocol)) {
    if (err && err_len) {
      snprintf(err, err_len, "protocol is '%s', expected '%s'",
               protocol->value.string, expected_protocol);
    }

    return 0;
  }

  json_value_t *types = json_member(root, "types");
  if (!types || types->type != JSON_OBJECT) {
    set_error(err, err_len, "missing or invalid 'types' object");
    return 0;
  }

  binary_format_t *formats = NULL;
  u32              count = 0;

  for (u32 i = 0; i < types->value.object.count; ++i) {
    json_member_t *member = &types->value.object.members[i];
    json_value_t  *entry = member->value;

    if (!entry || entry->type != JSON_OBJECT) { continue; }

    json_value_t *probes = json_member(entry, "probe");
    if (!probes || probes->type != JSON_ARRAY || !probes->value.array.count) {
      continue;
    }

    formats = (binary_format_t *)ck_realloc(
        formats, (count + 1) * sizeof(binary_format_t));
    binary_format_t *format = &formats[count];
    memset(format, 0, sizeof(*format));
    format->type = (char *)ck_alloc((u32)strlen(member->key) + 1);
    strcpy(format->type, member->key);

    for (u32 j = 0; j < probes->value.array.count; ++j) {
      if (!format_add_probe(format, probes->value.array.items[j])) {
        if (err && err_len) {
          snprintf(err, err_len, "invalid probe for type '%s'", member->key);
        }

        binary_formats_free(formats, count + 1);
        return 0;
      }
    }

    ++count;
  }

  if (!count) {
    binary_formats_free(formats, count);
    set_error(err, err_len, "no usable probes in 'types'");
    return 0;
  }

  *out = formats;
  *out_count = count;
  return 1;
}

static char *read_file(const char *path, size_t *out_len, char *err,
                       size_t err_len) {
  FILE *f = fopen(path, "rb");
  if (!f) { return NULL; }

  if (fseek(f, 0, SEEK_END)) {
    fclose(f);
    return NULL;
  }

  long size = ftell(f);
  if (size <= 0 || size > (16L << 20) || fseek(f, 0, SEEK_SET)) {
    fclose(f);
    if (err && err_len) {
      snprintf(err, err_len, "invalid or oversized formats file");
    }

    return NULL;
  }

  char *data = (char *)ck_alloc((u32)size + 1);
  if (fread(data, 1, (size_t)size, f) != (size_t)size) {
    ck_free(data);
    fclose(f);
    if (err && err_len) { snprintf(err, err_len, "cannot read formats file"); }
    return NULL;
  }

  fclose(f);
  data[size] = 0;
  *out_len = (size_t)size;
  return data;
}

s32 binary_formats_load(const char *path, const char *expected_protocol,
                        binary_format_t **out, u32 *out_count, char *err,
                        size_t err_len) {
  if (out) { *out = NULL; }
  if (out_count) { *out_count = 0; }
  if (err && err_len) { err[0] = 0; }
  if (!path || !out || !out_count) {
    set_error(err, err_len, "invalid arguments");
    return BINARY_FORMATS_ERROR;
  }

  FILE *probe = fopen(path, "rb");
  if (!probe) {
    if (errno == ENOENT) { return BINARY_FORMATS_ABSENT; }
    if (err && err_len) {
      snprintf(err, err_len, "cannot open %s: %s", path, strerror(errno));
    }

    return BINARY_FORMATS_ERROR;
  }

  fclose(probe);

  size_t data_len = 0;
  char  *data = read_file(path, &data_len, err, err_len);
  if (!data) {
    if (err && err_len && err[0]) { return BINARY_FORMATS_ERROR; }
    if (err && err_len) { snprintf(err, err_len, "cannot read %s", path); }
    return BINARY_FORMATS_ERROR;
  }

  char          json_err[256] = {0};
  json_value_t *root = json_parse(data, data_len, json_err, sizeof(json_err));
  ck_free(data);

  if (!root) {
    if (err && err_len) {
      snprintf(err, err_len, "invalid JSON: %s",
               json_err[0] ? json_err : "parse error");
    }

    return BINARY_FORMATS_ERROR;
  }

  u8 ok = load_formats_object(root, expected_protocol, out, out_count, err,
                              err_len);
  json_free(root);

  return ok ? BINARY_FORMATS_OK : BINARY_FORMATS_ERROR;
}

void binary_formats_free(binary_format_t *formats, u32 count) {
  if (!formats) { return; }

  for (u32 i = 0; i < count; ++i) {
    ck_free(formats[i].type);

    for (u32 j = 0; j < formats[i].probe_count; ++j) {
      ck_free(formats[i].probes[j].value);
      ck_free(formats[i].probes[j].mask);
    }

    ck_free(formats[i].probes);
  }

  ck_free(formats);
}

static u8 probe_matches(const binary_probe_t *probe, const u8 *buf, u32 len) {
  if (probe->offset > len || probe->len > len - probe->offset) { return 0; }

  for (u32 i = 0; i < probe->len; ++i) {
    u8 mask = probe->mask ? probe->mask[i] : 0xff;
    if ((buf[probe->offset + i] & mask) != (probe->value[i] & mask)) {
      return 0;
    }
  }

  return 1;
}

static u32 popcount8(u8 value) {
  u32 count = 0;

  while (value) {
    value &= (u8)(value - 1);
    ++count;
  }

  return count;
}

s32 binary_formats_match(const binary_format_t *formats, u32 count,
                         const u8 *buf, u32 len) {
  if (!formats || !buf || !len) { return -1; }

  s32 best = -1;
  u64 best_score = 0;

  for (u32 i = 0; i < count; ++i) {
    const binary_format_t *format = &formats[i];
    if (!format->probe_count) { continue; }

    u8  matched = 1;
    u64 constrained_bits = 0;

    for (u32 j = 0; j < format->probe_count; ++j) {
      const binary_probe_t *probe = &format->probes[j];
      if (!probe_matches(probe, buf, len)) {
        matched = 0;
        break;
      }

      for (u32 k = 0; k < probe->len; ++k) {
        constrained_bits += popcount8(probe->mask ? probe->mask[k] : 0xff);
      }
    }

    if (!matched) { continue; }

    u64 score = (constrained_bits << 32) + format->probe_count;
    if (best < 0 || score > best_score) {
      best = (s32)i;
      best_score = score;
    }
  }

  return best;
}
