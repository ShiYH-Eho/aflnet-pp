/* aflnet/utils/grammar.c - protocol grammar template guided mutation
   (optional AFLNet module, off unless AFLNET_GRAMMAR is set).

   Port of the grammar template machinery of ChatState's afl-fuzz.c:

     - templates are *imported from a file or a directory* when the
       AFLNET_GRAMMAR option is given (setup_llm_grammars_from_file() in
       ChatState) - the LLM/generation side of ChatState is intentionally
       not ported,
     - a template that matches the mutation target sends it to a list of
       mutable windows (parse_buffer() + starts_with() + get_mutable_ranges()
       in ChatState); the AFLNet region selection (src/aflnet/region.c) then
       narrows M2 to one of those windows.

   A grammar template describes the *shape* of one protocol message and is
   imported from a plain file:

     <header pattern>   <- first line of the template file     (PCRE2)
     <field pattern>    <- all remaining lines of the file     (PCRE2)

   The capture groups of the header pattern are the *variable fields* of the
   message, e.g.

     ^(?:(.*) APPEND (.*) (.*) (.*) (.*)\r\n)$
     (.+)

   describes an IMAP APPEND request whose mutable parts are the tag and the
   four arguments.  When such a template matches the AFLNet mutation target
   M2, the region selection narrows M2 down to one of those fields and folds
   the remaining bytes into M1/M3, so the whole mutation pipeline of the
   fuzzer only ever sees that field and aflnet_reassemble_region() rebuilds
   the message.  It only *guides* the existing mutators - nothing is
   generated from the grammar - and it needs no changes in the core fuzzer
   (src/afl-fuzz-one.c).

   Intentionally NOT ported (yet):
     - everything that generates a message from a grammar
       (gen_message_by_type(), regex_generate_expression(), the LLM prompts),
     - template sequences (a sequence of templates matched against a sequence
       of messages).

   Configuration:

     AFLNET_GRAMMAR=<dir>     one template per regular file, the file name is
                              used as the template (message type) name
     AFLNET_GRAMMAR=<file>    a single template

   Setting AFLNET_GRAMMAR enables the feature and, additionally, points the
   mutator at the right end of the input spectrum for the protocol in use
   (AFLNET_PROTOCOL): text protocols (SMTP, FTP, RTSP, SIP, HTTP, IMAP, POP3)
   get AFL++'s TEXT mutation strategies, the other protocols of the AFLNet
   handler table (TLS, DNS, DHCP, MQTT, SSH, ...) get the BINARY ones.  An
   explicit `-a text|binary` on the command line still wins.

     AFLNET_GRAMMAR_EXPLORE_PROB
                              0..100, percentage of fuzz iterations that
                              keep the whole message instead of narrowing it
                              to a template field ("exploration"), default
                              50 - this mirrors ChatState's
                              EPSILON_CHOICE = 0.5.

   The declarations live in ../aflnet-internal.h. */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "types.h"
#include "debug.h"
#include "common.h"
#include "alloc-inl.h"
#include "afl-fuzz.h"
#include "../aflnet-internal.h"
#include "binary_formats.h"

#ifdef HAVE_PCRE2

  #define PCRE2_CODE_UNIT_WIDTH 8
  #include <pcre2.h>

/* ------------------------------------------------------------------ */
/* module state                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
  char       *type;   /* template name (source file name)               */
  pcre2_code *header; /* pattern of the template's first line           */
  pcre2_code *fields; /* pattern of the remaining template lines        */

} grammar_template_t;

typedef struct {
  s32 start;
  s32 len;

} grammar_window_t;

static grammar_template_t *templates = NULL;
static u32                 templates_count = 0;
static u32                 templates_alloc = 0;

/* Optional companion metadata from <grammar-dir>/.binary-formats.json. */
static binary_format_t *binary_formats = NULL;
static u32              binary_formats_count = 0;

static u8  gt_enabled = 0; /* templates usable    */
static u32 gt_explore_prob = GRAMMAR_DEFAULT_EXPLORE_PROB;

/* mutable windows of the seed currently prepared for mutation */
static grammar_window_t *windows = NULL;
static u32               window_count = 0;
static u32               window_alloc = 0;
static u8                stage_active = 0;
static const char       *stage_template = NULL;

  /* ------------------------------------------------------------------ */
  /* protocol type -> AFL++ input mode (text / binary)                  */
  /* ------------------------------------------------------------------ */

  /* AFL++ input modes: 0 = generic, 1 = text, 2 = binary.  Which mutation
     strategy array the havoc stage uses is picked from this. */
  #define GRAMMAR_INPUT_GENERIC 0
  #define GRAMMAR_INPUT_TEXT 1
  #define GRAMMAR_INPUT_BINARY 2

/* AFLNet protocol -> input mode.  Line oriented, human readable request
   formats are text; the rest of the AFLNet handler table is binary. */
static const struct {
  const char *name;
  u8          mode;

} grammar_protocol_modes[] = {

    {"smtp", GRAMMAR_INPUT_TEXT},    {"ftp", GRAMMAR_INPUT_TEXT},
    {"rtsp", GRAMMAR_INPUT_TEXT},    {"sip", GRAMMAR_INPUT_TEXT},
    {"http", GRAMMAR_INPUT_TEXT},    {"imap", GRAMMAR_INPUT_TEXT},
    {"pop3", GRAMMAR_INPUT_TEXT},

    {"ssh", GRAMMAR_INPUT_BINARY},   {"tls", GRAMMAR_INPUT_BINARY},
    {"dtls", GRAMMAR_INPUT_BINARY},  {"dtls12", GRAMMAR_INPUT_BINARY},
    {"dicom", GRAMMAR_INPUT_BINARY}, {"dns", GRAMMAR_INPUT_BINARY},
    {"mqtt", GRAMMAR_INPUT_BINARY},  {"ipp", GRAMMAR_INPUT_BINARY},
    {"dhcp", GRAMMAR_INPUT_BINARY},  {"tftp", GRAMMAR_INPUT_BINARY},
    {"sntp", GRAMMAR_INPUT_BINARY},  {"ntp", GRAMMAR_INPUT_BINARY},
    {"snmp", GRAMMAR_INPUT_BINARY},

};

/* case insensitive string compare (the protocol is normalized to lower case
   by the caller, the table above is lower case as well) */
static u8 grammar_streq(const char *a, const char *b) {
  while (*a && *b) {
    if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) { return 0; }

    ++a;
    ++b;
  }

  return *a == *b;
}

static grammar_template_t *grammar_find_template(const char *type) {
  if (!type) { return NULL; }

  for (u32 i = 0; i < templates_count; ++i) {
    if (!strcmp(templates[i].type, type)) { return &templates[i]; }
  }

  return NULL;
}

static binary_format_t *grammar_find_format(const char *type) {
  if (!type) { return NULL; }

  for (u32 i = 0; i < binary_formats_count; ++i) {
    if (!strcmp(binary_formats[i].type, type)) { return &binary_formats[i]; }
  }

  return NULL;
}

/* Point afl->input_mode at the right end of the input spectrum for the
   protocol in use.  This runs while the state is initialised, i.e. *before*
   afl_parse_commandline(), so an explicit -a text|binary still wins over it. */
static void grammar_set_input_mode(struct afl_state *afl,
                                   const char       *protocol) {
  if (!afl || !protocol || !*protocol) { return; }

  if (afl->input_mode != GRAMMAR_INPUT_GENERIC) {
    ACTF(
        "Grammar templates: keeping the input mode configured on the "
        "command line");
    return;
  }

  for (u32 i = 0;
       i < sizeof(grammar_protocol_modes) / sizeof(grammar_protocol_modes[0]);
       ++i) {
    if (!grammar_streq(protocol, grammar_protocol_modes[i].name)) { continue; }

    afl->input_mode = grammar_protocol_modes[i].mode;

    const char *mode_name =
        afl->input_mode == GRAMMAR_INPUT_TEXT ? "text" : "binary";

    ACTF(
        "Grammar templates: protocol '%s' is %s -> using the %s mutation "
        "strategies (a command line -a overrides this)",
        protocol, mode_name, mode_name);
    return;
  }

  ACTF(
      "Grammar templates: protocol '%s' is not classified, keeping the "
      "default input mode",
      protocol);
}

/* ------------------------------------------------------------------ */
/* mutable window vector                                              */
/* ------------------------------------------------------------------ */

static void window_push(s32 start, s32 len) {
  /* Empty windows cannot carry a mutation, so they are dropped here (in
     ChatState they are kept and every mutation op bails out on len < 1). */
  if (len <= 0) { return; }

  if (unlikely(window_count == window_alloc)) {
    window_alloc = window_alloc ? window_alloc * 2 : 16;
    windows = ck_realloc(windows, window_alloc * sizeof(grammar_window_t));
  }

  windows[window_count].start = start;
  windows[window_count].len = len;
  ++window_count;
}

/* ------------------------------------------------------------------ */
/* PCRE2 helpers - ports of starts_with() / get_mutable_ranges()       */
/* ------------------------------------------------------------------ */

/* Match the header pattern against the seed.  On success every capture group
   becomes a mutable window and *match_len is set to the end offset of the
   whole match, i.e. where the field pattern starts to be scanned. */
static u8 template_header_match(const u8 *buf, u32 len, pcre2_code *pattern,
                                s32 *match_len) {
  pcre2_match_data *match_data =
      pcre2_match_data_create_from_pattern(pattern, NULL);

  if (unlikely(!match_data)) { return 0; }

  int rc = pcre2_match(pattern, buf, len, 0, 0, match_data, NULL);

  if (rc < 0) { /* no match / error */

    pcre2_match_data_free(match_data);
    return 0;
  }

  PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

  for (int i = 1; i < rc; ++i) {
    if (ovector[2 * i] == PCRE2_UNSET) { continue; }
    window_push((s32)ovector[2 * i],
                (s32)(ovector[2 * i + 1] - ovector[2 * i]));
  }

  *match_len = (s32)ovector[1];

  pcre2_match_data_free(match_data);
  return 1;
}

/* Scan everything after the header match for the field pattern: each capture
   group and each gap between two matches is a mutable window. */
static void template_collect_fields(const u8 *buf, u32 len, u32 offset,
                                    pcre2_code *pattern) {
  pcre2_match_data *match_data =
      pcre2_match_data_create_from_pattern(pattern, NULL);

  if (unlikely(!match_data)) { return; }

  for (;;) {
    int rc = pcre2_match(pattern, buf, len, offset, 0, match_data, NULL);

    if (rc < 0) { break; }

    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);

    /* bytes between the previous match and this one are mutable too */
    if (offset != ovector[0]) {
      window_push((s32)offset, (s32)(ovector[0] - offset));
    }

    for (int i = 1; i < rc; ++i) {
      if (ovector[2 * i] == PCRE2_UNSET) { continue; }
      window_push((s32)ovector[2 * i],
                  (s32)(ovector[2 * i + 1] - ovector[2 * i]));
    }

    /* an empty match would loop forever, so move one byte on */
    if (offset == ovector[1]) {
      ++offset;

    } else {
      offset = (u32)ovector[1];
    }
  }

  /* anything past the last match is mutable as well */
  if (offset < len) { window_push((s32)offset, (s32)(len - offset)); }

  pcre2_match_data_free(match_data);
}

/* Match one template and, on success, prepare its mutable windows. */
static u8 grammar_try_template(grammar_template_t *t, const u8 *seed, u32 len) {
  s32 header_len = 0;

  if (unlikely(!t->header || !t->fields)) { return 0; }
  if (!template_header_match(seed, len, t->header, &header_len)) { return 0; }

  template_collect_fields(seed, len, (u32)header_len, t->fields);
  stage_active = 1;
  stage_template = t->type;
  return 1;
}

/* ------------------------------------------------------------------ */
/* template import                                                    */
/* ------------------------------------------------------------------ */

static pcre2_code *template_compile(char *pattern, const char *type,
                                    const char *what) {
  int        err = 0;
  PCRE2_SIZE erroffset = 0;

  pcre2_code *code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                   0, &err, &erroffset, NULL);

  if (unlikely(!code)) {
    PCRE2_UCHAR msg[256];

    pcre2_get_error_message(err, msg, sizeof(msg));
    WARNF("Grammar template '%s': invalid %s pattern at offset %zu (%s)", type,
          what, (size_t)erroffset, msg);
    return NULL;
  }

  /* JIT is a pure optimisation, ignore failures (e.g. no JIT support) */
  (void)pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);
  return code;
}

/* Split one template file into header pattern (first line) and field pattern
   (everything after the first newline) and compile both.  Takes ownership of
   content. */
static u8 template_add(char *content, size_t content_len, const char *type) {
  char *separator = memchr(content, '\n', content_len);

  if (unlikely(!separator)) {
    WARNF(
        "Grammar template '%s' ignored: expected a header pattern line "
        "followed by a field pattern line",
        type);
    ck_free(content);
    return 0;
  }

  *separator = 0;

  char *header_src = content;       /* header pattern           */
  char *fields_src = separator + 1; /* field pattern            */

  /* a trailing newline of the file is not part of the pattern */
  size_t fields_len = strlen(fields_src);
  while (fields_len && (fields_src[fields_len - 1] == '\n' ||
                        fields_src[fields_len - 1] == '\r')) {
    fields_src[--fields_len] = 0;
  }

  if (unlikely(!*header_src || !*fields_src)) {
    WARNF("Grammar template '%s' ignored: empty header or field pattern", type);
    ck_free(content);
    return 0;
  }

  pcre2_code *header = template_compile(header_src, type, "header");
  pcre2_code *fields =
      header ? template_compile(fields_src, type, "field") : NULL;

  if (unlikely(!header || !fields)) {
    if (header) { pcre2_code_free(header); }
    if (fields) { pcre2_code_free(fields); }
    ck_free(content);
    return 0;
  }

  if (unlikely(templates_count == templates_alloc)) {
    templates_alloc = templates_alloc ? templates_alloc * 2 : 16;
    templates =
        ck_realloc(templates, templates_alloc * sizeof(grammar_template_t));
  }

  templates[templates_count].type = (char *)ck_strdup((u8 *)type);
  templates[templates_count].header = header;
  templates[templates_count].fields = fields;
  ++templates_count;

  ck_free(content);
  return 1;
}

static char *template_read_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");

  if (unlikely(!f)) { return NULL; }

  if (unlikely(fseek(f, 0, SEEK_END))) {
    fclose(f);
    return NULL;
  }

  long size = ftell(f);

  if (unlikely(size <= 0) || unlikely(fseek(f, 0, SEEK_SET))) {
    fclose(f);
    return NULL;
  }

  /* +1 so the content is always NUL terminated for C string handling */
  char *content = ck_alloc((size_t)size + 1);

  if (unlikely(fread(content, 1, (size_t)size, f) != (size_t)size)) {
    ck_free(content);
    fclose(f);
    return NULL;
  }

  fclose(f);
  content[size] = 0;
  *out_len = (size_t)size;
  return content;
}

static u8 template_load_file(const char *path, const char *type) {
  size_t content_len = 0;
  char  *content = template_read_file(path, &content_len);

  if (unlikely(!content)) {
    WARNF("Cannot read grammar template '%s' (%s)", path, strerror(errno));
    return 0;
  }

  return template_add(content, content_len, type ? type : path);
}

static u8 template_load_dir(const char *path) {
  struct dirent **entries = NULL;
  u8              loaded = 0;

  int count = scandir(path, &entries, NULL, alphasort);

  if (unlikely(count < 0)) {
    WARNF("Cannot read grammar template directory '%s' (%s)", path,
          strerror(errno));
    return 0;
  }

  for (int i = 0; i < count; ++i) {
    struct stat st;
    char       *file;

    /* skip "." / ".." and dotfiles */
    if (entries[i]->d_name[0] == '.') {
      free(entries[i]);
      continue;
    }

    file = (char *)alloc_printf("%s/%s", path, entries[i]->d_name);

    if (!stat(file, &st) && S_ISREG(st.st_mode)) {
      loaded += template_load_file(file, entries[i]->d_name);

    } else {
      WARNF("Grammar template '%s' ignored: not a regular file", file);
    }

    ck_free(file);
    free(entries[i]);
  }

  free(entries);
  return loaded;
}

/* ------------------------------------------------------------------ */
/* public API                                                         */
/* ------------------------------------------------------------------ */

u8 grammar_templates_init(struct afl_state *afl, const char *protocol) {
  if (gt_enabled) { return 1; }

  char *path = get_afl_env("AFLNET_GRAMMAR");

  if (!path) { return 0; } /* option not given -> off */

  /* The option is given, so this run fuzzes protocol messages with a grammar
     in mind: make the mutation strategies match the protocol type. */
  grammar_set_input_mode(afl, protocol);

  char *prob = get_afl_env("AFLNET_GRAMMAR_EXPLORE_PROB");

  if (prob) {
    int v = atoi(prob);

    if (v >= 0 && v <= 100) {
      gt_explore_prob = (u32)v;

    } else {
      WARNF(
          "Invalid AFLNET_GRAMMAR_EXPLORE_PROB '%s' (expected 0..100), "
          "using %u",
          prob, gt_explore_prob);
    }
  }

  struct stat st;

  if (stat(path, &st)) {
    WARNF(
        "AFLNET_GRAMMAR '%s' is not accessible (%s) - grammar guided "
        "mutation disabled",
        path, strerror(errno));
    return 0;
  }

  if (S_ISDIR(st.st_mode)) {
    template_load_dir(path);

  } else if (S_ISREG(st.st_mode)) {
    const char *base = strrchr(path, '/');
    template_load_file(path, base ? base + 1 : path);

  } else {
    WARNF(
        "AFLNET_GRAMMAR '%s' is neither a file nor a directory - "
        "grammar guided mutation disabled",
        path);
    return 0;
  }

  if (unlikely(!templates_count)) {
    WARNF(
        "No usable grammar template found in '%s' - grammar guided mutation "
        "disabled",
        path);
    return 0;
  }

  /* Binary message types are disambiguated with the probe table written next
     to the templates by pro-template.  A missing table is fine: regex matching
     remains the fallback.  A malformed table is reported and ignored. */
  if (S_ISDIR(st.st_mode)) {
    char *formats_path =
        (char *)alloc_printf("%s/%s", path, BINARY_FORMATS_NAME);
    char err[256];

    s32 fmt_rc = binary_formats_load(formats_path, protocol, &binary_formats,
                                     &binary_formats_count, err, sizeof(err));

    if (fmt_rc == BINARY_FORMATS_ERROR) {
      WARNF("Cannot use binary probe metadata '%s': %s", formats_path, err);

    } else if (fmt_rc == BINARY_FORMATS_OK) {
      ACTF("Loaded %u binary message probe definition(s) from '%s'",
           binary_formats_count, formats_path);
    }

    ck_free(formats_path);
  }

  gt_enabled = 1;

  ACTF(
      "Imported %u protocol grammar template(s) from '%s' (grammar guided "
      "mutation on %u%% of the fuzz iterations, %u%% whole-message "
      "exploration)",
      templates_count, path, 100 - gt_explore_prob, gt_explore_prob);

  return 1;
}

void grammar_templates_deinit(void) {
  for (u32 i = 0; i < templates_count; ++i) {
    if (templates[i].header) { pcre2_code_free(templates[i].header); }
    if (templates[i].fields) { pcre2_code_free(templates[i].fields); }
    ck_free(templates[i].type);
  }

  ck_free(templates);
  templates = NULL;
  templates_count = 0;
  templates_alloc = 0;

  ck_free(windows);
  windows = NULL;
  window_count = 0;
  window_alloc = 0;

  binary_formats_free(binary_formats, binary_formats_count);
  binary_formats = NULL;
  binary_formats_count = 0;

  stage_active = 0;
  stage_template = NULL;
  gt_enabled = 0;
}

u32 grammar_templates_count(void) {
  return templates_count;
}

u8 grammar_templates_enabled(void) {
  return gt_enabled;
}

u8 grammar_roll_guided(struct afl_state *afl) {
  if (!gt_enabled) { return 0; }
  if (!gt_explore_prob) { return 1; }
  if (gt_explore_prob >= 100) { return 0; }

  /* mirrors ChatState's "is_exploration = epsilon < EPSILON_CHOICE" */
  return rand_below(afl, 100) >= gt_explore_prob ? 1 : 0;
}

u8 grammar_stage_begin(const u8 *seed, u32 len) {
  grammar_stage_end();

  if (unlikely(!gt_enabled || !seed || !len)) { return 0; }

  /* Prefer the message type identified by its binary probes.  This matters
     when several generated header patterns are deliberately broad: without
     the probe every such pattern can match, and the alphabetical template
     order would otherwise decide the message type. */
  if (binary_formats_count) {
    s32 format_idx =
        binary_formats_match(binary_formats, binary_formats_count, seed, len);

    if (format_idx >= 0) {
      grammar_template_t *probed =
          grammar_find_template(binary_formats[format_idx].type);

      if (probed && grammar_try_template(probed, seed, len)) { goto prepared; }
    }
  }

  for (u32 i = 0; i < templates_count; ++i) {
    grammar_template_t *t = &templates[i];

    /* When probe metadata exists, do not let a known-but-nonmatching type fall
       back to another type's broad header pattern.  Templates that have no
       probe entry remain eligible for the legacy regex-only path. */
    if (binary_formats_count && grammar_find_format(t->type)) { continue; }

    /* first matching template wins, as in ChatState's parse_buffer() */
    if (grammar_try_template(t, seed, len)) { break; }
  }

prepared:
  if (unlikely(!stage_active)) { return 0; }

  if (unlikely(!window_count)) {
    /* graceful degradation, mirrors ChatState: the template matched but no
       mutable field could be derived, so the whole input stays mutable */
    window_push(0, (s32)len);

    if (unlikely(!window_count)) {
      stage_active = 0;
      stage_template = NULL;
      return 0;
    }
  }

  return 1;
}

u32 grammar_stage_count(void) {
  return window_count;
}

const char *grammar_stage_template(void) {
  return stage_template;
}

u8 grammar_stage_window(struct afl_state *afl, u32 *start, u32 *len) {
  if (unlikely(!stage_active || !window_count)) { return 0; }

  u32 idx = rand_below(afl, window_count);

  *start = (u32)windows[idx].start;
  *len = (u32)windows[idx].len;
  return 1;
}

void grammar_stage_end(void) {
  window_count = 0;
  stage_active = 0;
  stage_template = NULL;
}

#else /* !HAVE_PCRE2 */

/* The fuzzer was built without PCRE2: keep the API but disable the feature. */

u8 grammar_templates_init(struct afl_state *afl, const char *protocol) {
  (void)afl;
  (void)protocol;

  if (get_afl_env("AFLNET_GRAMMAR")) {
    WARNF(
        "AFLNET_GRAMMAR is set but this build has no PCRE2 support - "
        "grammar guided mutation is disabled (install libpcre2-dev and "
        "rebuild)");
  }

  return 0;
}

void grammar_templates_deinit(void) {
}

u32 grammar_templates_count(void) {
  return 0;
}

u8 grammar_templates_enabled(void) {
  return 0;
}

u8 grammar_roll_guided(struct afl_state *afl) {
  (void)afl;
  return 0;
}

u8 grammar_stage_begin(const u8 *seed, u32 len) {
  (void)seed;
  (void)len;
  return 0;
}

u32 grammar_stage_count(void) {
  return 0;
}

const char *grammar_stage_template(void) {
  return NULL;
}

u8 grammar_stage_window(struct afl_state *afl, u32 *start, u32 *len) {
  (void)afl;
  (void)start;
  (void)len;
  return 0;
}

void grammar_stage_end(void) {
}

#endif /* HAVE_PCRE2 */
