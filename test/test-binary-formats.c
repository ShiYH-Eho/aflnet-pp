/* Standalone regression test for .binary-formats.json probe loading/matching.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "binary_formats.h"

static void write_file(const char *path, const char *data) {
  FILE *f = fopen(path, "wb");
  assert(f);
  assert(fwrite(data, 1, strlen(data), f) == strlen(data));
  assert(!fclose(f));
}

int main(int argc, char **argv) {
  assert(argc == 2);

  char path[4096];
  char absent[4096];
  char invalid[4096];
  snprintf(path, sizeof(path), "%s/formats.json", argv[1]);
  snprintf(absent, sizeof(absent), "%s/absent.json", argv[1]);
  snprintf(invalid, sizeof(invalid), "%s/invalid.json", argv[1]);

  write_file(
      path,
      "{\n"
      "  \"format_version\": 1,\n"
      "  \"protocol\": \"TEST\",\n"
      "  \"framing\": {\"length_offset\": 0, \"length_size\": 1},\n"
      "  \"types\": {\n"
      "    \"GENERIC\": {\n"
      "      \"example_hex\": \"a000\",\n"
      "      \"probe\": [{\"offset\": 0, \"value\": \"0xA0\"}],\n"
      "      \"layout\": [{\"offset\": 0, \"size\": 1}]\n"
      "    },\n"
      "    \"SPECIAL\": {\n"
      "      \"probe\": [\n"
      "        {\"offset\": 0, \"value\": \"0xA0\"},\n"
      "        {\"offset\": 2, \"value\": \"0x01\", \"mask\": \"0x0f\"}\n"
      "      ]\n"
      "    },\n"
      "    \"ARRAY\": {\n"
      "      \"probe\": [{\"offset\": 1, \"value\": [66, 67]}]\n"
      "    },\n"
      "    \"ESCAPE\": {\n"
      "      \"probe\": [{\"offset\": 0, \"value\": \"\\\\xE0\"}]\n"
      "    }\n"
      "  }\n"
      "}\n");

  binary_format_t *formats = NULL;
  u32              count = 0;
  char             err[256];

  assert(binary_formats_load(absent, "test", &formats, &count, err,
                             sizeof(err)) == BINARY_FORMATS_ABSENT);
  assert(!formats && !count);

  s32 rc =
      binary_formats_load(path, "test", &formats, &count, err, sizeof(err));
  if (rc != BINARY_FORMATS_OK) {
    fprintf(stderr, "load failed: %s\n", err);
    return 1;
  }
  assert(count == 4);
  assert(!strcmp(formats[0].type, "GENERIC"));
  assert(!strcmp(formats[1].type, "SPECIAL"));
  assert(!strcmp(formats[2].type, "ARRAY"));
  assert(!strcmp(formats[3].type, "ESCAPE"));

  const u8 special[] = {0xa0, 0x00, 0x11};
  assert(binary_formats_match(formats, count, special, sizeof(special)) == 1);

  const u8 masked_bad[] = {0xa0, 0x00, 0x12};
  assert(binary_formats_match(formats, count, masked_bad, sizeof(masked_bad)) ==
         0);

  const u8 array_value[] = {0xa1, 0x42, 0x43};
  assert(binary_formats_match(formats, count, array_value,
                              sizeof(array_value)) == 2);

  const u8 escaped_value[] = {0xe0};
  assert(binary_formats_match(formats, count, escaped_value,
                              sizeof(escaped_value)) == 3);

  const u8 too_short[] = {0xa0};
  assert(binary_formats_match(formats, count, too_short, sizeof(too_short)) ==
         0);

  const u8 no_match[] = {0x55, 0x44, 0x43};
  assert(binary_formats_match(formats, count, no_match, sizeof(no_match)) ==
         -1);

  binary_formats_free(formats, count);
  formats = NULL;
  count = 0;

  assert(binary_formats_load(path, "other", &formats, &count, err,
                             sizeof(err)) == BINARY_FORMATS_ERROR);
  assert(strstr(err, "expected 'other'"));

  write_file(invalid, "{\"types\": {\"BROKEN\": ");
  assert(binary_formats_load(invalid, "test", &formats, &count, err,
                             sizeof(err)) == BINARY_FORMATS_ERROR);
  assert(strstr(err, "invalid JSON"));

  puts("[+] binary formats probe loader and matcher");
  return 0;
}
