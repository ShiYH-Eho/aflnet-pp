/* binary_formats.h - binary message probes from .binary-formats.json

   The grammar generator writes this optional companion file next to its
   protocol-grammar templates.  The fuzzer uses the per-type probes to select
   the right template when several binary header patterns would match M2. */

#ifndef AFLNET_BINARY_FORMATS_H
#define AFLNET_BINARY_FORMATS_H

#include <stddef.h>

#include "types.h"

#define BINARY_FORMATS_NAME ".binary-formats.json"
#define BINARY_FORMATS_OK 0
#define BINARY_FORMATS_ABSENT 1
#define BINARY_FORMATS_ERROR (-1)

typedef struct {
  u32 offset;
  u8 *value;
  u8 *mask; /* NULL means an exact byte comparison */
  u32 len;

} binary_probe_t;

typedef struct {
  char           *type;
  binary_probe_t *probes;
  u32             probe_count;

} binary_format_t;

/* Load the types/probe portion of path.  expected_protocol may be NULL.
   Returns BINARY_FORMATS_OK, BINARY_FORMATS_ABSENT or BINARY_FORMATS_ERROR;
   on error, err contains a human-readable diagnostic. */
s32 binary_formats_load(const char *path, const char *expected_protocol,
                        binary_format_t **out, u32 *out_count, char *err,
                        size_t err_len);

void binary_formats_free(binary_format_t *formats, u32 count);

/* Return the index of the most specific format whose probes all match, or -1.
   Number of constrained bits is the primary specificity score; the number of
   probe clauses breaks ties. */
s32 binary_formats_match(const binary_format_t *formats, u32 count,
                         const u8 *buf, u32 len);

#endif
