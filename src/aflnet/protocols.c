/* aflnet/protocols.c - protocol request / message extractors.

   Split out of src/afl-fuzz-aflnet.c.  Each extract_requests_<proto>()
   splits a raw testcase byte stream into a sequence of regions (one per
   protocol message), so that the fuzzer can mutate a single message while
   keeping the surrounding ones intact. */

#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "afl-fuzz.h"
#include "aflnet.h"
#include "aflnet-internal.h"
#include "alloc-inl.h" 

static void afl_net_append_region(region_t **regions, unsigned int *region_count,
                                  int start, int end) {

  *regions = (region_t *)ck_realloc(*regions,
                                   (*region_count + 1) * sizeof(region_t));
  region_t *region = &(*regions)[*region_count];
  region->start_byte = start;
  region->end_byte = end;
  region->modifiable = 1;
  region->state_sequence = NULL;
  region->state_count = 0;
  (*region_count)++;

}
static region_t *afl_net_finalize_regions(region_t *regions,
                                          unsigned int *region_count_ref,
                                          unsigned int buf_size) {

  if ((*region_count_ref == 0) && (buf_size > 0)) {
    afl_net_append_region(&regions, region_count_ref, 0,
                          (int)buf_size - 1);
  }

  return regions;

}
u32 read_bytes_to_uint32(unsigned char *buf, unsigned int offset,
                         int num_bytes) {

  u32 val = 0;
  for (int i = 0; i < num_bytes; i++) {
    val = (val << 8) + buf[i + offset];
  }

  return val;

}
region_t *extract_requests_tftp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[2] = {0x00, 0x00};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_dhcp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[2] = {0xff, 0xff};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_SNTP(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[1] = {0x0};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_NTP(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[1] = {0x0};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  if (buf_size == 48) {
    for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
      memcpy(&mem[mem_count], buf + byte_count, 1);
      if (mem_count == 47) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;
      } else {
        mem_count++;
        cur_end++;
        if (cur_end == buf_size - 1) {
          afl_net_append_region(&regions, &region_count, (int)cur_start,
                                (int)cur_end);
          break;
        }
        if (mem_count == mem_size) {
          mem_size = mem_size * 2;
          mem = (char *)ck_realloc(mem, mem_size);
        }
      }
    }
  } else {
    for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
      memcpy(&mem[mem_count], buf + byte_count, 1);
      if (((mem_count > 48) &&
           (memcmp(&mem[mem_count - 1], terminator, 1) == 0) &&
           (mem_count == 68 || mem_count == 120))) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;
      } else {
        mem_count++;
        cur_end++;
        if (cur_end == buf_size - 1) {
          afl_net_append_region(&regions, &region_count, (int)cur_start,
                                (int)cur_end);
          break;
        }
        if (mem_count == mem_size) {
          mem_size = mem_size * 2;
          mem = (char *)ck_realloc(mem, mem_size);
        }
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_SNMP(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[1] = {0x0};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_smtp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[2] = {0x0D, 0x0A};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);
    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_ssh(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[2] = {0x0D, 0x0A};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if (mem_count >= 6) {
      if (!strncmp(mem, "SSH-", 4)) {
        while ((byte_count < buf_size) &&
               (memcmp(&mem[mem_count - 1], terminator, 2))) {
          if (mem_count == mem_size - 1) {
            mem_size = mem_size * 2;
            mem = (char *)ck_realloc(mem, mem_size);
          }
          memcpy(&mem[++mem_count], buf + byte_count++, 1);
          cur_end++;
        }

        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);

        if (cur_end < buf_size - 1) {
          mem_count = 0;
          cur_start = cur_end + 1;
          cur_end = cur_start;
        }
      } else {
        unsigned int *size_buf = (unsigned int *)&mem[0];
        unsigned int  message_size = (unsigned int)ntohl(*size_buf);
        unsigned char message_code = (unsigned char)mem[5];
        unsigned int  bytes_to_skip = message_size - 2;

        if ((message_code >= 20) && (message_code <= 49)) {
          /* key exchange */
        } else {
          bytes_to_skip += 8;
        }

        unsigned int temp_count = 0;
        while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
          byte_count++;
          cur_end++;
          temp_count++;
        }

        if (byte_count < buf_size) {
          byte_count--;
          cur_end--;
        }

        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);

        if (cur_end < buf_size - 1) {
          mem_count = 0;
          cur_start = cur_end + 1;
          cur_end = cur_start;
        }
      }
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_tls(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if (mem_count >= 5) {
      u16 *size_buf = (u16 *)&mem[3];
      u16  message_size = (u16)ntohs(*size_buf);
      unsigned int bytes_to_skip = message_size;
      unsigned int temp_count = 0;

      while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
        byte_count++;
        cur_end++;
        temp_count++;
      }

      if (byte_count < buf_size) {
        byte_count--;
        cur_end--;
      }

      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);

      if (cur_end < buf_size - 1) {
        mem_count = 0;
        cur_start = cur_end + 1;
        cur_end = cur_start;
      }
    } else {
      mem_count++;
      cur_end++;
      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_dicom(unsigned char *buf, unsigned int buf_size,
                                 unsigned int *region_count_ref) {

  unsigned int pdu_length = 0;
  unsigned int packet_length = 0;
  unsigned int region_count = 0;
  unsigned int end = 0;
  unsigned int start = 0;
  region_t     *regions = NULL;
  unsigned int byte_count = 0;

  while (byte_count < buf_size) {
    if ((byte_count + 2 >= buf_size) || (byte_count + 5 >= buf_size)) { break; }

    pdu_length = (buf[byte_count + 5]) |
                 (buf[byte_count + 4] << 8) |
                 (buf[byte_count + 3] << 16) |
                 (buf[byte_count + 2] << 24);

    packet_length = pdu_length + 6;

    start = byte_count;
    end = byte_count + packet_length - 1;

    if (end < start) { break; }
    if (end >= buf_size) { break; }

    afl_net_append_region(&regions, &region_count, (int)start, (int)end);

    if ((byte_count + packet_length) < byte_count) { break; }
    if ((byte_count + packet_length) < packet_length) { break; }
    byte_count += packet_length;
  }

  if ((byte_count < buf_size) && (buf_size > 0)) {
    afl_net_append_region(&regions, &region_count, (int)byte_count,
                          (int)buf_size - 1);
  }

  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_dns(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);

    if ((mem_count >= 12) && (*(mem + mem_count) == 0)) {
      cur_end += 4;
      byte_count += 4;

      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);

      if (cur_end == buf_size - 1) { break; }

      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size *= 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_rtsp(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 3) && (memcmp(&mem[mem_count - 3], terminator, 4) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_ftp(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[2] = {0x0D, 0x0A};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_mqtt(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;
  region_t      *regions = NULL;

  mem = (char *)ck_alloc(mem_size);

  while (cur_start < buf_size) {
    if ((buf_size - cur_start) == 1) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)buf_size - 1);
      break;
    }

    memcpy(&mem[mem_count], buf + cur_start, 2);
    cur_start = cur_start + 2;

    if (mem[1] >= 0) {
      cur_end = cur_start + (unsigned char)mem[1] - 1;
    } else {
      cur_end = buf_size;
    }

    afl_net_append_region(&regions, &region_count, (int)cur_start - 2,
                          (int)cur_end);

    mem_count = 0;
    cur_start = cur_end + 1;
    cur_end = cur_start;
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_sip(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[2] = {0x0D, 0x0A};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 1) && (memcmp(&mem[mem_count - 1], terminator, 1) == 0) &&
        (((buf_size - byte_count >= 8) &&
          (memcmp(buf + byte_count, "REGISTER", 8) == 0)) ||
         ((buf_size - byte_count >= 6) &&
          (memcmp(buf + byte_count, "INVITE", 6) == 0)) ||
         ((buf_size - byte_count >= 3) &&
          (memcmp(buf + byte_count, "ACK", 3) == 0)) ||
         ((buf_size - byte_count >= 3) &&
          (memcmp(buf + byte_count, "BYE", 3) == 0)))) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_http(unsigned char *buf, unsigned int buf_size,
                                unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count >= 4) && (memcmp(&mem[mem_count - 3], terminator, 4) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}
region_t *extract_requests_ipp(unsigned char *buf, unsigned int buf_size,
                               unsigned int *region_count_ref) {

  char          *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int   region_count = 0;
  region_t      *regions = NULL;
  char           terminator[4] = {0x0D, 0x0A, 0x0D, 0x0A};
  char           ipp[1] = {0x03};
  unsigned int   cur_start = 0;
  unsigned int   cur_end = 0;

  mem = (char *)ck_alloc(mem_size);

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 3) &&
        ((memcmp(&mem[mem_count - 3], terminator, 4) == 0) ||
         (memcmp(&mem[mem_count], ipp, 1) == 0)) &&
        ((buf_size - byte_count >= 4) &&
         (memcmp(buf + byte_count, "POST", 4) == 0))) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)cur_end);
      mem_count = 0;
      cur_start = cur_end + 1;
      cur_end = cur_start;
    } else {
      mem_count++;
      cur_end++;

      if (cur_end == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)cur_end);
        break;
      }

      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}

/* DTLS 1.2 record version marker.  The content-type / message-type defines
   used here (CCS_CONTENT_TYPE ... MALFORMED_MESSAGE_TYPE) are shared with
   response_codes.c and live in aflnet-internal.h. */
unsigned char dtls12_version[2] = {0xFE, 0xFD};

region_t *extract_requests_dtls12(unsigned char *buf, unsigned int buf_size,
                                  unsigned int *region_count_ref) {

  unsigned int byte_count = 0;
  unsigned int region_count = 0;
  region_t     *regions = NULL;
  unsigned int  cur_start = 0;

  while (byte_count < buf_size) {
    if ((byte_count > 3 && buf_size - byte_count > 1) &&
        (buf[byte_count] >= CCS_CONTENT_TYPE &&
         buf[byte_count] <= HEARTBEAT_CONTENT_TYPE) &&
        (memcmp(&buf[byte_count + 1], dtls12_version, 2) == 0)) {
      afl_net_append_region(&regions, &region_count, (int)cur_start,
                            (int)byte_count - 1);
      cur_start = byte_count;
    } else {
      if (byte_count == buf_size - 1) {
        afl_net_append_region(&regions, &region_count, (int)cur_start,
                              (int)byte_count);
        break;
      }
    }

    byte_count++;
  }

  regions = afl_net_finalize_regions(regions, &region_count, buf_size);
  *region_count_ref = region_count;
  return regions;

}

/* Extractor of response codes */

static u32  message_code_counter = 0;
static u32  message_code_cap = 0;
static u32  message_code_count = 0;
static u32 *message_code_keys = NULL;
static u32 *message_code_vals = NULL;
void init_message_code_map(void) {

  message_code_counter = 0;
  message_code_cap = 0;
  message_code_count = 0;
  ck_free(message_code_keys);
  ck_free(message_code_vals);
  message_code_keys = NULL;
  message_code_vals = NULL;

}
void destroy_message_code_map(void) {

  ck_free(message_code_keys);
  ck_free(message_code_vals);
  message_code_keys = NULL;
  message_code_vals = NULL;
  message_code_cap = 0;
  message_code_count = 0;
  message_code_counter = 0;

}
static u32 get_mapped_message_code(u32 ori_message_code) {

  for (u32 i = 0; i < message_code_count; i++) {
    if (message_code_keys[i] == ori_message_code) {
      return message_code_vals[i];
    }
  }

  if (message_code_count == message_code_cap) {
    u32 new_cap = message_code_cap ? message_code_cap * 2 :
                                     AFLNET_CODE_MAP_INIT_CAP;
    message_code_keys = (u32 *)ck_realloc(message_code_keys,
                                          new_cap * sizeof(u32));
    message_code_vals = (u32 *)ck_realloc(message_code_vals,
                                          new_cap * sizeof(u32));
    message_code_cap = new_cap;
  }

  message_code_counter++;
  message_code_keys[message_code_count] = ori_message_code;
  message_code_vals[message_code_count] = ori_message_code;
  // message_code_vals[message_code_count] = message_code_counter;
  message_code_count++;

  return ori_message_code;
  // return message_code_counter;

}
unsigned int *extract_response_codes_tftp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator_one[1] = {0x00};
  char          terminator_two[1] = {0x03};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) &&
        ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0))) {
      char         temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);

      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size) {
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      break;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_dhcp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator_one[1] = {0x02};
  char          terminator_two[1] = {0x04};
  char          terminator_three[1] = {0x05};
  char          terminator_four[1] = {0x06};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 240) &&
        (((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) ||
          (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0)) ||
         (memcmp(&mem[mem_count - 1], terminator_three, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_four, 1) == 0))) {
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);

      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size) {
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);

      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      break;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_SNTP(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator_one[1] = {0x24};
  char          terminator_two[1] = {0x35};
  char          terminator_three[1] = {0x01};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) &&
        ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_three, 1) == 0))) {
      unsigned int message_code = (unsigned int)(unsigned char)mem[0];
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size) {
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      break;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_NTP(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator_one[1] = {0x24};
  char          terminator_two[1] = {0x35};
  char          terminator_three[1] = {0x01};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) &&
        ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_three, 1) == 0))) {
      unsigned int message_code = (unsigned int)(unsigned char)mem[0];
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size) {
      char temp[5];
      memcpy(temp, mem, 5);
      temp[4] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      break;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_SNMP(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator_one[1] = {0x0A};
  char          terminator_two[1] = {0x01};
  char          terminator_three[1] = {0x02};
  char          terminator_four[1] = {0x03};
  char          terminator_five[1] = {0x04};
  char          terminator_six[1] = {0x05};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 7) &&
        ((memcmp(&mem[mem_count - 1], terminator_one, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_two, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_three, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_four, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_five, 1) == 0) ||
         (memcmp(&mem[mem_count - 1], terminator_six, 1) == 0))) {
      unsigned int message_code = (unsigned int)(unsigned char)mem[byte_count - 1];
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else if (byte_count == buf_size) {
      unsigned int message_code = (unsigned int)(unsigned char)mem[byte_count - 1];
      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      break;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_smtp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator[2] = {0x0D, 0x0A};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      char temp[4];
      memcpy(temp, mem, 4);
      temp[3] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);

      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_ssh(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         mem[7];
  unsigned int byte_count = 0;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  if (state_sequence == NULL) {
    PFATAL("Unable realloc a memory region to store state sequence");
  }
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(mem, buf + byte_count, 6);
    byte_count += 6;

    if (strstr(mem, "SSH")) {
      char tmp = 0x00;
      while (tmp != 0x0A) {
        memcpy(&tmp, buf + byte_count, 1);
        byte_count += 1;
      }

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      if (state_sequence == NULL) {
        PFATAL("Unable realloc a memory region to store state sequence");
      }
      state_sequence[state_count - 1] = 256;
    } else {
      unsigned int *size_buf = (unsigned int *)&mem[0];
      unsigned int  message_size = (unsigned int)ntohl(*size_buf);

      if (message_size - 2 > buf_size - byte_count) { break; }

      unsigned char message_code = (unsigned char)mem[5];

      if ((message_code >= 20) && (message_code <= 49)) {
        /* key exchange */
      } else {
        message_size += 8;
      }

      message_code = (unsigned char)get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      if (state_sequence == NULL) {
        PFATAL("Unable realloc a memory region to store state sequence");
      }
      state_sequence[state_count - 1] = message_code;

      byte_count += message_size - 2;
    }
  }

  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_tls(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned char content_type;
  unsigned char message_type;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if (mem_count >= 6) {
      content_type = mem[0];

      if (content_type != 0x17) {
        message_type = mem[5];
      } else {
        message_type = 0xFF;
      }

      u16 *size_buf = (u16 *)&mem[3];
      u16  message_size = (u16)ntohs(*size_buf);

      unsigned int bytes_to_skip = message_size - 1;
      unsigned int temp_count = 0;
      while ((byte_count < buf_size) && (temp_count < bytes_to_skip)) {
        byte_count++;
        temp_count++;
      }

      if (byte_count < buf_size) { byte_count--; }

      unsigned int message_code = (content_type << 8) + message_type;
      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }

  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_dicom(unsigned char *buf,
                                           unsigned int  buf_size,
                                           unsigned int *state_count_ref) {

  if (buf_size == 0) {
    *state_count_ref = 0;
    return NULL;
  }

  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  state_count++;
  unsigned int message_code = buf[0];
  message_code = get_mapped_message_code(message_code);
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = message_code;

  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_dns(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  for (unsigned int byte_count = 0; byte_count < buf_size; byte_count++) {
    memcpy(&mem[mem_count], buf + byte_count, 1);

    if ((mem_count >= 12) && (*(mem + mem_count) == 0)) {
      byte_count += 5;
      mem_count += 5;

      unsigned int message_code =
          (unsigned int)((mem[2] << 8) + mem[3]);
      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_dtls12(unsigned char *buf,
                                            unsigned int  buf_size,
                                            unsigned int *state_count_ref) {

  unsigned int  byte_count = 0;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  unsigned int  status_code = 0;

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    if ((buf_size - byte_count > 13) &&
        (buf[byte_count] >= CCS_CONTENT_TYPE &&
         buf[byte_count] <= HEARTBEAT_CONTENT_TYPE) &&
        (memcmp(&buf[byte_count + 1], dtls12_version, 2) == 0)) {
      unsigned char content_type = buf[byte_count];
      unsigned char message_type;
      u32 record_length = read_bytes_to_uint32(buf, byte_count + 11, 2);

      if ((int)(buf_size - byte_count - 13 - record_length) < 0) {
        message_type = MALFORMED_MESSAGE_TYPE;
      } else {
        switch (content_type) {
          case HS_CONTENT_TYPE: {
            unsigned char hs_msg_type = buf[byte_count + 13];
            if (record_length >= 12) {
              u32 frag_length = read_bytes_to_uint32(buf, byte_count + 22, 3);
              if (record_length - frag_length == 12) {
                message_type = hs_msg_type;
              } else {
                message_type = UNKNOWN_MESSAGE_TYPE;
              }
            } else {
              message_type = MALFORMED_MESSAGE_TYPE;
            }
          } break;
          case CCS_CONTENT_TYPE:
            if (record_length == 1) {
              unsigned char ccs_msg_type = buf[byte_count + 13];
              message_type = ccs_msg_type;
            } else {
              if (record_length > 1) {
                message_type = UNKNOWN_MESSAGE_TYPE;
              } else {
                message_type = MALFORMED_MESSAGE_TYPE;
              }
            }
            break;
          case ALERT_CONTENT_TYPE:
            if (record_length == 2) {
              unsigned char type = buf[byte_count + 14];
              message_type = type;
            } else {
              if (record_length > 2) {
                message_type = UNKNOWN_MESSAGE_TYPE;
              } else {
                message_type = MALFORMED_MESSAGE_TYPE;
              }
            }
            break;
          case APPLICATION_CONTENT_TYPE:
            message_type = UNKNOWN_MESSAGE_TYPE;
            break;
          case HEARTBEAT_CONTENT_TYPE:
            if (record_length >= 3) {
              message_type = UNKNOWN_MESSAGE_TYPE;
            } else {
              message_type = MALFORMED_MESSAGE_TYPE;
            }
            break;
          default:
            content_type = UNKNOWN_CONTENT_TYPE;
            message_type = UNKNOWN_MESSAGE_TYPE;
            break;
        }
      }

      status_code = (content_type << 8) + message_type;
      status_code = get_mapped_message_code(status_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = status_code;
      byte_count += record_length;
    } else {
      byte_count++;
    }
  }

  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_rtsp(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator[2] = {0x0D, 0x0A};
  char          rtsp[5] = {0x52, 0x54, 0x53, 0x50, 0x2f};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      if ((mem_count >= 5) && (memcmp(mem, rtsp, 5) == 0)) {
        char temp[4];
        memcpy(temp, &mem[9], 4);
        temp[3] = 0x0;
        unsigned int message_code = (unsigned int)atoi(temp);

        if (message_code == 0) { break; }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                    state_count *
                                                        sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_ftp(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator[2] = {0x0D, 0x0A};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);
    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0) &&
        ((mem[3] == ' ') ||
         (isdigit(buf[byte_count]) &&
          (memcmp(&mem[0], &buf[byte_count], 3)) != 0) ||
         byte_count == buf_size)) {
      char temp[4];
      memcpy(temp, mem, 4);
      temp[3] = 0x0;
      unsigned int message_code = (unsigned int)atoi(temp);

      if (message_code == 0) { break; }

      message_code = get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_mqtt(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  unsigned char *mem;
  unsigned int   byte_count = 0;
  unsigned int   mem_count = 0;
  unsigned int   mem_size = 1024;
  unsigned int  *state_sequence = NULL;
  unsigned int   state_count = 0;
  char           start1[1] = {0x20};
  char           start2[1] = {0x40};
  char           start3[1] = {0x50};
  char           start4[1] = {0x62};
  char           start5[1] = {0x70};
  char           start6[1] = {0x90};
  char           start7[1] = {0xB0};
  char           start8[1] = {0xD0};
  char           start9[1] = {0xE0};
  char           start10[1] = {0xF0};

  mem = (unsigned char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count++], buf + byte_count++, 1);
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) &&
        ((memcmp(&mem[0], start1, 1) == 0) ||
         (memcmp(&mem[0], start2, 1) == 0) ||
         (memcmp(&mem[0], start3, 1) == 0) ||
         (memcmp(&mem[0], start4, 1) == 0) ||
         (memcmp(&mem[0], start5, 1) == 0) ||
         (memcmp(&mem[0], start6, 1) == 0) ||
         (memcmp(&mem[0], start7, 1) == 0) ||
         (memcmp(&mem[0], start8, 1) == 0) ||
         (memcmp(&mem[0], start9, 1) == 0) ||
         (memcmp(&mem[0], start10, 1) == 0))) {
      unsigned char message_code = (unsigned char)mem[0];
      if (message_code == 0) { break; }

      message_code = (unsigned char)get_mapped_message_code(message_code);

      state_count++;
      state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                  state_count *
                                                      sizeof(unsigned int));
      state_sequence[state_count - 1] = message_code;
      mem_count = 0;
      byte_count = byte_count + mem[1];
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (unsigned char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_sip(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator[2] = {0x0D, 0x0A};
  char          sip[4] = {0x53, 0x49, 0x50, 0x2f};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      if ((mem_count >= 4) && (memcmp(mem, sip, 4) == 0)) {
        char temp[4];
        memcpy(temp, &mem[8], 4);
        temp[3] = 0x0;
        unsigned int message_code = (unsigned int)atoi(temp);

        if (message_code == 0) { break; }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                    state_count *
                                                        sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_http(unsigned char *buf,
                                          unsigned int  buf_size,
                                          unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminator[2] = {0x0D, 0x0A};
  char          http[5] = {0x48, 0x54, 0x54, 0x50, 0x2f};

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 0) && (memcmp(&mem[mem_count - 1], terminator, 2) == 0)) {
      if ((mem_count >= 5) && (memcmp(mem, http, 5) == 0)) {
        char temp[4];
        memcpy(temp, &mem[9], 4);
        temp[3] = 0x0;
        unsigned int message_code = (unsigned int)atoi(temp);

        if (message_code == 0) { break; }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                    state_count *
                                                        sizeof(unsigned int));
        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}
unsigned int *extract_response_codes_ipp(unsigned char *buf,
                                         unsigned int  buf_size,
                                         unsigned int *state_count_ref) {

  char         *mem;
  unsigned int  byte_count = 0;
  unsigned int  mem_count = 0;
  unsigned int  mem_size = 1024;
  unsigned int *state_sequence = NULL;
  unsigned int  state_count = 0;
  char          terminatorHTTP[4] = {0x0D, 0x0A, 0x0D, 0x0A};
  char          http[5] = {0x48, 0x54, 0x54, 0x50, 0x2F};
  unsigned int  message_code = 0;
  char          tempHTTP[4];

  mem = (char *)ck_alloc(mem_size);

  state_count++;
  state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                              state_count *
                                                  sizeof(unsigned int));
  if (state_sequence == NULL) {
    PFATAL("Unable realloc a memory region to store state sequence");
  }
  state_sequence[state_count - 1] = 0;

  while (byte_count < buf_size) {
    memcpy(&mem[mem_count], buf + byte_count++, 1);

    if ((mem_count > 3) &&
        (memcmp(&mem[mem_count - 3], terminatorHTTP, 4) == 0)) {
      if ((mem_count >= 5) && (memcmp(mem, http, 5) == 0)) {
        memcpy(tempHTTP, &mem[9], 4);
        tempHTTP[3] = 0x0;
        message_code = (unsigned int)atoi(tempHTTP);

        if (message_code == 0) { break; }

        if (message_code == 200) {
          unsigned int third = (unsigned int)buf[byte_count + 2];
          unsigned int fourth = (unsigned int)buf[byte_count + 3];
          message_code += (unsigned int)(10 * third + fourth);
        }

        message_code = get_mapped_message_code(message_code);

        state_count++;
        state_sequence = (unsigned int *)ck_realloc(state_sequence,
                                                    state_count *
                                                        sizeof(unsigned int));
        if (state_sequence == NULL) {
          PFATAL("Unable realloc a memory region to store state sequence");
        }

        state_sequence[state_count - 1] = message_code;
        mem_count = 0;
      } else {
        mem_count = 0;
      }
    } else {
      mem_count++;
      if (mem_count == mem_size) {
        mem_size = mem_size * 2;
        mem = (char *)ck_realloc(mem, mem_size);
      }
    }
  }

  if (mem) { ck_free(mem); }
  *state_count_ref = state_count;
  return state_sequence;

}