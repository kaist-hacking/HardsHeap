#include <stdint.h>
#include <unistd.h>

#include "child/api.h"
#include "child/array.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/logging.h"
#include "common/stream.h"

typedef enum {
    EVENT_ADJACENT
} EventType;

const int             adj_leniency = 0x10;
extern Stream         g_shm_strm;
bool strict = true;
bool cross_obj = false;

const char* additional_argv[MAX_ARGC + 1] = {
    // Disable every write action
    "-c",
    "HEAP_WRITE",
    "-c",
    "BUFFER_WRITE",
    // Disable every buggy action
    "-c",
    "VULN",
    NULL
};

void module_usage() {
  fprintf(stderr, "  -S: Disable a strict mode for adjacent (i.e., considering indices)\n");
  fprintf(stderr, "  -c: Report only adjacent objects with different sizes\n");
}

void initialize(int argc, char** argv) {
  int c;
  while ((c = getopt(argc, argv, "Sc")) != -1) {
    switch (c) {
      case 'S':
        strict = false;
        fprintf(stderr, "// [adjacent] Disable a strict mode\n");
        break;
      case 'c':
        cross_obj = true;
        fprintf(stderr, "// [adjacent] Enable a cross-object mode\n");
        break;
      default:
        module_usage();
        exit(-1);
    }
  }

  if (optind != argc) {
    // Failed to process all arguments
    module_usage();
    exit(-1);
  }

  stream_write_8(&g_shm_strm, strict);
}

void post_allocate(HeapManager* hmgr, Array* buffer, int index)
{
    // Check whether blocks adjacent to the current block within adj_leniency.
    // adj_leniency is required for handling allocators with inline metadata.
    uintptr_t h1 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
    size_t h1_size = hmgr->usable_size[index];
    uintptr_t h1_end = h1 + h1_size;

    if (h1 == 0 || h1 == kBadPtr)
        return;

    for (int i = 0; i < hmgr->arr.front; i++) {
        if (i == index)
            continue;

        uintptr_t h2 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &i);
        size_t h2_size = hmgr->usable_size[i];
        uintptr_t h2_end = h2 + h2_size;

        if (h2 == 0 || h2 == kBadPtr)
            continue;

        // If we enable cross object mode,
        // skip adjacent if objects size are equal
        if (cross_obj && h1_size == h2_size) continue;

        if ((h1_end - adj_leniency <= h2
                && h1_end + adj_leniency >= h2) // h1 -> h2
            || (h2_end - adj_leniency <= h1
                && h2_end + adj_leniency >= h1)) // h2 -> h1
        {
            set_event_type(EVENT_ADJACENT, "ADJACENT");
            DEBUG("[BUG] Found adjacent chunk");
            DEBUG("p[%d]=%p (size=%ld), "
                  "p[%d]=%p (size=%ld)",
                index, (void*)h1, h1_size,
                i, (void*)h2, h2_size);

            BEGIN_STMT;
            STMT("assert("
                  "(p[%d] + malloc_usable_size(p[%d]) - %d <= p[%d] && p[%d] + malloc_usable_size(p[%d]) + %d >= p[%d])"
                  " || (p[%d] + malloc_usable_size(p[%d]) - %d <= p[%d] && p[%d] + malloc_usable_size(p[%d]) + %d >= p[%d]))",
                  i, i, adj_leniency, index,
                  i, i, adj_leniency, index,
                  index, index, adj_leniency, i,
                  index, index, adj_leniency, i);
            END_STMT

            stream_write_8(&g_shm_strm, 1);
            stream_write_32(&g_shm_strm, index);
            stream_write_32(&g_shm_strm, i);
        }
    }
}

void finalize(HeapManager* UNUSED(hmgr)) {
  // -1 is used to notify the end of data
  stream_write_8(&g_shm_strm, 1);
  stream_write_32(&g_shm_strm, -1);
  stream_write_32(&g_shm_strm, -1);
}

