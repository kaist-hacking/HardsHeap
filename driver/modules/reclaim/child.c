#include <stdint.h>
#include <unistd.h>

#include "child/api.h"
#include "child/array.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/logging.h"
#include "common/stream.h"

typedef enum {
    EVENT_RECLAIM
} EventType;

extern Stream         g_shm_strm;
bool strict = true;

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
  fprintf(stderr, "  -S: Disable a strict mode for reclaim (i.e., considering indices)\n");
}

void initialize(int argc, char** argv) {
  int c;
  while ((c = getopt(argc, argv, "S")) != -1) {
    switch (c) {
      case 'S':
        strict = false;
        fprintf(stderr, "// [reclaim] Disable a strict mode\n");
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
    uintptr_t h1 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
    if (!h1 || h1 == kBadPtr)
        return;

    int dangled_index = -1;
    // search heap manager to see if the currently allocated heap was allocated from previous actions
    for (int i = 0; i < index; i++) {
        uintptr_t h2 = (uintptr_t)heap_mgr_get_freed_heap(hmgr, &i);
        if (!h2 || h2 == kBadPtr)
            continue;

        if (h2 <= h1 && h1 < h2 + hmgr->usable_size[i]) {
            // Don't break.
            // We want to find the most recent one.
            dangled_index = i;
        }
    }

    if (dangled_index != -1) {
        uintptr_t dangled_ptr = (uintptr_t)heap_mgr_get_freed_heap(hmgr, &dangled_index);
        // if it had been allocated before, it is either destroyed or took from the backend
        // store the dealloc-alloc pair
        DEBUG("[BUG] Reclaim happends: p[%d]=%p (size=%ld) -> p[%d]= %p (size=%ld)",
            dangled_index, dangled_ptr, hmgr->usable_size[dangled_index],
            index, h1, hmgr->usable_size[index]);
        BEGIN_STMT;
        STMT("assert(p[%d] <= p[%d] && p[%d] < p[%d] + %ld)",
            dangled_index, index,
            index, dangled_index,
            hmgr->usable_size[dangled_index]);
        set_event_type(EVENT_RECLAIM, "RECLAIM");
        END_STMT;

        stream_write_8(&g_shm_strm, 1);
        stream_write_32(&g_shm_strm, dangled_index);
        stream_write_32(&g_shm_strm, index);
    }
}

void finalize(HeapManager* UNUSED(hmgr)) {
  // -1 is used to notify the end of data
  stream_write_8(&g_shm_strm, 1);
  stream_write_32(&g_shm_strm, -1);
  stream_write_32(&g_shm_strm, -1);
}

