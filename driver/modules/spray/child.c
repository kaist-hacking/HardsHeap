#include <stdint.h>

#include "child/api.h"
#include "child/array.h"
#include "child/heap_manager.h"
#include "common/stream.h"

extern Stream g_shm_strm;

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

void finalize(HeapManager* hmgr) {
  for (int index = 0; index < hmgr->arr.front; index++) {
    uintptr_t h = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
    if (!h || h == kBadPtr)
      continue;
    stream_write_ptr(&g_shm_strm, h);
    stream_write_ptr(&g_shm_strm, h + hmgr->usable_size[index]);
  }
}
