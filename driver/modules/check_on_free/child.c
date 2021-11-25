#include <stdint.h>
#include <unistd.h>

#include "child/api.h"
#include "child/array.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/config.h"
#include "common/logging.h"
#include "common/stream.h"

typedef enum {
    EVENT_CHECK_ON_FREE
} EventType;

extern Stream g_shm_strm;
bool strict = false;
const size_t n_check = 0x100;
const char magic = 0xaa;
Array corrupted;

const char* additional_argv[MAX_ARGC + 1] = {
    // Disable every write action
    "-c",
    "HEAP_WRITE",
    "-c",
    "BUFFER_WRITE",
    // Enable only overflow
    "-v", "OFF_BY_ONE_NULL",
    "-v", "OFF_BY_ONE",
    "-v", "WRITE_AFTER_FREE",
    "-v", "DOUBLE_FREE",
    "-v", "ARBITRARY_FREE",
    NULL
};

void initialize(int argc, char** argv) {
  array_init(&corrupted, HEAP_LIMIT, sizeof(char));
}

void post_allocate(HeapManager* hmgr, Array* buffer, int index)
{
    // For optimization, instead of polluting all chunk memory,
    // let's focus on start of the chunk
    uintptr_t h = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
    if (!h || h == kBadPtr)
        return;

    size_t size = MIN(n_check, hmgr->usable_size[index]);
    memset((void*)h, magic, size);
    array_set(&corrupted, index, 0);
}

void pre_deallocate(HeapManager* hmgr, Array* buffer, int index) {
  // For optimization, instead of polluting all chunk memory,
  // let's focus on start of the chunk
  uintptr_t h = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
  if (!h || h == kBadPtr)
    return;

  size_t size = MIN(n_check, hmgr->usable_size[index]);
  char* ptr = (char*)h;
  for (int i = 0; i < size; i++) {
    if (ptr[i] != magic) {
      array_set(&corrupted, index, 1);
      return;
    }
  }
}

void post_deallocate(HeapManager* hmgr, Array* buffer, int index) {
  uintptr_t h = (uintptr_t)heap_mgr_get_heap(hmgr, &index);
  if (!h || h == kBadPtr)
    return;

  if (array_get(&corrupted, index)) {
    DEBUG("[BUG] Found corrupted yet successfully free: p[%d]=%p", index, h);
    set_event_type(EVENT_CHECK_ON_FREE, "CHECK_ON_FREE");
    END_STMT;
  }
}

void finalize(HeapManager* UNUSED(hmgr)) {
    stream_write_8(&g_shm_strm, has_event());
}

