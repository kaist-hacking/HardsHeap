#include <stdint.h>

#include "child/api.h"
#include "child/array.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/logging.h"
#include "common/stream.h"

typedef enum {
    EVENT_METADATA
} EventType;

extern Stream g_shm_strm;
const size_t n_check = 0x100;

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

void check_bytes(uintptr_t h, int index, size_t start, size_t end)
{
    bool is_first = true;
    uint8_t* ptr = (uint8_t*)h;
    for (int i = start; i < end; i++) {
        if (ptr[i] != 0) {
            DEBUG("[BUG] Found uninitialized: p[%d][%d] = %x", index, i, ptr[i]);
            set_event_type(EVENT_METADATA, "METADATA");

            if (is_first) {
              BEGIN_STMT;
              STMT("assert(((char*)p[%d])[%d] != 0)", index, i);
              is_first = false;
            }
            END_STMT;
        }
    }
}

void post_allocate(HeapManager* hmgr, Array* buffer, int index)
{
    uintptr_t h = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
    if (!h || h == kBadPtr)
        return;

    // For optimization, instead of scanning all chunk memory,
    // let's focus on start and end of the chunk
    size_t start = 0;
    size_t end = MIN(n_check, hmgr->usable_size[index]);
    check_bytes(h, index, start, end);

    if (hmgr->usable_size[index] > n_check) {
        // Skip indicies that are covered from the previous loop
        size_t start = MAX(hmgr->usable_size[index] - n_check, n_check);
        size_t end = hmgr->usable_size[index];
        check_bytes(h, index, start, end);
    }
}

void finalize(HeapManager* UNUSED(hmgr))
{
    stream_write_8(&g_shm_strm, has_event());
}
