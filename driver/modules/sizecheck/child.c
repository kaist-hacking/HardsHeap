#include <stdint.h>
#include <unistd.h>

#include "child/api.h"
#include "child/array.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/logging.h"
#include "common/stream.h"

typedef enum {
    EVENT_SIZECHECK
} EventType;

extern Stream g_shm_strm;
bool strict = false;

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

void post_allocate(HeapManager* hmgr, Array* buffer, int index)
{
    uintptr_t h1 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &index);
    if (!h1 || h1 == kBadPtr)
        return;

    if (hmgr->usable_size[index] < hmgr->size[index]) {
        DEBUG("[BUG] Insufficient size allocated: p[%d]=malloc(%ld) (size=%ld)",
            index, hmgr->size[index], hmgr->usable_size[index]);
        set_event_type(EVENT_SIZECHECK, "SIZECHECK");
        BEGIN_STMT;
        STMT("assert(malloc_usable_size(p[%d]) < %ld)", index, hmgr->size[index]);
        END_STMT;
    }
}

void finalize(HeapManager* UNUSED(hmgr)) {
    stream_write_8(&g_shm_strm, has_event());
}

