#include "api.h"

WEAK_ATTRIBUTE const char* additional_argv[MAX_ARGC + 1] = { NULL };

WEAK_ATTRIBUTE void module_usage() {}

WEAK_ATTRIBUTE void initialize(int argc, char** argv) {}

WEAK_ATTRIBUTE void finalize(HeapManager* hmgr) {}

WEAK_ATTRIBUTE void post_allocate_dryrun(HeapManager* hmgr, Array* buffer, int index) {}

WEAK_ATTRIBUTE void post_allocate(HeapManager* hmgr, Array* buffer, int index) {}

WEAK_ATTRIBUTE void pre_deallocate(HeapManager* hmgr, Array* buffer, int index) {}

WEAK_ATTRIBUTE void post_deallocate(HeapManager* hmgr, Array* buffer, int index) {}

WEAK_ATTRIBUTE void post_heap_write(HeapManager* hmgr, Array* buffer) {}

WEAK_ATTRIBUTE void post_buffer_write(HeapManager* hmgr, Array* buffer, int index, int num) {}

WEAK_ATTRIBUTE void post_double_free(HeapManager* hmgr, Array* buffer) {}

WEAK_ATTRIBUTE void post_arbitrary_free(HeapManager* hmgr, Array* buffer) {}
