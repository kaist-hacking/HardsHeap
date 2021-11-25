#include <stdio.h>

#include "child/heap_manager.h"
#include "child/array.h"
#include "common/logging.h"

// Example
/*
char* additional_argv[] = {
    "-c", "DEALLOC", NULL
};
*/

void initialize(int argc, char** argv)
{
    DEBUG(DBG_INFO "=> initialize");
    for (int i = 1; i < argc; i++)
        DEBUG(DBG_INFO "\t%dth arg: %s", i, argv[i]);
}

void finalize(HeapManager* UNUSED(hmgr))
{
    DEBUG(DBG_INFO "=> finalize");
}

void post_allocate(HeapManager* hmgr, Array* buffer, int index)
{
    DEBUG(DBG_INFO "=> post_allocate");
}

void post_deallocate(HeapManager* hmgr, Array* buffer, int index)
{
    DEBUG(DBG_INFO "=> post_deallocate");
}

void post_heap_write(HeapManager* hmgr, Array* buffer)
{
    DEBUG(DBG_INFO "=> post_heap_write");
}

void post_buffer_write(HeapManager* hmgr, Array* buffer)
{
    DEBUG(DBG_INFO "=> post_buffer_write");
}

void post_double_free(HeapManager* hmgr, Array* buffer)
{
    DEBUG(DBG_INFO "=> post_double_free");
}

void post_arbitrary_free(HeapManager* hmgr, Array* buffer)
{
    DEBUG(DBG_INFO "=> post_arbitrary_free");
}
