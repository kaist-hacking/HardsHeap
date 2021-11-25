#ifndef __HARDSHEAP_API_H__
#define __HARDSHEAP_API_H__

#if defined(__GNUC__)
# define UNUSED(x) UNUSED_##x __attribute__((unused))
# define WEAK_ATTRIBUTE __attribute__((weak))
#else
# define UNUSED(x) x
# define WEAK_ATTRIBUTE
#endif

#include "heap_manager.h"
#include "array.h"

#define MAX_ARGC 255
const char* additional_argv[MAX_ARGC + 1];

void initialize(int argc, char** argv);
void finalize(HeapManager* hmgr);
void module_usage();

// void pre_allocate(HeapManager* hmgr, Array* buffer, int index);
void post_allocate(HeapManager* hmgr, Array* buffer, int index);
void post_allocate_dryrun(HeapManager* hmgr, Array* buffer, int index);

void pre_deallocate(HeapManager* hmgr, Array* buffer, int index);
void post_deallocate(HeapManager* hmgr, Array* buffer, int index);

// void pre_heap_write(HeapManager* hmgr, Array* buffer);
void post_heap_write(HeapManager* hmgr, Array* buffer);

// void pre_buffer_write(HeapManager* hmgr, Array* buffer, int index, int num);
void post_buffer_write(HeapManager* hmgr, Array* buffer, int index, int num);

// void pre_double_free(HeapManager* hmgr, Array* buffer);
void post_double_free(HeapManager* hmgr, Array* buffer);

// void pre_arbitrary_free(HeapManager* hmgr, Array* buffer);
void post_arbitrary_free(HeapManager* hmgr, Array* buffer);

#endif // __HARDSHEAP_API_H__
