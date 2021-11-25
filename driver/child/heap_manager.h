#ifndef __HARDSHEAP_HEAP_MANAGER_H__
#define __HARDSHEAP_HEAP_MANAGER_H__

#include <stdio.h>
#include <stdint.h>
#include "array.h"

typedef struct {
  Array arr;
  bool* freed;
  bool* valid;
  size_t* usable_size;
  int limit;
  size_t* size;
} HeapManager;

#define kBadPtr  0xcccccccc

void heap_mgr_init(HeapManager* hmgr, int limit);
void* heap_mgr_get_heap(HeapManager* hmgr, int* index);
void* heap_mgr_get_valid_heap(HeapManager* hmgr, int* index);
void* heap_mgr_get_freed_heap(HeapManager* hmgr, int* index);

#endif // __HARDSHEAP_HEAP_MANAGER_H__
