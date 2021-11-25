#include "heap_manager.h"
#include "utils.h"
#include "common/utils.h"

void heap_mgr_init(HeapManager* hmgr, int limit) {
  hmgr->limit = limit;
  array_init(&hmgr->arr, limit, sizeof(void*));
  hmgr->freed = (bool*)random_mmap(round_up_page_size(limit));
  hmgr->valid = (bool*)random_mmap(round_up_page_size(limit));
  hmgr->usable_size = (size_t*)random_mmap(round_up_page_size(limit * sizeof(size_t)));
  hmgr->size = (size_t*)random_mmap(round_up_page_size(limit * sizeof(size_t)));
}

void* heap_mgr_get_heap(HeapManager* hmgr, int* index) {
  if (array_is_empty(&hmgr->arr))
    return NULL;
  *index %= hmgr->arr.front;
  if (hmgr->valid[*index])
    return (void*)array_get(&hmgr->arr, *index);
  else
    return (void*)kBadPtr;
}

void* heap_mgr_get_valid_heap(HeapManager* hmgr, int* index) {
  if (array_is_empty(&hmgr->arr))
    return NULL;

  *index %= hmgr->arr.front;
  if (hmgr->freed[*index])
    return NULL;

  return (void*)heap_mgr_get_heap(hmgr, index);
}

void* heap_mgr_get_freed_heap(HeapManager* hmgr, int* index) {
  if (array_is_empty(&hmgr->arr))
    return NULL;

  *index %= hmgr->arr.front;
  if (!hmgr->freed[*index])
    return NULL;

  return heap_mgr_get_heap(hmgr, index);
}
