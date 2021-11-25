#include <stdint.h>

#include "child/array.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/logging.h"
#include "common/stream.h"
#include "common/config.h"

typedef enum {
  EVENT_OVERLAP,
  EVENT_RESTRICTED_WRITE_IN_CONTAINER,
  EVENT_RESTRICTED_WRITE_IN_BUFFER,
  EVENT_ARBITRARY_WRITE_IN_CONTAINER,
  EVENT_ARBITRARY_WRITE_IN_BUFFER,
  EVENT_ALLOC_IN_CONTAINER,
  EVENT_ALLOC_IN_BUFFER,
  EVENT_LAST
} EventType;

Array hmgr_shadow;
Array buffer_shadow;

extern Stream         g_shm_strm;

void initialize(int argc, char** argv) {
  // XXX: move this to a shared header
  array_init(&hmgr_shadow, HEAP_LIMIT, sizeof(void*));
  array_init(&buffer_shadow, BUFFER_LIMIT, sizeof(void*));
}

void finalize(HeapManager* hmgr) {
    stream_write_8(&g_shm_strm, has_event());
}

void shadow_mem_sanity_check(Array* orig, Array* shadow)
{
    assert(orig->limit == shadow->limit
        && orig->nmemb == shadow->nmemb);
}

bool shadow_mem_verify(Array* orig, Array* shadow)
{
    shadow_mem_sanity_check(orig, shadow);

    return memcmp((void*)orig->mem, (void*)shadow->mem,
        orig->limit * orig->nmemb);
}

int shadow_mem_diff(Array* arr_orig, Array* arr_shadow, intptr_t* orig, intptr_t* shadow)
{
    shadow_mem_sanity_check(arr_orig, arr_shadow);

    void* ptr_orig = (void*)arr_orig->mem;
    void* ptr_shadow = (void*)arr_shadow->mem;

    for (int i = 0; i < arr_orig->limit; i++) {
        if (memcmp(ptr_orig, ptr_shadow, arr_orig->nmemb)) {
            *orig = *(intptr_t*)ptr_orig;
            *shadow = *(intptr_t*)ptr_shadow;
            return i;
        }

        ptr_orig += arr_orig->nmemb;
        ptr_shadow += arr_shadow->nmemb;
    }

    return -1;
}

void shadow_mem_make_same(Array* orig, Array* shadow)
{
    shadow_mem_sanity_check(orig, shadow);

    memcpy((void*)shadow->mem, (void*)orig->mem,
        orig->limit * orig->nmemb);
}

void check_overlap(HeapManager* hmgr, Array* buffer, int i) {
  uintptr_t h1 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &i);

  for (int j = 0; j < hmgr->arr.front; j++) {
    if (i == j)
      continue;
    uintptr_t h2 = (uintptr_t)heap_mgr_get_valid_heap(hmgr, &j);

    if (h1 == 0 || h2 == 0 || h1 == kBadPtr || h2 == kBadPtr)
      continue;

    if ((h1 <= h2 && h2 < h1 + hmgr->usable_size[i])
        || (h2 <= h1 && h1 < h2 + hmgr->usable_size[j])) {
      DEBUG("[BUG] Found overlap");
      DEBUG("p[%d]=%p (size=%ld), "
          "p[%d]=%p (size=%ld)", i, (void*)h1, hmgr->usable_size[i],
          j, (void*)h2, hmgr->usable_size[j]);
      BEGIN_STMT;
      STMT("assert((p[%d] <= p[%d] && p[%d] < p[%d] + %ld)"
              " || (p[%d] <= p[%d] && p[%d] < p[%d] + %ld))",
              i, j, j, i, hmgr->usable_size[i],
              j, i, i, j, hmgr->usable_size[j]);
      END_STMT;
      set_event_type(EVENT_OVERLAP, "OVERLAP");
    }
  }

  if (h1 >= buffer->mem
      && h1 < buffer->mem + buffer->mem_size) {
    DEBUG("[BUG] Found allocation in buffer");
    DEBUG("p[%d]=%p (size=%ld), "
        "buf=%p (size=%d)",
        i,
        (void*)h1, hmgr->usable_size[i],
        (void*)buffer->mem, buffer->mem_size);
    BEGIN_STMT;
    STMT("assert((void*)buf <= p[%d] "
          "&& p[%d] <= (void*)buf + sizeof(buf))", i, i);
    END_STMT;
    set_event_type(EVENT_ALLOC_IN_BUFFER, "ALLOC_IN_BUFFER");
  }

  if (h1 >= hmgr->arr.mem
      && h1 < hmgr->arr.mem + hmgr->arr.mem_size) {
    DEBUG("[BUG] Found allocation in a container");
    DEBUG("p[%d]=%p (size=%ld), "
        "container=%p (size=%d)",
        i,
        (void*)h1, hmgr->usable_size[i],
        (void*)hmgr->arr.mem, hmgr->arr.mem_size);
    BEGIN_STMT;
    STMT("assert((void*)p <= p[%d] "
          "&& p[%d] <= (void*)p + sizeof(p))", i, i);
    END_STMT;
    set_event_type(EVENT_ALLOC_IN_CONTAINER, "ALLOC_IN_CONTAINER");
  }
}

void check_buffer_modify(Array *buffer, bool write) {
  if (shadow_mem_verify(buffer, &buffer_shadow)) {
    intptr_t orig = 0, shadow = 0;
    int index = shadow_mem_diff(buffer, &buffer_shadow, &orig, &shadow);

    DEBUG("[BUG] Found modification in buffer at index %d - %p -> %p",
        index, shadow, orig);
    shadow_mem_make_same(buffer, &buffer_shadow);
    if (write)
      set_event_type(EVENT_ARBITRARY_WRITE_IN_BUFFER, "ARBITRARY_WRITE_IN_BUFFER");
    else
      set_event_type(EVENT_RESTRICTED_WRITE_IN_BUFFER, "RESTRICTED_WRITE_IN_BUFFER");
    END_STMT
  }
}

void check_container_modify(HeapManager* hmgr, bool write) {
  if (shadow_mem_verify(&hmgr->arr, &hmgr_shadow)) {
    intptr_t orig = 0, shadow = 0;
    int index = shadow_mem_diff(&hmgr->arr, &hmgr_shadow, &orig, &shadow);

    DEBUG("[BUG] Found modification in container at index %d - %p -> %p",
        index, shadow, orig);
    shadow_mem_make_same(&hmgr->arr, &hmgr_shadow);
    if (write)
      set_event_type(EVENT_ARBITRARY_WRITE_IN_CONTAINER, "ARBITRARY_WRITE_IN_CONTAINER");
    else
      set_event_type(EVENT_RESTRICTED_WRITE_IN_CONTAINER, "RESTRICTED_WRITE_IN_CONTAINER");
    END_STMT
  }
}

void post_allocate(HeapManager* hmgr, Array* buffer, int index)
{
    // Set shadow memory only if *_dryrun does not set
    if (array_get(&hmgr_shadow, index) == 0)
      array_set(&hmgr_shadow, index, array_get(&hmgr->arr, index));
    check_overlap(hmgr, buffer, index);
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
}

void post_allocate_dryrun(HeapManager* hmgr, Array* buffer, int index)
{
    array_set(&hmgr_shadow, index, array_get(&hmgr->arr, index));
    check_overlap(hmgr, buffer, index);
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
}

void post_heap_write(HeapManager* hmgr, Array* buffer)
{
    check_buffer_modify(buffer, true);
    check_container_modify(hmgr, true);
}

void post_buffer_write(HeapManager* hmgr, Array* buffer, int index, int num)
{
    for (int i = 0; i < num; i++)
      array_set(&buffer_shadow, index + i, array_get(buffer, index + i));
    check_buffer_modify(buffer, true);
    check_container_modify(hmgr, true);
}

void post_double_free(HeapManager* hmgr, Array* buffer)
{
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
}

void post_arbitrary_free(HeapManager* hmgr, Array* buffer)
{
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
}

void post_deallocate(HeapManager* hmgr, Array* buffer, int index)
{
    check_buffer_modify(buffer, false);
    check_container_modify(hmgr, false);
}

