#include "array.h"
#include "logging.h"
#include "utils.h"
#include "common/utils.h"

void array_init(Array* arr, int limit, int nmemb)
{
    arr->limit = limit;
    arr->front = 0;
    arr->nmemb = nmemb;
    arr->mem_size = round_up_page_size(limit * nmemb);
    // Array memory looks like [UNUSED_AREA | USED_AREA | UNUSED_AREA]
    // This helps to detect out of bounds modification
    arr->mem_size_real = arr->mem_size * 3;
    arr->mem_real = (uintptr_t)random_mmap(arr->mem_size_real);
    arr->mem = (uintptr_t)arr->mem_real + arr->mem_size;
}

uintptr_t array_get(Array* arr, int index) {
  uintptr_t value = 0;
  memcpy(&value, (void*)(arr->mem + index * arr->nmemb), arr->nmemb);
  return value;
}

void array_set(Array* arr, int index, uintptr_t elem) {
  assert(index < arr->limit);

  int off = index * arr->nmemb;
  memcpy((void*)(arr->mem + off), &elem, arr->nmemb);
}

void array_push(Array* arr, uintptr_t elem) {
  if (arr->front == arr->limit)
    FATAL(DBG_INFO "Reach the maximum in Array");

  array_set(arr, arr->front, elem);
  arr->front++;
}

bool array_is_empty(Array* arr) {
  return arr->front == 0;
}
