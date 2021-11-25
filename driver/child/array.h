#ifndef __HARDSHEAP_ARRAY_H__
#define __HARDSHEAP_ARRAY_H__

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uintptr_t mem;
    uintptr_t mem_real;
    int front;
    int limit;
    int mem_size;
    int mem_size_real;
    int nmemb;
} Array;


void array_init(Array* arr, int limit, int nmemb);
uintptr_t array_get(Array* arr, int index);
void array_set(Array* arr, int index, uintptr_t elem);
void array_push(Array* arr, uintptr_t elem);
bool array_is_empty(Array* arr);

#endif // __HARDSHEAP_ARRAY_H__