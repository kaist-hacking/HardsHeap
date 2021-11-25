#ifndef __HARDSHEAP_UTILS_H__
#define __HARDSHEAP_UTILS_H__

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define MIN(a,b) \
  ({ __typeof__ (a) _a = (a); \
   __typeof__ (b) _b = (b); \
   _a < _b ? _a : _b; })

#define MAX(a,b) \
  ({ __typeof__ (a) _a = (a); \
   __typeof__ (b) _b = (b); \
   _a > _b ? _a : _b; })


uintptr_t round_up(uintptr_t value, int multiple);
uintptr_t round_up_page_size(uintptr_t size);

void set_event_type(int ety, char* name);
void show_event();
bool has_event();

#endif
