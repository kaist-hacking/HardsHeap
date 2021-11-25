#ifndef __HARDSHEAP_API_H__
#define __HARDSHEAP_API_H__

#if defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
# define WEAK_ATTRIBUTE __attribute__((weak))
#else
# define UNUSED(x) x
# define WEAK_ATTRIBUTE
#endif

void initialize();
void finalize();
void analyze_single();
double calculate_prob();

#endif // __HARDSHEAP_API_H__
