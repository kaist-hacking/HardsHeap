#ifndef __HARDSHEAP_COMMON_UTILS_H__
#define __HARDSHEAP_COMMON_UTILS_H__

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * Split a space-separated string into argv.
 * WARNING: args will be modified
 *
 * @param args a string argument.
 * @param argv a string vector
 * @param size size of argv
 * 
 * @return the number of argv
 */

void* random_mmap(size_t size);
int string_to_argv(char* args, char* argv0, char** argv, int size);

#ifdef __cplusplus
}
#endif

#endif // __HARDSHEAP_COMMON_UTILS_H__
