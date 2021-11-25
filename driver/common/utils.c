#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "utils.h"

int string_to_argv(char* args, char* argv0, char** argv, int size)
{
    int argc = 0;
    assert(size >= 2);
    argv[argc++] = argv0;

    if (args == NULL) {
        argv[argc] = NULL;
        return argc;
    }

    char* ptr = strchr(args, ' ');
    argv[argc++] = args;
    while (ptr != NULL) {
        *ptr = '\0';
        ptr += 1;
        argv[argc++] = ptr;
        ptr = strchr(ptr, ' ');
        assert(size >= argc);
    }

    argv[argc] = NULL;
    return argc;
}

void* random_mmap(size_t size)
{
    // Randomly allocate maps to prevent interactions between them
    while (true) {
        uintptr_t base = rand() & (~0xfff);
        void* addr = mmap((void*)base, size,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);

        if (addr != MAP_FAILED)
            return addr;
    }
}

