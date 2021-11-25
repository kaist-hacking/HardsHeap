#ifndef HARDSHEAP_SHM_H
#define HARDSHEAP_SHM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

typedef struct {
    int shm_id;
    void* ptr;
    int length;
} SharedMemory;

bool shm_alloc(SharedMemory* shm);
bool shm_attach(SharedMemory* shm);
void shm_fini(SharedMemory* shm);

#ifdef __cplusplus
}
#endif

#define SHARED_MEMORY_SIZE 0x1000

#endif /* HARDSHEAP_SHM_H */
