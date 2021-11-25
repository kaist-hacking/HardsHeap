#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <time.h>

#include "shared_memory.h"
#include "logging.h"
#include "utils.h"

static int get_shm_id()
{
    const char* id_str = getenv("HARDSHEAP_SHM_ID");
    if (id_str)
        return atoi(id_str);
    else
        return -1;
}

static int try_shmget() {
  srand(time(NULL)); // For deterministic
  while (true) {
    key_t key = rand();
    int shm_id = shmget(key, SHARED_MEMORY_SIZE, IPC_CREAT | IPC_EXCL | 0666);
    if (shm_id == -1) {
      if (errno != EEXIST) {
        perror("shmget");
        exit(EXIT_FAILURE);
      }
      // Retry using other key
      continue;
    }

    char str[0x100];
    snprintf(str, sizeof(str), "%d", shm_id);
    setenv("HARDSHEAP_SHM_ID", str, 1);
    DEBUG(DBG_INFO "New shared memory id: %d", shm_id);
    return shm_id;
  }
}

static bool shm_init(SharedMemory* shm, int shm_id)
{
    if (shm_id == -1) {
        fprintf(stderr, "Invalid shm_id\n");
	exit(EXIT_FAILURE);
        return false;
    }

    void* addr = shmat(shm_id, NULL, 0);
    if (addr == (void*) -1) {
        FATAL("Failed to attach to shared memory");
        return false;
    }

    shm->shm_id = shm_id;
    shm->ptr = addr;
    shm->length = SHARED_MEMORY_SIZE;
    return true;
}

bool shm_alloc(SharedMemory* shm) {
  int shm_id = try_shmget();
  return shm_init(shm, shm_id);
}

bool shm_attach(SharedMemory* shm) {
  int shm_id = get_shm_id();
  if (shm_id != -1) {
    return shm_init(shm, shm_id);
  }
  else {
    shm->shm_id = -1;
    shm->ptr = random_mmap((int)SHARED_MEMORY_SIZE);
    shm->length = SHARED_MEMORY_SIZE;
    return false;
  }
}

void shm_fini(SharedMemory* shm)
{
  if (shm->shm_id != -1) {
    shmctl(shm->shm_id, IPC_RMID, NULL);
    shm->shm_id = -1;
  }
}
