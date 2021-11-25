#include <assert.h>

#include <dlfcn.h>
#include <malloc.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "child/api.h"
#include "child/heap_manager.h"
#include "child/utils.h"
#include "common/config.h"
#include "common/logging.h"
#include "common/shared_memory.h"
#include "common/stream.h"
#include "common/utils.h"

typedef enum {
  VULN_OVERFLOW,
  VULN_OFF_BY_ONE_NULL,
  VULN_OFF_BY_ONE,
  VULN_WRITE_AFTER_FREE,
  VULN_DOUBLE_FREE,
  VULN_ARBITRARY_FREE,
  VULN_LAST
} VulnType;

typedef enum {
  CAP_HEAP_ADDR,
  CAP_CONTAINER_ADDR,
  CAP_BUFFER_ADDR,
  CAP_DEALLOC,
  CAP_HEAP_WRITE,
  CAP_BUFFER_WRITE,
  CAP_VULN,
  CAP_LAST,
} CapabilityType;

typedef struct {
  char* name;
  int type;
  bool enable;
} Option;

typedef struct {
  int header;
  int footer;
  int round;
  int minsz;
} AllocatorInfo;

// Global variables
Stream         g_strm;
HeapManager     g_hmgr;
Array           g_buffer;
uintptr_t       g_lower_bound = 0;
uintptr_t       g_upper_bound = 0;
Stream         g_actions;
int             g_skipped = 0;
// Info: header, footer, round, minsz
AllocatorInfo  g_allocator_info = {-1, -1, -1, -1};
SharedMemory   g_shm;
Stream         g_shm_strm;


// NOTE: MAX_NUM_SIZES should be <= 65535
#define MAX_NUM_SIZES 0x1000
uintptr_t       g_sizes[MAX_NUM_SIZES];
uintptr_t       g_num_sizes;

#define MAX_NUM_TXN 0x1000
uintptr_t       g_txns[MAX_NUM_TXN];
uintptr_t       g_num_txn;
uintptr_t       g_idx_txn;

#define TXN_ID_ALLOCATE 0
#define TXN_ID_DEALLOCATE 1
#define TXN_ID_VULN 2

char* module_args = NULL;

Option  g_capabilities[] = {
  {"HEAP_ADDR", CAP_HEAP_ADDR, true},
  {"CONTAINER_ADDR", CAP_CONTAINER_ADDR, true},
  {"BUFFER_ADDR", CAP_BUFFER_ADDR, true},
  {"DEALLOC", CAP_DEALLOC, true},
  {"HEAP_WRITE", CAP_HEAP_WRITE, true},
  {"BUFFER_WRITE", CAP_BUFFER_WRITE, true},
  {"VULN", CAP_VULN, true}
};

Option g_vulns[] = {
  {"OVERFLOW", VULN_OVERFLOW, true},
  {"OFF_BY_ONE_NULL", VULN_OFF_BY_ONE_NULL, true},
  {"OFF_BY_ONE", VULN_OFF_BY_ONE, true},
  {"WRITE_AFTER_FREE", VULN_WRITE_AFTER_FREE, true},
  {"DOUBLE_FREE", VULN_DOUBLE_FREE, true},
  {"ARBITRARY_FREE", VULN_ARBITRARY_FREE, true}
};

uintptr_t interesting_values[] = {
  -1,
  -sizeof(void*),
  0,
  sizeof(void*),
};

// APIs
void done() {
    fprintf(stderr, "}\n");

    fprintf(stderr, "// The number of actions: %d\n", g_actions.index - g_skipped);
    // XXX: SIGUSR2 is used for parent <-> afl interaction, so it should be changed.
    finalize(&g_hmgr);
    show_event();
    shm_fini(&g_shm);
    _exit(0);
}

void stream_init_child(Stream* strm, const char* filename, int limit) {
  // Special version of stream_init() for child
  char* buf = (char*)random_mmap(limit);
  size_t size = limit;

  if (filename != NULL) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "[-] Cannot open a file: %s\n", filename);
      exit(EXIT_FAILURE);
    }
    size = read(fd, buf, limit);
    close(fd);
  }

  assert(size != -1);
  stream_init(strm, buf, size);
}

intptr_t stream_read_offset(Stream* strm) {
  return stream_read_8(strm) % 9 - 4;
}

uintptr_t stream_read_range(Stream* strm, int beg, int end) {
  return stream_read_32(strm) % (end - beg) + beg;
}

// XXX: Don't like name..
bool do_action() {
  if (stream_read_8(&g_actions) == 0) {
    return true;
  }
  else {
    g_skipped++;
    // Remove the statement for this operation
    CLEAR_STMT;
    return false;
  }
}

bool do_action_heap(void* h) {
  if (do_action() && (uintptr_t)h != kBadPtr)
    return true;
  else {
    CLEAR_STMT;
    return false;
  }
}

uintptr_t fuzz_unaligned_size(Stream* strm) {
  // Return aligned size
  int beg = 0, end = 0;

  if (g_num_sizes != 0) {
    // If -s option is given, then use size from the input
    return g_sizes[stream_read_16(strm) % g_num_sizes];
  }

  switch (stream_read_8(strm) % 7)  {
    case 0 ... 1:
      beg = (1 << 0);
      end = 1 << 5;
      break;

    case 2 ... 3:
      beg = (1 << 5);
      end = (1 << 10);
      break;

    case 4:
      beg = (1 << 10);
      end = (1 << 15);
      break;

    case 5:
      beg = (1 << 15);
      end = 1 << 20;
      break;

    case 6:
      beg = (1 << 20);
      end = 1 << 25;
      break;

    default:
      assert(false);
  }
  return stream_read_range(strm, beg, end);
}

uintptr_t fuzz_aligned_size(Stream* strm) {
  return round_up(fuzz_unaligned_size(strm), 8);
}

uintptr_t fuzz_size(HeapManager* hmgr, Stream* strm) {
  int index = stream_read_16(strm);
  if (heap_mgr_get_heap(hmgr, &index) == NULL) {
    // If there is no size.. return random size
    return fuzz_aligned_size(strm);
  }
  else {
    if (stream_read_8(strm) & 1) {
      // Return usable size
      return hmgr->usable_size[index];
    }
    else {
      // Chunk size would be the usable_size + overhead
      int overhead = 0;
      if (g_allocator_info.header != -1)
        overhead = g_allocator_info.header + g_allocator_info.footer;
      else {
        // We don't have information about overhead.
        // Let's use random value (but we believe it is address-aligned).
        overhead = (stream_read_8(strm) % 4) * sizeof(void*);
      }
      return hmgr->usable_size[index] + overhead;
    }
  }
}

uintptr_t get_txn(uintptr_t orig) {
  // No transaction has been specified
  if (g_num_txn == 0)
    return orig;

  // Consumed all transactions
  if (g_num_txn == g_idx_txn)
    done();

  return g_txns[g_idx_txn++];
}

uintptr_t fuzz_transform_linear(Stream* strm, uintptr_t size) {
  int a = 1, b = 0;
  switch (stream_read_8(strm) % 5) {
    case 0 ... 1:
      a = 1;
      b = stream_read_offset(strm) * sizeof(void*);
      break;

    case 2 ... 3:
      a = stream_read_8(strm) % 3 + 1;
      b = 0;
      break;

    case 4:
      a = stream_read_8(strm) % 3 + 1;
      b = stream_read_offset(strm) * sizeof(void*);
      break;

    default:
      assert(false);
  }

  return a * size + b + (stream_read_8(strm) & 7);
}

uintptr_t fuzz_int(HeapManager* hmgr, Array* buffer, Stream* strm) {
  uintptr_t value = 0;
  int op;

retry:
  op = stream_read_8(strm);

  switch (op % 13) {
    case 0: {
      // Interesting values
      value = interesting_values[stream_read_8(strm)
        % (sizeof(interesting_values) / sizeof(intptr_t))];
      break;
    }

    case 1: {
      // Offset of the buffer and a chunk
      if (!g_capabilities[CAP_HEAP_ADDR].enable
          || !g_capabilities[CAP_BUFFER_ADDR].enable) {
        stream_rewind_8(&g_strm);
        goto retry;
      }
      int index_h = stream_read_16(strm);
      void* h = heap_mgr_get_heap(hmgr, &index_h);
      if (h == NULL)
        goto retry;

      int index_b = stream_read_16(strm) % buffer->limit;
      if (h == NULL)
        goto retry;
      uintptr_t buffer_heap_off
          = buffer->mem + index_b * sizeof(void*)
          - (uintptr_t)h;
      int sign = stream_read_8(strm) & 1 ? -1 : 1;
      int off = stream_read_offset(strm) * sizeof(void*);
      if (sign == 1) {
        STMT("(uintptr_t)&buf[%d] - (uintptr_t)p[%d] + %d",
          index_b, index_h, off);
      }
      else {
        STMT("(uintptr_t)p[%d] - (uintptr_t)&buf[%d] + %d",
          index_h, index_b, off);
      }
      return sign * buffer_heap_off + off;
    }

    case 2: {
      // Offset of the container and a chunk
      if (!g_capabilities[CAP_HEAP_ADDR].enable
          || !g_capabilities[CAP_CONTAINER_ADDR].enable) {
        stream_rewind_8(&g_strm);
        goto retry;
      }
      int index_h = stream_read_16(strm);
      void* h = heap_mgr_get_heap(hmgr, &index_h);
      if (h == NULL)
        goto retry;

      int size = hmgr->arr.front == 0 ? hmgr->limit : hmgr->arr.front;
      int index_c = stream_read_16(strm) % size;

      uintptr_t container_heap_off
        = hmgr->arr.mem + index_c * sizeof(void*)
        - (uintptr_t)h;
      int sign = stream_read_8(strm) & 1 ? -1 : 1;
      int off = stream_read_offset(strm) * sizeof(void*);
      if (sign == 1) {
        STMT("(uintptr_t)&p[%d] - (uintptr_t)p[%d] + %d",
            index_c, index_h, off);
      }
      else {
        STMT("(uintptr_t)p[%d] - (uintptr_t)&p[%d] + %d",
            index_h, index_c, off);
      }
      return sign * container_heap_off + off;
    }

    case 3: {
      // Aligned random size
      value = fuzz_aligned_size(strm);
      break;
    }

    case 4: {
      // Unaligned random size
      value = fuzz_unaligned_size(strm);
      break;
    }

    case 5 ... 8: {
      // Fuzzy size
      value = fuzz_size(hmgr, strm);
      break;
    }

    case 9 ... 12: {
      // Fuzzy size + Linear transformation
      value = fuzz_transform_linear(strm, fuzz_size(hmgr, strm));
      break;
    }

    default:
      assert(false);
  }

  STMT("%ld", value);
  return value;
}

uintptr_t fuzz_ptr(HeapManager* hmgr, Array* buffer, Stream* strm) {
  uintptr_t value = 0;
  int op;

retry:
  op = stream_read_8(strm);

  switch (op % 4) {
    case 0: {
      break;
    }

    case 1: {
      // Heap address
      if (!g_capabilities[CAP_HEAP_ADDR].enable) {
        stream_rewind_8(&g_strm);
        goto retry;
      }
      int index = stream_read_16(strm);
      void* h = heap_mgr_get_heap(hmgr, &index);
      if (h == NULL)
        break;
      int off = stream_read_offset(strm) * sizeof(void*);
      STMT("(uintptr_t)p[%d] + %d", index, off);
      return (uintptr_t)h + off;
    }

    case 2: {
      // Buffer address
      if (!g_capabilities[CAP_BUFFER_ADDR].enable) {
        stream_rewind_8(&g_strm);
        goto retry;
      }
      int index = stream_read_16(strm) % buffer->limit;
      STMT("(uintptr_t)&buf[%d]", index);
      return (uintptr_t)buffer->mem + index * sizeof(uintptr_t);
    }

    case 3: {
      // Container address
      if (!g_capabilities[CAP_CONTAINER_ADDR].enable) {
        stream_rewind_8(&g_strm);
        goto retry;
      }
      int size = hmgr->arr.front == 0 ? hmgr->limit : hmgr->arr.front;
      int index = stream_read_16(strm) % size;
      uintptr_t h = hmgr->arr.mem;
      int off = stream_read_offset(strm) * sizeof(void*);
      STMT("(uintptr_t)&p[%d] + %d", index, off);
      return h + index * sizeof(uintptr_t) + off;
    }

    default:
      assert(false);
  }

  // NULL
  STMT("%ld", value);
  return value;
}


// XXX: bad naming
uintptr_t fuzz_aligned_to_unaligned_lower(Stream* strm, uintptr_t size) {
  switch (stream_read_8(strm) % 3) {
    case 0:
      return size;
    case 1:
      return size | 1;
    case 2:
      return size | (stream_read_8(strm) & 7);
    default:
      assert(false);
  }
}

int heap_mgr_allocate(HeapManager* hmgr, Array* buffer, size_t size) {
  // Returns -1 if it does not actually allocate

  void* ptr = NULL;
  bool valid;

  if (do_action()) {
    ptr = malloc(size);
    valid = true;
    END_STMT;
  }
  else {
    ptr = (void*)kBadPtr;
    valid = false;
    CLEAR_STMT;
  }

  array_push(&hmgr->arr, (uintptr_t)ptr);

  int index = hmgr->arr.front - 1;
  hmgr->valid[index] = valid;

  if (g_allocator_info.header != -1) {
    int overhead = g_allocator_info.header + g_allocator_info.footer;
    hmgr->usable_size[index] = MAX(g_allocator_info.minsz,
        round_up(size + overhead, g_allocator_info.round)) - overhead;
  }
  else if (valid) {
    hmgr->usable_size[index] = size;

    // Since malloc_usable_size() can be failed due to an invalid chunk,
    // e.g., tcmalloc, we check techniques before calling malloc_usable_size()
    post_allocate_dryrun(hmgr, buffer, index);

    hmgr->usable_size[index] = malloc_usable_size(ptr);
  }
  // TODO: Remove hmgr->size
  hmgr->size[index] = size;
  post_allocate(hmgr, buffer, index);
  return (ptr == (void*)kBadPtr) ? -1 : index;
}

bool heap_mgr_force_deallocate(HeapManager* hmgr, int* index) {
  if (hmgr->arr.front == 0)
    return false;

  *index %= hmgr->arr.front;
  void* ptr = (void*)array_get(&hmgr->arr, *index);
  hmgr->freed[*index] = true;

  if (do_action_heap(ptr)) {
    free(ptr);
    return true;
  }
  else
    return false;
}

bool heap_mgr_deallocate(HeapManager* hmgr, int* index) {
  if (hmgr->arr.front == 0)
    return false;

  *index %= hmgr->arr.front;
  if (hmgr->freed[*index])
    return false;

  return heap_mgr_force_deallocate(hmgr, index);
}

uintptr_t fuzz_value(HeapManager* hmgr, Array* buffer, Stream* strm) {
  int op = stream_read_8(strm);

  switch (op % 2) {
    case 0:
      return fuzz_int(hmgr, buffer, strm);
    case 1:
      return fuzz_ptr(hmgr, buffer, strm);
    default:
      assert(false);
  }
}

void fuzz_allocate(HeapManager* hmgr, Array* buffer, Stream* strm) {
retry:
  BEGIN_STMT;
  STMT("p[%d] = malloc(", hmgr->arr.front);

  uintptr_t size = 0;
  if (g_num_sizes != 0) {
    // If -s option is given, then use size from the input
    size = g_sizes[stream_read_16(strm) % g_num_sizes];
    STMT("%ld", size);
  }
  else
    size = fuzz_int(hmgr, buffer, strm);

  if ((g_lower_bound != 0 && g_lower_bound > size) ||
      (g_upper_bound != 0 && size > g_upper_bound)) {
    CLEAR_STMT;
    goto retry;
  }
  STMT(")");

  heap_mgr_allocate(hmgr, buffer, size);
}

void fuzz_deallocate(HeapManager* hmgr, Array* buffer, Stream* strm) {
  // Do nothing if less than one memory is allocated
  int index = stream_read_16(strm);

  pre_deallocate(hmgr, buffer, index);
  if (heap_mgr_deallocate(hmgr, &index)) {
    BEGIN_STMT;
    STMT("free(p[%d])", index);
    END_STMT;

    post_deallocate(hmgr, buffer, index);
  }
}

void fuzz_heap_write(HeapManager* hmgr, Array* buffer, Stream* strm) {
  int index = stream_read_16(strm);
  void* h = heap_mgr_get_valid_heap(hmgr, &index);
  // Not a valid heap
  if (h == NULL)
    return;

  int num_slots = hmgr->usable_size[index] / sizeof(uintptr_t);
  if (num_slots == 0)
    return;

  bool higher = stream_read_8(strm) & 1;
  int beg = 0, end = 0;

  if (higher) {
    beg = 0;
    end = stream_read_8(strm) % MIN(num_slots, 8) + 1;
  }
  else {
    beg = num_slots - (stream_read_8(strm) % MIN(num_slots, 8) + 1);
    end = num_slots;
  }

  assert(beg >= 0 && end <= num_slots);

  for (int i = beg; i < end; i++) {
    BEGIN_STMT;
    STMT("((uintptr_t*)p[%d])[%d] = ", index, i);
    uintptr_t value = fuzz_value(hmgr, buffer, strm);

    if (do_action_heap(h))
      *((uintptr_t*)h + i) = value;
    END_STMT;
  }

  post_heap_write(hmgr, buffer);
}

void fuzz_buffer_write(HeapManager *hmgr,
    Array* buffer, Stream* strm) {
  int index = stream_read_16(strm) % buffer->limit;
  int remainder = buffer->limit - index;
  int num = stream_read_8(strm) % MIN(8, remainder) + 1;

  for (int i = 0; i < num; i++) {
    BEGIN_STMT;
    STMT("buf[%d] = ", index + i);
    uintptr_t value = fuzz_value(hmgr, buffer, strm);
    if (do_action())
      array_set(buffer, index + i, value);
    END_STMT;
  }

  post_buffer_write(hmgr, buffer, index, num);
}

VulnType get_random_vuln_type(Stream* strm) {
  while (true) {
    VulnType vuln = stream_read_8(strm) % VULN_LAST;
    if (g_vulns[vuln].enable)
      return vuln;
  }
}

void fuzz_vuln(HeapManager* hmgr,
    Array* buffer, Stream* strm) {
  static VulnType prev_vuln = VULN_LAST;
  VulnType vuln = get_random_vuln_type(strm);
  vuln = get_txn(vuln);

  // Do not allow two types of vulnerability
  if (prev_vuln != VULN_LAST
      && vuln != prev_vuln)
    return;

  switch (vuln) {
    case VULN_OVERFLOW: {
      int index = stream_read_16(strm);
      void* h = heap_mgr_get_valid_heap(hmgr, &index);
      if (h == NULL)
        return;

      int num = stream_read_8(strm) % 8 + 1;

      bool first = true;
      for (int i = 0; i < num; i ++) {
        if (first) DEBUG("[VULN] Overflow");
        BEGIN_STMT;
        // NOTE: We overflow from usable_size[index] - sizeof(void*).
        // This is sensitive to ptmalloc that contains metadata at the last
        // int off = hmgr->usable_size[index] + (i - 1) * sizeof(void*);
        int off = hmgr->usable_size[index] + i * sizeof(void*);
        STMT("*(uintptr_t*)(p[%d] + %d) = ", index, off);
        uintptr_t value = fuzz_value(hmgr, buffer, strm);
        if (do_action_heap(h)) {
          if (first) first = false;
          *(uintptr_t*)((uintptr_t)h + off) = value;
        }
        END_STMT;
      }
    }
    break;

    case VULN_OFF_BY_ONE: {
      int index = stream_read_16(strm);
      void* h = heap_mgr_get_valid_heap(hmgr, &index);
      if (h == NULL)
        return;

      if (do_action_heap(h)) {
        uint8_t value = stream_read_8(strm);
        uint8_t old = *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]);

        DEBUG("[VULN] Off-by-one");
        DEBUG("old = %d, new=%d", old, value);

        BEGIN_STMT;
        STMT("*(char*)(p[%d] + %ld) = %d", index, hmgr->usable_size[index], value);
        *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]) = value;
        END_STMT;
      }
    }
    break;

    case VULN_OFF_BY_ONE_NULL: {
      int index = stream_read_16(strm);
      void* h = heap_mgr_get_valid_heap(hmgr, &index);
      if (h == NULL)
        return;

      if (do_action_heap(h)) {
        uint8_t old = *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]);
        DEBUG("[VULN] Off-by-one NULL");
        DEBUG("old = %d", old);

        BEGIN_STMT;
        STMT("*(char*)(p[%d] + %ld) = 0", index, hmgr->usable_size[index]);

        *(uint8_t*)((uintptr_t)h + hmgr->usable_size[index]) = 0;

        END_STMT;
      }
    }
    break;

    case VULN_WRITE_AFTER_FREE: {
      // XXX: Merge with fill heap
      int index = stream_read_16(strm);
      void* h = heap_mgr_get_freed_heap(hmgr, &index);
      // Not a valid heap
      if (h == NULL)
        return;

      int num_slots = hmgr->usable_size[index] / sizeof(uintptr_t);
      if (num_slots == 0)
        return;

      bool higher = stream_read_8(strm) & 1;
      int beg = 0, end = 0;

      if (higher) {
        beg = 0;
        end = stream_read_8(strm) % MIN(num_slots, 8) + 1;
      }
      else {
        beg = num_slots - (stream_read_8(strm) % MIN(num_slots, 8) + 1);
        end = num_slots;
      }

      assert(beg >= 0 && end <= num_slots);

      bool first = true;
      for (int i = beg; i < end; i++) {
        if (first) DEBUG("[VULN] Write-after-free");
        BEGIN_STMT;
        STMT("((uintptr_t*)p[%d])[%d] = ", index, i);
        uintptr_t value = fuzz_value(hmgr, buffer, strm);
        if (do_action_heap(h)) {
          if (first) first = false;
          *((uintptr_t*)h + i) = value;
        }
        END_STMT;
      }
    }
    break;

    case VULN_DOUBLE_FREE: {
      int index = stream_read_16(strm);
      void* h = heap_mgr_get_freed_heap(hmgr, &index);
      if (h == NULL)
        return;

      for (int i = 0 ; i < hmgr->limit; i++) {
        int other_index = i;
        void* other_h = heap_mgr_get_valid_heap(hmgr, &other_index);
        if (other_h == h && (uintptr_t)h != kBadPtr) {
          DEBUG(DBG_INFO "This is not really freed memory");
          return;
        }
      }

      if (do_action()) {
        DEBUG("[VULN] Double free");
        if (heap_mgr_force_deallocate(hmgr, &index)) {
          BEGIN_STMT;
          STMT("free(p[%d])", index);
          END_STMT;

          post_double_free(hmgr, buffer);
        }
      }
    }
    break;

    case VULN_ARBITRARY_FREE: {
      int index = stream_read_16(strm) % buffer->limit;

      if (do_action()) {
        DEBUG("[VULN] Arbitrary free");

        BEGIN_STMT;
        STMT("free(&buf[%d])", index);
        END_STMT;

        free((void*)(buffer->mem + index * sizeof(uintptr_t)));

        post_arbitrary_free(hmgr, buffer);
      }
    }
    break;

    default:
      assert(false);
  }

  prev_vuln = vuln;
}

void initialize_random() {
    int fd = open("/dev/urandom", O_RDONLY);
    assert(fd != -1);
    int seed = 0;
    assert(read(fd, &seed, sizeof(seed)) == sizeof(seed));
    close(fd);

    srand(seed);
}

void print_options(char* name, Option* options, int num_elem) {
  bool first = true;
  fprintf(stderr, "     <%s>:= ", name);
  for (int i = 0; i < num_elem; i++) {
    if (first)
      first = false;
    else
      fprintf(stderr, " | ");
    fprintf(stderr, "%s", options[i].name);
  }
  fprintf(stderr, "\n");
}

void set_option(char* name, Option* options, int num_elem) {
  for (int i = 0; i < num_elem; i++) {
    if (!strcmp(optarg, options[i].name)) {
      options[i].enable = false;
      fprintf(stderr, "// Disable %s: %s\n", name, optarg);
      return;
    }
  }

  fprintf(stderr, "// [ERROR] No such %s: %s\n", name, optarg);
  exit(-1);
}

void set_allocator_information() {
  // Make optarg writable
  char buf[strlen(optarg) + 1], *saveptr = buf;
  strncpy(buf, optarg, sizeof(buf));

  // TODO: Better way to parse AllocatorInfo
  assert(sizeof(AllocatorInfo) == 4 * sizeof(int));
  int* ptr = (int*)&g_allocator_info;
  for (int i = 0; i < 4; i++) {
    char* p = strtok_r(saveptr, ":", &saveptr);
    if (p == NULL) {
      fprintf(stderr, "// [ERROR] Invalid format for allocator information\n");
      exit(-1);
    }
    ptr[i] = atoi(p);
  }

  if (g_allocator_info.round == 0) {
    // Round cannot be zero
    fprintf(stderr, "// [ERROR] Round cannot be zero\n");
    exit(-1);
  }

  fprintf(stderr,
      "// [INFO] Allocator information: header=%d, footer=%d, round=%d, minsz=%d\n",
      g_allocator_info.header,
      g_allocator_info.footer,
      g_allocator_info.round,
      g_allocator_info.minsz);
}

void usage(char* filename) {
  fprintf(stderr,
  "Usage: %s [OPTION]... FILE [MAPFILE]\n"
  "  -c <cap>: Disable a capability\n", filename);
  print_options("cap", g_capabilities, CAP_LAST);

  fprintf(stderr,
  "  -v <vuln>: Disable a vulnerbility\n");
  print_options("vuln", g_vulns, VULN_LAST);

  fprintf(stderr,
  "  -u <ub>: Set upper bound of allocation\n"
  "  -l <lb>: Set lower bound of allocation\n"
  "  -s <list-of-sizes>: Set allocations sizes (e.g., 1,2,3)\n"
  "  -a <header>:<footer>:<round>:<minsz>: Set information for allocator\n"
#if 0
  // Make this option hidden, which is only used for evaluation
  "  -A <list-of-transactions>: Set a sequence of transactions\n"
  "     Possible Transactions - "
  "        M: alloc, F: free\n"
  "        OV: overflow, O1: off-by-one, O1N: off-by-one NULL\n"
  "        FF: double free, AF: arbitrary free, WF: write-after-free\n"
  "        (e.g., M-M-OV-F-M)\n"
#endif
  "    e.g. For ptmalloc in 64-bit, -a 8:0:16:32\n"
  "  -m <module_args>: Set an argument string for a specific module\n");
  module_usage();
  fprintf(stderr, "  -h: Display this help and exit\n");
}

void make_arguments(int argc, char** argv, int* new_argc, char* new_argv[])
{
    // Append 'additional_argv' to the existing 'argv'
    int additional_argc = 0;
    while (additional_argv[additional_argc] != NULL)
        additional_argc++;

    *new_argc = argc + additional_argc;
    assert(*new_argc < MAX_ARGC);
    new_argv[0] = argv[0];
    memcpy(new_argv + 1, additional_argv, sizeof(char*) * additional_argc);
    memcpy(new_argv + additional_argc + 1, argv + 1, sizeof(char*) * (argc - 1));
    new_argv[*new_argc] = NULL;
}

void initialize_module(int argc, char** argv) {
  // save and restore optind to use getopt() in initialize()
  int old_optind = optind;
  optind = 1;

  initialize(argc, argv);

  optind = old_optind;
}

int main(int argc, char** argv) {
  char* new_argv[MAX_ARGC + 1] = {0};
  int new_argc = 0;
  make_arguments(argc, argv, &new_argc, new_argv);

  int c;
  while ((c = getopt(new_argc, new_argv, "A:s:c:v:u:l:a:m:zh")) != -1) {
    switch (c) {
      case 'c':
        set_option("capability", g_capabilities, CAP_LAST);
        break;
      case 'v':
        set_option("vuln", g_vulns, VULN_LAST);
        break;
      case 'u':
        g_upper_bound = strtoul(optarg, NULL, 10);
        if (g_upper_bound)
          fprintf(stderr, "// [INFO] Set upper bound: %ld\n", g_upper_bound);
        break;
      case 'l':
        g_lower_bound = strtoul(optarg, NULL, 10);
        if (g_lower_bound)
          fprintf(stderr, "// [INFO] Set lower bound: %ld\n", g_lower_bound);
        break;
      case 's': {
        char *ptr = strtok(optarg, ",");
        while (ptr != NULL) {
          int size = atoi(ptr);
          if (size <= 0) {
            fprintf(stderr, "[FATAL] Invalid size in -s option\n");
            exit(-1);
          }

          if (g_num_sizes >= MAX_NUM_SIZES) {
            fprintf(stderr, "[FATAL] Too many sizes in -s option\n");
            exit(-1);
          }

          g_sizes[g_num_sizes++] = size;
          ptr = strtok(NULL, ",");

        }

        fprintf(stderr, "[INFO] Sizes: {");
        bool first = true;

        for (uintptr_t i = 0; i < g_num_sizes; i++) {
          if (!first)
            fprintf(stderr, ", ");
          if (first)
            first = false;

          fprintf(stderr, "%ld", g_sizes[i]);
        }
        fprintf(stderr, "}\n");

        break;
      }

      case 'm': {
        module_args = optarg;
        break;
      }

      case 'A': {
        // TODO: 'A' option should be mutually exclusive with 'c' and 'v'
        char * ptr = strtok(optarg, "-");
        while (ptr != NULL) {
          if (!strcmp(ptr, "M")) {
            g_txns[g_num_txn++] = TXN_ID_ALLOCATE;
          }
          else if (!strcmp(ptr, "F")) {
            g_txns[g_num_txn++] = TXN_ID_DEALLOCATE;
          }
          else if (!strcmp(ptr, "OV")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_OVERFLOW;
          }
          else if (!strcmp(ptr, "O1")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_OFF_BY_ONE;
          }
          else if (!strcmp(ptr, "O1N")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_OFF_BY_ONE_NULL;
          }
          else if (!strcmp(ptr, "AF")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_ARBITRARY_FREE;
          }
          else if (!strcmp(ptr, "FF")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_DOUBLE_FREE;
          }
          else if (!strcmp(ptr, "WF")) {
            g_txns[g_num_txn++] = TXN_ID_VULN;
            g_txns[g_num_txn++] = VULN_WRITE_AFTER_FREE;
          }
          else {
            fprintf(stderr, "[FATAL] Unknown transaction: %s", ptr);
            exit(-1);
          }
          ptr = strtok(NULL, "-");
        }

        // TODO: Make more pretty printing
        fprintf(stderr, "// [INFO] List of transactions: ");
        bool first = true;
        for (uintptr_t i = 0; i < g_num_txn; i++) {
          if (!first)
            fprintf(stderr, ", ");
          if (first)
            first = false;

          fprintf(stderr, "%ld", g_txns[i]);
        }
        fprintf(stderr, "\n");
        break;
      }

      case 'a':
        set_allocator_information();
        break;
      case 'h':
      default:
        usage(new_argv[0]);
        exit(-1);
    }
  }

  if (new_argc == optind || new_argc > optind + 2) {
    usage(new_argv[0]);
    exit(-1);
  }

  char* module_argv[MAX_ARGC];
  int module_argc = string_to_argv(module_args, argv[0], module_argv, MAX_ARGC);

  initialize_random();
  shm_attach(&g_shm);
  stream_init(&g_shm_strm, g_shm.ptr, g_shm.length);

  initialize_module(module_argc, module_argv);

#if 0
  // XXX: why we did this?
  struct sigaction sa;
  sa.sa_handler = NULL;
  memset(&sa, 0, sizeof(struct sigaction));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = done;
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGSEGV, &sa, NULL);
#endif

  atexit(done);

  // Use global variables to avoid using heap
  if (new_argc == optind + 1)
    stream_init_child(&g_actions, NULL, 0x1000);
  else
    stream_init_child(&g_actions, new_argv[optind + 1], 0x1000);

  stream_init_child(&g_strm, new_argv[optind], 0x1000);

  heap_mgr_init(&g_hmgr, HEAP_LIMIT);
  array_init(&g_buffer, BUFFER_LIMIT, sizeof(uintptr_t));

  fprintf(stderr,
      "#include <assert.h>\n"
      "#include <stdio.h>\n"
      "#include <stdlib.h>\n"
      "#include <stdint.h>\n"
      "#include <malloc.h>\n\n"
      "void* p[%d];\n"
      "uintptr_t buf[%d];\n\n"
      "int main() {\n", HEAP_LIMIT, BUFFER_LIMIT);

  DEBUG(DBG_INFO "Stream buffer: %p", g_strm.buf);
  DEBUG(DBG_INFO "Input size: %lu", g_strm.size);


  while (true) {
    uint8_t op;
    bool is_txn;

retry:
    op = stream_read_8(&g_strm);

    // Transactions: allocate, deallocate, vuln
    // Non-transactions: heap writes, buffer writes
    switch (op % 5) {
      case 0:
      case 1:
      case 2:
        is_txn = true;
        break;
      case 3:
      case 4:
        is_txn = false;
        break;
    }

    if (is_txn) {
      op = get_txn(op);
      switch (op % 3) {
        case TXN_ID_ALLOCATE:
          fuzz_allocate(&g_hmgr, &g_buffer, &g_strm);
          break;
        case TXN_ID_DEALLOCATE:
          if (!g_capabilities[CAP_DEALLOC].enable) {
            stream_rewind_8(&g_strm);
            goto retry;
          }
          fuzz_deallocate(&g_hmgr, &g_buffer, &g_strm);
          break;
        case TXN_ID_VULN:
          if (!g_capabilities[CAP_VULN].enable) {
            stream_rewind_8(&g_strm);
            goto retry;
          }
          fuzz_vuln(&g_hmgr, &g_buffer, &g_strm);
          break;
        default:
          assert(false);
      }
    }
    else {
      switch (op % 2) {
        case 0:
          if (!g_capabilities[CAP_HEAP_WRITE].enable) {
            stream_rewind_8(&g_strm);
            goto retry;
          }
          fuzz_heap_write(&g_hmgr, &g_buffer, &g_strm);
          break;
        case 1:
          if (!g_capabilities[CAP_BUFFER_WRITE].enable) {
            stream_rewind_8(&g_strm);
            goto retry;
          }
          fuzz_buffer_write(&g_hmgr, &g_buffer, &g_strm);
          break;
        default:
          assert(false);
      }
    }
  }
}
