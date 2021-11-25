#ifndef __HARDSHEAP_STREAM_H__
#define __HARDSHEAP_STREAM_H__

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  size_t size;
  void* buf;
  int index;
} Stream;

void stream_init(Stream* strm, void* buf, size_t size);

void stream_clear(Stream* strm);
void stream_read(Stream* strm, void* buf, size_t size);

#define DECLARE_STREAM_READ(sz) \
  uint##sz##_t stream_read_##sz(Stream* strm);

DECLARE_STREAM_READ(8);
DECLARE_STREAM_READ(16);
DECLARE_STREAM_READ(32);
DECLARE_STREAM_READ(64);
DECLARE_STREAM_READ(ptr);

#undef DECLARE_STREAM_READ

void stream_write(Stream* strm, void* buf, size_t size);

#define DECLARE_STREAM_WRITE(sz) \
  uint##sz##_t stream_write_##sz(Stream* strm, uint##sz##_t ch);

DECLARE_STREAM_WRITE(8);
DECLARE_STREAM_WRITE(16);
DECLARE_STREAM_WRITE(32);
DECLARE_STREAM_WRITE(64);
DECLARE_STREAM_WRITE(ptr);

#undef DECLARE_STREAM_WRITE

void stream_rewind_8(Stream* strm);

#ifdef __cplusplus
}
#endif

#endif // __HARDSHEAP_STREAM_H_
