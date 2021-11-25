#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "stream.h"

void stream_init(Stream* strm, void* buf, size_t size) {
    strm->buf = buf;
    strm->size = size;
    strm->index = 0;
}

void stream_check_index(Stream* strm, int req) {
  if (strm->index + req > strm->size) {
    // Reach to the end of the buffer
    exit(0);
  }
}

void stream_clear(Stream* strm) {
  strm->index = 0;
  memset(strm->buf, 0, strm->size);
}

void stream_read(Stream* strm, void* buf, size_t size) {
  stream_check_index(strm, size);
  memcpy(buf, strm->buf + strm->index, size);
  strm->index += size;
}

#define DEFINE_STREAM_READ(sz) \
  uint##sz##_t stream_read_##sz(Stream* strm) { \
  uint##sz##_t ch; \
  stream_read(strm, &ch, sizeof(ch)); \
  return ch; \
}

DEFINE_STREAM_READ(8);
DEFINE_STREAM_READ(16);
DEFINE_STREAM_READ(32);
DEFINE_STREAM_READ(64);
DEFINE_STREAM_READ(ptr);

#undef DEFINE_STREAM_READ

void stream_write(Stream* strm, void* buf, size_t size) {
  stream_check_index(strm, size);
  memcpy(strm->buf + strm->index, buf, size);
  strm->index += size;
}

#define DEFINE_STREAM_WRITE(sz) \
  uint##sz##_t stream_write_##sz(Stream* strm, uint##sz##_t ch) { \
  stream_write(strm, &ch, sizeof(ch)); \
  return ch; \
}

DEFINE_STREAM_WRITE(8);
DEFINE_STREAM_WRITE(16);
DEFINE_STREAM_WRITE(32);
DEFINE_STREAM_WRITE(64);
DEFINE_STREAM_WRITE(ptr);

#undef DEFINE_STREAM_WRITE

void stream_rewind_8(Stream* strm) {
  assert(strm->size >= 1);
  strm->index -= 1;
  *(uint8_t*)(strm->buf + strm->index) *= 31;
  *(uint8_t*)(strm->buf + strm->index) += 99;
  return;
}
