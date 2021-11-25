#ifndef __HARDHEAP_LOGGING_H__
#define __HARDHEAP_LOGGING_H__

#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define FIRST_ARG(N, ...) N

#define DEBUG(...) do { \
  assert(!strchr(FIRST_ARG(__VA_ARGS__), '\n')); \
  STMT("  // "); \
  STMT(__VA_ARGS__ ); \
  STMT("\n"); \
} while( false );


// API for printing statements
#define BEGIN_STMT \
  add_stmt("  ");

#define STMT(...) do { \
  add_stmt(__VA_ARGS__); \
} while (false);

#define END_STMT \
  flush_stmt();

#define CLEAR_STMT \
  clear_stmt();

#define DBG_VALUE "[VALUE] "
#define DBG_INFO "[INFO] "
#define FATAL(...) do { DEBUG(__VA_ARGS__); exit(EXIT_FAILURE); } while(false);

#ifdef __cplusplus
extern "C" {
#endif

void add_stmt(const char* fmt, ...);
void clear_stmt();
void flush_stmt();

#ifdef __cplusplus
}
#endif

#endif // __HARDHEAP_LOGGING_H__
