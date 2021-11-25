#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>

#include "logging.h"

int             g_stmt_size = 0;
char            g_stmt_buf[0x1000];

void add_stmt(const char* fmt, ...) {
  va_list ap;

  va_start (ap, fmt);
  int size = vsnprintf(g_stmt_buf + g_stmt_size,
      sizeof(g_stmt_buf) - g_stmt_size,
      fmt, ap);

  if (size < 0) {
    DEBUG("Error occurred when copying a statement");
    exit(-1);
  }
  g_stmt_size += size;
  va_end(ap);
}

void clear_stmt() {
  g_stmt_size = 0;
  g_stmt_buf[0] = 0;
}

void flush_stmt() {
  if (g_stmt_size != 0) {
    g_stmt_buf[g_stmt_size] = 0;
    if (g_stmt_buf[g_stmt_size - 1] == '\n')
      fprintf(stderr, "%s", g_stmt_buf);
    else
      fprintf(stderr, "%s;\n", g_stmt_buf);
    clear_stmt();
  }
}
