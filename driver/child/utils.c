#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils.h"
#include "logging.h"

uintptr_t round_up(uintptr_t value, int multiple) {
  uintptr_t remainder = value % multiple;
  if (remainder == 0)
    return value;
  else
    return value + multiple - remainder;
}

uintptr_t round_up_page_size(uintptr_t size) {
  return round_up(size, getpagesize());
}

int             g_event_type = -1;
#define MAX_EVENT_NAME 0x100
char            g_event_name[MAX_EVENT_NAME];


// XXX: utils sounds so strage for this function
void set_event_type(int ety, char* name)
{
    // EVENT_* is ascending ordered by interesting
    // e.g., ALLOC_IN_BUFFER is more interesting than OVERLAP or RESTRICTED_WRITE_IN_BUFFER
    assert(ety >= 0);
    if (ety > g_event_type) {
        g_event_type = ety; // At first time
        strncpy(g_event_name, name, MAX_EVENT_NAME - 1);
    }
}

bool has_event() {
    return g_event_type != -1;
}

void show_event()
{
    if (has_event()) {
        fprintf(stderr, "// " DBG_INFO "EVENT_%s is detected\n",
            g_event_name);
    }
}
