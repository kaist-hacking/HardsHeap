#include <stdbool.h>
#include <stdio.h>
#include <map>
#include "common/stream.h"

extern Stream g_shm_strm;
int n_runs = 0;
std::map<std::pair<int, int>, int> n_events;

void analyze_single()
{
    bool strict = stream_read_8(&g_shm_strm);

    n_runs++;

    while(true) {
      bool valid = stream_read_8(&g_shm_strm);
      if (!valid) break;
      int i = stream_read_32(&g_shm_strm);
      int j = stream_read_32(&g_shm_strm);

      if (i == -1 && j == -1)
        break;

      if (strict)
        n_events[std::make_pair(i, j)] += 1;
      else {
        // In non-strict mode, just calculate the number of event
        n_events[std::make_pair(0, 0)] += 1;
        break;
      }
    }
}

double calculate_prob()
{
  int most_freq = 0;
  for (auto it :  n_events)
    most_freq = std::max(most_freq, it.second);

  return (double)most_freq / n_runs;
}
