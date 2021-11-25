#include <stdbool.h>
#include <stdio.h>
#include "common/stream.h"

extern Stream g_shm_strm;
int n_runs = 0;
int n_events = 0;

void analyze_single()
{
    n_runs++;

    bool happened = stream_read_8(&g_shm_strm);
    n_events += (int)happened;
}

double calculate_prob()
{
    return (double)n_events / n_runs;
}
