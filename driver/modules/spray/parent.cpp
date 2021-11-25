#include <stdbool.h>
#include <stdio.h>
#include "boost/icl/interval.hpp"
#include "boost/icl/interval_map.hpp"
#include "common/stream.h"

extern Stream g_shm_strm;

boost::icl::interval_map<uintptr_t, int> imap;
int n_runs = 0;

void analyze_single()
{
    n_runs++;

    while (true) {
        uintptr_t start = stream_read_ptr(&g_shm_strm);
        uintptr_t end = stream_read_ptr(&g_shm_strm);
        if (!start || !end)
            break;
        auto range = boost::icl::interval<uintptr_t>::right_open(start, end);
        imap += std::make_pair(range, 1);
    }
}

double calculate_prob()
{
    uintptr_t start = 0, end = 0;
    int n_events = 0;

    for (auto& iter : imap) {
        if (n_events < iter.second) {
            n_events = iter.second;
            start = boost::icl::first(iter.first);
            end = boost::icl::last(iter.first);
        }
    }

    fprintf(stderr, "// Address range [%p - %p] is the most frequently allocated\n", (void*)start, (void*)end);
    return (double)n_events / n_runs;
}
