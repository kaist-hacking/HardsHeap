#!/usr/bin/env python3
import argparse
import logging
import os
import re
import signal
import shutil
import tempfile
import multiprocessing as mp
import shlex
import minimize
import sys

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-c', '--cpu_count', default=mp.cpu_count(), type=int)
    p.add_argument('--mode', choices=['greedy', 'ssdd', 'classical'], default='ssdd')
    p.add_argument('afl_dir')
    p.add_argument('output_dir')
    return p.parse_args()

def minimize_one(crash_dir, output_dir, name):
    minimizer = minimize.Minimizer(cmd, args.mode)
    path = os.path.join(crash_dir, name)
    action_map_file = os.path.join(args.output_dir, name + ".min")
    log_file = os.path.join(args.output_dir, name + ".log")

    shutil.copy(path, os.path.join(args.output_dir, name))

    # Save raw log file before minimization
    raw_log_file = os.path.join(args.output_dir, name + ".rawlog")
    stderr, _ = minimizer.run_driver(path)
    with open(raw_log_file, "wb") as f:
        f.write(stderr.encode('utf-8'))

    try:
        nactions, event, vuln = minimizer.minimize(path, action_map_file, log_file)
    except (AssertionError, UnicodeDecodeError, OSError):
        return None, None, None

    if nactions is None:
        return None, None, None

    return nactions, event, vuln

if __name__ == "__main__":
    args = parse_args()

    logging.basicConfig(level=logging.DEBUG)

    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)

    # Read fuzzer_stats to find cmd
    fuzzer_stats = open(os.path.join(args.afl_dir, "fuzzer_stats")).read()
    command_line = fuzzer_stats.split("\n")[-2].replace("driver-fuzz", "driver")
    cmd = re.findall(r"[^\s]*driver.*", command_line)[0]
    cmd = shlex.split(cmd) # To handle an argument with space
    cmd[0] = os.path.abspath(cmd[0])

    crash_dir = os.path.join(args.afl_dir, "crashes")
    if not os.path.exists(crash_dir):
        print('[-] No crash found')
        sys.exit(0)

    pool = mp.Pool(args.cpu_count)
    results = []
    for name in sorted(os.listdir(crash_dir)):
        if name in ["README.txt"]:
            continue
        results.append(pool.apply_async(minimize_one, (crash_dir, args.output_dir, name)))

    pool.close()
    pool.join()

    # make summary
    minimals = {}
    for res in results:
        nactions, event, vuln = res.get()
        if nactions is None:
            continue

        key = event + ":" + vuln

        min_nactions, _ = minimals.get(key, (2**32, ""))
        if min_nactions > nactions:
            minimals[key] = (nactions, name)

    with open(os.path.join(args.output_dir, "summary.txt"), "w") as f:
        for k, v in minimals.items():
            f.write("%s: %s (%d)\n" % (k, v[1], v[0]))
