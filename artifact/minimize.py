#!/usr/bin/env python3
import argparse
import sys
import os
import multiprocessing as mp
import subprocess
import signal

MODES = ['ssdd', 'greedy', 'deterministic']
ROOT = os.path.abspath(os.path.dirname(__file__))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout', default=3600, type=int)
    parser.add_argument('-r', '--root_dir', required=True, help="HardsHeap's root directory")
    parser.add_argument('-o', '--output_dir', required=True, help="Output directory")
    parser.add_argument('-m', '--modes', nargs='+', required=True,
            help="Modes for minimization (ssdd, greedy, deterministic)")
    return parser.parse_args()

def minimize_one(root_dir, module, test_dir, mode, timeout):
    allocator = os.path.basename(test_dir).split('-', 1)[1]
    allocator_path = os.path.join(ROOT, 'secure-allocators', allocator, 'run.sh')
    assert(os.path.exists(allocator_path))

    print(f'[+] Minimization({mode}): {module} to {allocator}')
    minimize_dir = os.path.join(test_dir, 'minimize_%s' % mode)
    if os.path.exists(minimize_dir):
        print(f'[-] Already exists: {minimize_dir}')
        return

    minimize_all_py = os.path.join(root_dir, 'driver/minimize_all.py')
    p = subprocess.Popen([
        allocator_path,
        minimize_all_py,
        '-c', '1',
        '--mode=%s' % mode,
        test_dir,
        minimize_dir],
        env=os.environ,
        preexec_fn=os.setsid)

    try:
        p.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    finally:
        p.wait()
if __name__ == '__main__':
    args = parse_args()

    if any([not mode in MODES for mode in args.modes]):
        print('Only available modes: %s' % MODES)
        sys.exit(1)


    results = []
    pool = mp.Pool(mp.cpu_count() // 2)

    minimize_all_py = os.path.join(args.root_dir, 'driver/minimize_all.py')
    for mode in sorted(args.modes):
        for module in os.listdir(args.output_dir):
            if module == 'input':
                continue
            module_dir = os.path.join(args.output_dir, module)
            for output_dir in os.listdir(module_dir):
                test_dir = os.path.join(module_dir, output_dir)
                r = pool.apply_async(minimize_one,
                        [args.root_dir, module, test_dir, mode, args.timeout])
                results.append(r)

    for r in results:
        r.get()
