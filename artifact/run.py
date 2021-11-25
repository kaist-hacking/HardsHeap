#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
import multiprocessing as mp
from itertools import product

ROOT = os.path.dirname(os.path.abspath(__file__))

MODES = {
    'adjacent': [
            ('crossobj', ['-m', '-c']),
            ('smallobj', ['-c', '-u 1024'])
    ],

    'reclaim': [
            ('smallobj', ['-c', '-u 1024'])
    ]
}

def get_modules(build_dir):
    modules = {}
    modules_dir = os.path.join(build_dir, "modules")
    for m in os.listdir(modules_dir):
        if m == 'example':
            continue

        parent = os.path.join(modules_dir, m, "parent")

        if not os.path.exists(parent):
            continue

        modules[m] = (parent, [])

        # Support additional modes
        if m in MODES:
            additional_modes = MODES[m]
            for mode, option in additional_modes:
                modules['%s-%s' % (m, mode)] = (parent, option)

    return modules


def get_allocators():
    allocators = {}
    allocators_dir = os.path.join(ROOT, 'secure-allocators')
    for a in os.listdir(allocators_dir):
        dirp = os.path.join(allocators_dir, a)
        if not os.path.isdir(dirp):
            continue

        run_sh = os.path.join(dirp, "run.sh")
        if not os.path.exists(run_sh):
            print('[!] %s does not have run.sh' % a)
            continue

        allocators[a] = run_sh
    return allocators


def make_input(output_dir):
    input_dir = os.path.join(output_dir, 'input')
    os.mkdir(input_dir)

    # Non-crashing inputs
    with open(os.path.join(input_dir, 'default'), 'w') as f:
        f.write('A')

    for i in range(16):
        with open(os.path.join(input_dir, 'random%02d' % i), 'wb') as f:
            f.write(os.urandom(16))

    return input_dir


def clean_up(p):
 if p.poll() == None:
    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
    p.wait()

def run_single(args, input_dir, module, module_path, allocator, allocator_path, timeout, option):
    print(f'[+] Run {module} to {allocator}')
    test_dir = os.path.join(args.output_dir, module, f'output-{allocator}')

    os.makedirs(test_dir)
    afl_fuzz = os.path.join(args.root_dir, 'tool/afl-2.52b/afl-fuzz')

    p = subprocess.Popen([
        allocator_path,
        afl_fuzz,
        '-m', 'none',
        '-i', input_dir,
        '-o', test_dir]
        + ['--', module_path]
        + option
        + ['@@'],
        env=os.environ,
        preexec_fn=os.setsid)

    signal.signal(signal.SIGINT, lambda: clean_up(p))

    try:
        p.wait(timeout=timeout)
    finally:
        clean_up(p)

def run_hardsheap(args, modules, allocators, timeout):
    os.mkdir(args.output_dir)
    input_dir = make_input(args.output_dir)

    # If we have multiple test cases, don't use UI
    if len(modules) != 1 or len(allocators) != 1:
        os.environ['AFL_NO_UI'] = '1'

    # Temporarly disable affinity due to error
    os.environ['AFL_NO_AFFINITY'] = '1'

    # Skip crashes for trivial ones
    os.environ['AFL_SKIP_CRASHES'] = '1'

    pool = mp.Pool(mp.cpu_count() // 2)

    results = []
    for module, allocator in product(modules.keys(), allocators.keys()):
        module_path, option = modules[module]
        allocator_path = allocators[allocator]

        r = pool.apply_async(run_single, [args, input_dir, module, module_path, allocator, allocator_path, timeout, option])
        results.append(r)

    for r in results:
        r.get()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--timeout', default=24 * 60 * 60, type=int)
    parser.add_argument('-r', '--root_dir', required=True, help="HardsHeap's root directory")
    parser.add_argument('-b', '--build_dir', default=None, help='Build directory with compiled modules')
    parser.add_argument('-o', '--output_dir', required=True, help='Output directory to store testing results')
    parser.add_argument('-m', '--module', help='HardsHeap module to run (Default: all modules)')
    parser.add_argument('-a', '--allocator', help='Secure allocator (Default: all allocators)')
    args = parser.parse_args()

    if os.path.exists(args.output_dir):
        print(f'[-] Output directory already exists: {args.output_dir}')
        sys.exit(1)

    if args.build_dir is None:
        args.build_dir = os.path.join(args.root_dir, 'driver/build')
        print(f"[*] 'build_dir' is not set. So use '{args.build_dir}' by default.")

    modules = get_modules(args.build_dir)

    if args.module:
        if args.module not in modules:
            print(f'[-] -m/--module should be one of {list(modules.keys())}')
            sys.exit(1)

        modules = {args.module: modules[args.module]}

    allocators = get_allocators()
    if args.allocator:
        if args.allocator not in allocators:
            print(f'[-] -a/--allocator should be one of {list(allocators.keys())}')
            sys.exit(1)

        allocators = {args.allocator: allocators[args.allocator]}

    run_hardsheap(args, modules, allocators, args.timeout)

