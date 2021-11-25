#!/usr/bin/env python3
import argparse
import copy
import logging
import os
import re
import subprocess
import shutil
import time
import tempfile
import signal
import scipy.stats
import numpy as np
import sys

BUF_MAX = 4096
N_SAMPLES = 30
EXEC_TMOUT = 10

l = logging.getLogger('minimize')

def get_driver_exe():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "driver"))

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=['greedy', 'ssdd', 'classical'], default='ssdd')
    p.add_argument("action_map_file")
    p.add_argument("cmd", nargs="+")
    return p.parse_args()

class Minimizer(object):
    def __init__(self, cmd, mode):
        self.cmd = cmd[:-1]
        assert(cmd[-1] == "@@")
        self.mode = mode

        # setup environ variables
        env = copy.copy(os.environ)
        env["LIBC_FATAL_STDERR_"] = "1"
        self.env = env

        self.orig_cmd = copy.copy(self.cmd)
        self.orig_env = env

    @property
    def crash_signals(self):
        sig = signal.SIGUSR2
        return [-sig, 128 + sig]

    def run_driver(self, input_file, action_map_file=None):
        stdout = open(os.devnull, "wb")
        stderr = subprocess.PIPE

        cmd = self.cmd + [input_file]
        if action_map_file:
            cmd += [action_map_file]

        p = subprocess.Popen(
                cmd,
                env=self.env,
                stdout=stdout, stderr=stderr)
        try:
            _, stderr = p.communicate(timeout=EXEC_TMOUT)
        except subprocess.TimeoutExpired:
            p.terminate()
            stderr = b''
        return stderr.decode('utf-8'), p.wait()

    def check_deterministic(self, input_file):
        stderr, retcode = self.run_driver(input_file)
        return self.get_prob(stderr) == 1

    def get_event(self, input_file, action_map_file=None):
        stderr, _ = self.run_driver(input_file, action_map_file)
        events = re.findall(r"(EVENT_.*) is detected", stderr)
        if not events:
            return "EVENT_UNKNOWN"
        assert(len(events) == 1)
        return events[0]

    def get_num_actions(self, input_file, action_map_file=None):
        stderr, _ = self.run_driver(input_file, action_map_file)
        nactions = re.findall(r"The number of actions: (\d+)", stderr)
        assert(len(nactions) == 1)
        return int(nactions[0])

    def get_vuln(self, input_file, action_map_file=None):
        stderr, _ = self.run_driver(input_file, action_map_file)
        vuln = re.findall(r"\[VULN\] (.*)", stderr)
        if not vuln:
            return "VULN_UNKNOWN"

        return vuln[0]

    def get_prob(self, stderr):
        prob = re.findall(r"Probability: (.*)", stderr)
        if not prob:
            return 0.0

        return float(prob[0])

    def get_probs(self, input_file, action_map_file=None):
        probs = []
        for i in range(N_SAMPLES):
            stderr, _ = self.run_driver(input_file, action_map_file)
            probs.append(self.get_prob(stderr))
        return probs

    def patch_cmdline_deterministic(self):
        for i, arg in enumerate(self.cmd):
            split = arg.split("/")
            if split[-1] != 'parent':
                continue

            # switch parent to child for efficiency
            split[-1] = 'child'
            self.cmd[i] = '/'.join(split)
            assert(os.path.exists(self.cmd[i]))

            # remove a child option
            if '-c' in self.cmd:
                self.cmd.remove('-c')

            if "HARDSHEAP_PRELOAD" in self.env:
                self.env["LD_PRELOAD"] = self.env["HARDSHEAP_PRELOAD"]
            return

        raise ValueError('Unexpected cmdline')

    def restore_cmdline(self):
        self.env = copy.copy(self.orig_env)
        self.cmd = copy.copy(self.orig_cmd)

    def minimize_deterministic(self, crash_file, action_map_file, timeout):
        l.info("Start to minimize deterministic: %s" % crash_file)

        event = self.get_event(crash_file)
        nactions = self.get_num_actions(crash_file)

        if not nactions:
            l.info("No crash file: %s" % crash_file)
            return None, None, None

        action_map = bytearray(b"\x00" * nactions)

        start_time = time.time()
        for i in range(len(action_map)):
            action_map[i] = 0xff # Disable it
            with open(action_map_file, "wb") as f:
                f.write(action_map)
            new_event = self.get_event(crash_file, action_map_file)
            if event != new_event:
                action_map[i] = 0x00
                l.info("Need %dth action" % i)
            else:
                l.info("Remove %dth action" % i)
            if time.time() - start_time > timeout:
                break

        with open(action_map_file, "wb") as f:
            f.write(action_map)

        nactions = self.get_num_actions(crash_file, action_map_file)
        event = self.get_event(crash_file, action_map_file)
        vuln = self.get_vuln(crash_file, action_map_file)

        if any([not bool(b) for b in [nactions, event, vuln]]):
            return None, None, None

        return nactions, event, vuln

    def compare_probs(self, probs, new_probs):
        # check whether probs >= new_probs
        if self.mode == 'greedy':
            return np.average(probs) > np.average(new_probs)
        else:
            t, p = scipy.stats.ttest_ind(probs, new_probs)
            return t > 0 and p < 0.05

    def minimize_probabilistic(self, crash_file, action_map_file, timeout):
        # Don't consider multi-events in probabilistic manner
        l.info("Start to minimize probablistic: %s" % crash_file)

        nactions = self.get_num_actions(crash_file)
        probs = self.get_probs(crash_file)

        if not nactions or np.average(probs) == 0:
            l.info("No crash file: %s" % crash_file)
            return None, None, None

        action_map = bytearray(b"\x00" * nactions)
        start_time = time.time()
        for i in range(len(action_map)):
            action_map[i] = 0xff # Disable it
            with open(action_map_file, "wb") as f:
                f.write(action_map)
            new_probs = self.get_probs(crash_file, action_map_file)
            if self.compare_probs(probs, new_probs):
                action_map[i] = 0x00
                l.info("Need %dth action" % i)
            else:
                l.info("Remove %dth action" % i)

            if time.time() - start_time > timeout:
                break

        with open(action_map_file, "wb") as f:
            f.write(action_map)

        nactions = self.get_num_actions(crash_file, action_map_file)
        # It's not possible to get event in a probablistic case
        event = "EVENT_UNKNOWN"
        vuln = self.get_vuln(crash_file, action_map_file)

        if any([not bool(b) for b in [nactions, event, vuln]]):
            return None, None, None

        return nactions, event, vuln


    def minimize(self, crash_file, action_map_file, log_file=None, timeout=5*60):
        # Check if it is really crash file
        if self.mode == 'classical' or self.check_deterministic(crash_file):
            self.patch_cmdline_deterministic()
            out = self.minimize_deterministic(crash_file, action_map_file, timeout)
            self.restore_cmdline()
        else:
            out = self.minimize_probabilistic(crash_file, action_map_file, timeout)

        cmd = self.cmd + [crash_file, action_map_file]

        if log_file:
            stderr, _ = self.run_driver(crash_file, action_map_file)
            with open(log_file, 'wb') as f:
                f.write(stderr.encode('utf-8'))

        return out

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    args = parse_args()

    cmd = copy.copy(args.cmd)
    crash_file = cmd[-1]
    cmd[-1] = "@@"

    if os.path.exists(args.action_map_file):
        print('[-] File already exists: %s' % args.action_map_file)
        sys.exit(1)

    minimizer = Minimizer(cmd, mode=args.mode)
    minimizer.minimize(crash_file, args.action_map_file)

    # Run to show the minimized one
    import sys
    sys.stderr.write("\n")
    os.system(" ".join(args.cmd[:-1] + [crash_file, args.action_map_file]))
