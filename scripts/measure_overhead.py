#!/usr/bin/env python3
"""Linux-only sequential overhead measurements; emits anonymized JSON lines."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpus', required=True)
    parser.add_argument('--duration', type=float, default=15)
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if args.duration <= 0 or args.repeats < 1:
        parser.error('duration and repeats must be positive')
    script = Path(__file__).resolve().parent.parent / 'coreward.py'
    print(json.dumps({'schema': 1, 'script_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                      'duration_s': args.duration, 'repeats': args.repeats,
                      'stdout': '/dev/null', 'cpu_basis': 'one logical CPU = 100%',
                      'includes_startup_and_children': True}), flush=True)
    modes = [('thread_1s', ['-s', 'thread', '-i', '1']),
             ('process_1s', ['-s', 'process', '-i', '1']),
             ('thread_idle_1s', ['-s', 'thread', '-i', '1', '-l']),
             ('thread_200ms', ['-s', 'thread', '-i', '0.2'])]
    # Rotate order between rounds to reduce systematic time-of-run bias.
    for repeat in range(args.repeats):
        for mode, flags in modes[repeat % len(modes):] + modes[:repeat % len(modes)]:
            command = [sys.executable, str(script), args.cpus, '-d', str(args.duration)] + flags
            with tempfile.TemporaryFile(mode='w+b') as stderr:
                start = time.monotonic()
                child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
                try:
                    _, status, usage = os.wait4(child.pid, 0)
                    child.returncode = os.waitstatus_to_exitcode(status)
                finally:
                    if child.returncode is None:
                        child.terminate()
                        child.wait()
                elapsed = time.monotonic() - start
                stderr.seek(0)
                output = stderr.read().decode('utf-8', errors='replace')
            if child.returncode:
                raise RuntimeError('monitor failed with exit {}'.format(child.returncode))
            summary = re.search(r'^stopped: (.+)$', output, re.MULTILINE)
            if summary is None or 'clock=schedstat-ns' not in output:
                raise RuntimeError('missing completion summary or nanosecond clock')
            row = {'mode': mode, 'repeat': repeat + 1, 'wall_s': round(elapsed, 6),
                   'user_s': round(usage.ru_utime, 6), 'system_s': round(usage.ru_stime, 6),
                   'cpu_pct_inclusive': round(100 * (usage.ru_utime + usage.ru_stime) / elapsed, 4),
                   'peak_rss_kib': usage.ru_maxrss,
                   'warnings_other_than_visibility': sum(line.startswith('WARNING:') and
                       'visibility depends on' not in line for line in output.splitlines())}
            for item in summary.group(1).split():
                name, value = item.split('=')
                row[name] = float(value) if '.' in value else int(value)
            print(json.dumps(row), flush=True)


if __name__ == '__main__':
    main()
