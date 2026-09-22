#!/usr/bin/env python3
"""Small Linux CPU intruder monitor; Python 3.6+, standard library only."""
import argparse
import json
import math
import os
import pwd
import re
import resource
import signal
import subprocess
import sys
import time


def cpu_list(value):
    result = set()
    for part in value.split(','):
        if not re.fullmatch(r'[0-9]+(?:-[0-9]+)?', part):
            raise ValueError('invalid CPU list: ' + value)
        ends = [int(x) for x in part.split('-')]
        first, last = ends[0], ends[-1]
        if first > last or last > 1048575:
            raise ValueError('invalid CPU range: ' + part)
        result.update(range(first, last + 1))
    return result


def read(path):
    with open(path, encoding='utf-8', errors='replace') as stream:
        return stream.read()


def format_cpus(cpus):
    ranges = []
    first = last = None
    for cpu in sorted(set(cpus)):
        if first is None:
            first = last = cpu
        elif cpu == last + 1:
            last = cpu
        else:
            ranges.append(str(first) if first == last else '{}-{}'.format(first, last))
            first = last = cpu
    if first is not None:
        ranges.append(str(first) if first == last else '{}-{}'.format(first, last))
    return ','.join(ranges)


def format_hit(timestamp, user, uid, pid, tid, cpu, state, delta, cpu_pct, comm):
    # Minimum widths only: never truncate identifiers or command names.
    return ('{}  pid={:<8} tid={:<8} last_cpu={:<5} cpu_pct={:>6.2f}%\n'
            '  user={:<22} uid={:<10} state={:<3} delta_ticks={}\n'
            '  comm={}').format(timestamp, pid, tid, cpu, cpu_pct,
                               json.dumps(user, ensure_ascii=True), uid, state, delta,
                               json.dumps(comm, ensure_ascii=True))


def excluded_users(value):
    if value is None:
        # sudo defaults to the invoking user, not root.
        return {int(os.environ.get('SUDO_UID', os.getuid()))}
    result = set()
    if value == '':
        return result
    for name in value.split(','):
        name = name.strip()
        if not name:
            raise ValueError('empty entry in user list; use --exclude-users "" for none')
        result.add(int(name) if name.isdecimal() else pwd.getpwnam(name).pw_uid)
    return result


def parse_stat(data):
    return parse_record(data)[:5]


def parse_record(data):
    # comm may itself contain spaces and closing parentheses.
    left, right = data.index('('), data.rindex(')')
    fields = data[right + 2:].split()
    return (data[left + 1:right], fields[0], int(fields[11]) + int(fields[12]),
            int(fields[19]), int(fields[36]), int(fields[17]))


def effective_uid(status):
    for line in status.splitlines():
        if line.startswith('Uid:'):
            return int(line.split()[2])
    raise ValueError('missing Uid in proc status')


def warn(message):
    print('WARNING: ' + message, file=sys.stderr, flush=True)


class StatReader:
    """Reuse proc stat descriptors; no repeated open/read-to-EOF/close per tick."""
    def __init__(self):
        self.files = {}
        self.seen = set()
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        desired = 8256 if hard == resource.RLIM_INFINITY else min(hard, 8256)
        if soft != resource.RLIM_INFINITY and soft < desired:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
                soft = desired
            except (ValueError, OSError):
                pass
        self.limit = 8192 if soft == resource.RLIM_INFINITY else max(0, min(8192, soft - 64))

    def read(self, path):
        self.seen.add(path)
        fd = self.files.get(path)
        temporary = False
        if fd is None:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
            if len(self.files) < self.limit:
                self.files[path] = fd
            else:
                temporary = True
        try:
            data = os.pread(fd, 8192, 0)
            if not data:
                raise ProcessLookupError(path)
            return data.decode('utf-8', errors='replace')
        except (FileNotFoundError, ProcessLookupError):
            if not temporary:
                os.close(self.files.pop(path))
            raise
        finally:
            if temporary:
                os.close(fd)

    def prune(self):
        for path in self.files.keys() - self.seen:
            os.close(self.files.pop(path))
        self.seen.clear()

    def close(self):
        for fd in self.files.values():
            os.close(fd)
        self.files.clear()

    def __del__(self):
        self.close()


class Scanner:
    def __init__(self, cpus, excluded, proc='/proc', scope='thread', threshold=1.0):
        if scope not in ('thread', 'process'):
            raise ValueError('scope must be thread or process')
        self.scope = scope
        self.threshold = threshold
        self.clock_ticks = os.sysconf('SC_CLK_TCK')
        self.cpus, self.excluded, self.proc = cpus, excluded, proc
        try:
            self.high_resolution = int(read(proc + '/self/schedstat').split()[0]) > 0
        except (OSError, ValueError, IndexError):
            self.high_resolution = False
        self.runtime_fallbacks = 0
        self.previous = {}
        self.denied = 0
        self.scanned = 0
        self.reader = StatReader()

    def scan(self):
        previous, current, hits = self.previous, {}, []
        sampled_at = time.monotonic()
        self.denied = self.scanned = 0
        self.runtime_fallbacks = 0
        with os.scandir(self.proc) as processes:
            for process in processes:
                if not process.name.isdecimal() or int(process.name) == os.getpid():
                    continue
                try:
                    task = process.path + '/task/'
                    leader_path = task + process.name + '/stat'
                    leader = parse_record(self.reader.read(leader_path))
                    count = leader[5]
                    # Process scope deliberately samples only the leader's own
                    # stat, not aggregate process CPU time paired with its CPU.
                    if self.scope == 'thread' and count > 1:
                        with os.scandir(task) as entries:
                            tids = [e.name for e in entries if e.name.isdecimal()]
                    else:
                        tids = [process.name]
                    uid = None
                    for tid in tids:
                        try:
                            record = leader if tid == process.name else parse_record(self.reader.read(task + tid + '/stat'))
                            comm, state, ticks, start, cpu, _ = record
                            self.scanned += 1
                            key = (int(process.name), int(tid), start)
                            old = previous.get(key)
                            runtime_ns = None
                            observed_at = sampled_at
                            if self.high_resolution:
                                try:
                                    runtime_ns = int(self.reader.read(task + tid + '/schedstat').split()[0])
                                    observed_at = time.monotonic()
                                except (PermissionError, FileNotFoundError, ProcessLookupError, ValueError, IndexError):
                                    self.runtime_fallbacks += 1
                            # Never compare different clocks after fallback or recovery.
                            if old is not None and ((old[2] is None) != (runtime_ns is None)):
                                old = None
                            current[key] = (ticks, observed_at, runtime_ns)
                            delta = ticks - old[0] if old is not None else 0
                            elapsed = observed_at - old[1] if old is not None else 0
                            runtime_delta = (runtime_ns - old[2]
                                             if runtime_ns is not None and old is not None else 0)
                            active = runtime_delta > 0 if runtime_ns is not None else delta > 0
                            if cpu in self.cpus and (active or state == 'R'):
                                cpu_seconds = (max(0, runtime_delta) / 1e9 if runtime_ns is not None
                                               else max(0, delta) / self.clock_ticks)
                                cpu_pct = (100.0 * cpu_seconds / elapsed
                                           if elapsed > 0 else 0.0)
                                # Positive thresholds need two samples, including
                                # for runnable tasks and newly reused thread IDs.
                                if self.threshold > 0 and (old is None or cpu_pct < self.threshold):
                                    continue
                                # Resolve credentials only for candidate processes,
                                # never cache UID across scans or PID reuse.
                                if uid is None:
                                    uid = effective_uid(read(process.path + '/status'))
                                if uid not in self.excluded:
                                    hits.append((key, uid, cpu, comm, state, delta, cpu_pct))
                        except PermissionError:
                            self.denied += 1
                        except (FileNotFoundError, ProcessLookupError):
                            pass
                except PermissionError:
                    self.denied += 1
                except (FileNotFoundError, ProcessLookupError):
                    pass
        self.reader.prune()
        self.previous = current
        return hits


def cpu_times():
    result = {}
    for line in read('/proc/stat').splitlines():
        fields = line.split()
        if fields and re.fullmatch(r'cpu[0-9]+', fields[0]):
            values = [int(x) for x in fields[1:9]]  # guest time already included
            result[int(fields[0][3:])] = (sum(values), values[3])
    return result


class IdlePlacement:
    def __init__(self, watched):
        self.allowed = set(os.sched_getaffinity(0))
        self.pool = self.allowed - watched or self.allowed
        self.previous = cpu_times()
        self.next_update = time.monotonic() + 2
        # Keep the monitor off watched cores when alternatives are available.
        os.sched_setaffinity(0, self.pool)

    def update(self, now):
        if now < self.next_update:
            return
        current = cpu_times()
        candidates = self.pool & current.keys()
        scores = {}
        for cpu in candidates:
            total, idle = current[cpu]
            before = self.previous.get(cpu, (total, idle))
            elapsed = total - before[0]
            if elapsed > 0:
                scores[cpu] = max(0, idle - before[1]) / elapsed
        if scores:
            best = max(scores.values())
            # A small idle group lets the kernel balance work; avoid one-core pinning.
            chosen = sorted((c for c in scores if scores[c] >= best - 0.05),
                            key=lambda c: (-scores[c], c))[:4]
            os.sched_setaffinity(0, set(chosen))
        self.previous, self.next_update = current, now + 2


def low_priority(cpus):
    for label, action in (
        ('nice 19', lambda: os.setpriority(os.PRIO_PROCESS, 0, 19)),
        ('SCHED_IDLE', lambda: os.sched_setscheduler(0, os.SCHED_IDLE, os.sched_param(0))),
    ):
        try:
            action()
        except (OSError, AttributeError) as error:
            warn('{} unavailable: {}'.format(label, error))
    try:
        result = subprocess.run(['ionice', '-c', '3', '-p', str(os.getpid())],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                universal_newlines=True, timeout=3)
        if result.returncode:
            warn('idle I/O priority unavailable: ' + result.stderr.strip())
    except (OSError, subprocess.TimeoutExpired) as error:
        warn('idle I/O priority unavailable: ' + str(error))
    print('priority: policy={} nice={}'.format(os.sched_getscheduler(0),
          os.getpriority(os.PRIO_PROCESS, 0)), file=sys.stderr, flush=True)
    try:
        return IdlePlacement(cpus)
    except OSError as error:
        warn('idle CPU placement unavailable: ' + str(error))
        return None


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError('must be finite and greater than zero')
    return number


def percentage(value):
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 100:
        raise argparse.ArgumentTypeError('must be finite and between 0 and 100')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cpus', help='CPU IDs, e.g. 0-3,8,10')
    parser.add_argument('-i', '--interval', type=positive, default=1.0, help='seconds (default: 1.0)')
    parser.add_argument('-s', '--scope', choices=('thread', 'process'), default='thread',
                        help='thread: all threads (default); process: leaders only, misses worker threads')
    parser.add_argument('-x', '--exclude-users', default=None, metavar='USER,UID,...',
                        help='replace default current-user exclusion; empty string excludes nobody')
    parser.add_argument('-l', '--low-priority', action='store_true', help='idle scheduling and idle CPU selection')
    parser.add_argument('-r', '--repeat', type=positive, default=5.0, help='repeat persistent sightings after N seconds (default: 5)')
    parser.add_argument('-t', '--threshold', type=percentage, default=1.0, metavar='PERCENT',
                        help='minimum sampled CPU %% of one core (default: 1.0; 0 disables filtering)')
    parser.add_argument('-d', '--duration', type=positive, help='stop after N seconds; default runs until Ctrl+C')
    args = parser.parse_args()
    try:
        cpus = cpu_list(args.cpus)
        online = cpu_list(read('/sys/devices/system/cpu/online').strip())
        if not cpus <= online:
            raise ValueError('CPU IDs are offline or absent: ' + str(sorted(cpus - online)))
        excluded = excluded_users(args.exclude_users)
    except (ValueError, KeyError, OSError) as error:
        parser.error(str(error))
    scanner = Scanner(cpus, excluded, scope=args.scope, threshold=args.threshold)
    if not scanner.high_resolution:
        warn('nanosecond runtime unavailable; using coarse stat ticks ({} ticks/s). '
             'Low thresholds can produce quantization noise.'.format(scanner.clock_ticks))
    placement = low_priority(cpus) if args.low_priority else None
    print('watch={}\ninterval={}s scope={} threshold={}% of one core exclude_uids={} clock={}\n'
          'last_cpu is a sampled hint, not a scheduling trace'.format(
          format_cpus(cpus), args.interval, args.scope, args.threshold, sorted(excluded),
          'schedstat-ns' if scanner.high_resolution else 'stat-ticks'),
          file=sys.stderr, flush=True)
    if args.scope == 'process':
        print('process scope checks main threads only; worker-thread activity is not covered',
              file=sys.stderr, flush=True)
    if os.geteuid() != 0:
        warn('visibility depends on /proc permissions, hidepid and PID namespace; hidden processes cannot be detected')
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    start = time.monotonic()
    cpu_start = time.process_time()
    next_poll = start
    last_warning = -float('inf')
    reported, users = {}, {}
    samples = 0
    max_scan = total_scan = 0.0
    max_threads = 0
    while not stopped:
        now = time.monotonic()
        if args.duration and now - start >= args.duration:
            break
        if placement:
            try:
                placement.update(now)
            except OSError as error:
                warn('idle CPU placement disabled: ' + str(error))
                placement = None
        scan_start = time.monotonic()
        hits = scanner.scan()
        scan_time = time.monotonic() - scan_start
        total_scan += scan_time
        max_scan = max(max_scan, scan_time)
        max_threads = max(max_threads, scanner.scanned)
        samples += 1
        active = set()
        for key, uid, cpu, comm, state, delta, cpu_pct in hits:
            identity = (key, uid, cpu)
            active.add(identity)
            if now - reported.get(identity, -float('inf')) < args.repeat:
                continue
            if uid not in users:
                try:
                    users[uid] = pwd.getpwuid(uid).pw_name
                except KeyError:
                    users[uid] = str(uid)
            print(format_hit(time.strftime('%Y-%m-%d %H:%M:%S'), users[uid], uid, key[0], key[1],
                             cpu, state, delta, cpu_pct, comm), flush=True)
            reported[identity] = now
        # Brief sleep/wake cycles must not bypass the output cooldown.
        reported = {key: value for key, value in reported.items()
                    if key in active or now - value < args.repeat}
        if (scanner.denied or scanner.runtime_fallbacks or scan_time > args.interval) and now - last_warning >= 10:
            warn('scan={:.1f}ms denied={} coarse_clock_fallbacks={} '
                 '(denials mean incomplete coverage; coarse clocks can cause threshold noise)'.format(
                 scan_time * 1000, scanner.denied, scanner.runtime_fallbacks))
            last_warning = now
        next_poll += args.interval
        current_time = time.monotonic()
        if next_poll <= current_time:
            next_poll = current_time + args.interval  # never spin to catch up
        delay = next_poll - current_time
        if args.duration:
            delay = min(delay, max(0, start + args.duration - current_time))
        time.sleep(delay)
    elapsed = time.monotonic() - start
    print('stopped: samples={} max_threads={} mean_scan_ms={:.2f} max_scan_ms={:.2f} cpu_pct_one_core={:.2f}'.format(
          samples, max_threads, total_scan * 1000 / max(samples, 1), max_scan * 1000,
          100 * (time.process_time() - cpu_start) / max(elapsed, 0.001)), file=sys.stderr, flush=True)


if __name__ == '__main__':
    if sys.platform != 'linux':
        sys.exit('coreward requires Linux /proc and Python 3.6+')
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)
