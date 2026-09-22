"""Unit and Linux integration checks. Run: python3 -m unittest -v."""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import coreward as cw


def stat_line(ticks=0, cpu=2, state='S', start=5, comm='a ) tricky name'):
    fields = ['0'] * 50
    fields[0], fields[11], fields[12] = state, str(ticks), '0'
    fields[17] = '1'
    fields[19], fields[36] = str(start), str(cpu)
    return '42 (' + comm + ') ' + ' '.join(fields)


class ParsingTests(unittest.TestCase):
    def test_cpu_lists(self):
        self.assertEqual(cw.cpu_list('0-2,5,2'), {0, 1, 2, 5})
        for value in ('', '2-1', 'a', '1,,2', '-1', '1-', '1.0', '0-999999999'):
            with self.assertRaises(ValueError):
                cw.cpu_list(value)

    def test_stat_comm(self):
        self.assertEqual(cw.parse_stat(stat_line(11)), ('a ) tricky name', 'S', 11, 5, 2))

    def test_users(self):
        self.assertEqual(cw.excluded_users(''), set())
        self.assertEqual(cw.excluded_users('123,456'), {123, 456})
        with mock.patch.dict(os.environ, {'SUDO_UID': '123'}):
            self.assertEqual(cw.excluded_users(None), {123})
        with self.assertRaises(ValueError):
            cw.excluded_users('123,')

    def test_sampling_baseline_activity_reuse_and_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / '987654'
            thread = root / 'task' / '987655'
            thread.mkdir(parents=True)
            leader = root / 'task' / '987654'
            leader.mkdir()
            leader_data = stat_line().rsplit(') ', 1)
            fields = leader_data[1].split()
            fields[17] = '2'
            (leader / 'stat').write_text(leader_data[0] + ') ' + ' '.join(fields))
            (root / 'status').write_text('Uid:\t123\t456\t123\t123\n')
            path = thread / 'stat'
            path.write_text(stat_line(10))
            scanner = cw.Scanner({2}, set(), directory)
            self.assertFalse(scanner.scan())  # historical sleeping CPU is not a hit
            path.write_text(stat_line(11))
            hit = scanner.scan()[0]
            self.assertEqual(hit[0], (987654, 987655, 5))
            self.assertEqual((hit[1], hit[-1]), (456, 1))
            self.assertFalse(scanner.scan())
            path.write_text(stat_line(100, start=6))
            self.assertFalse(scanner.scan())  # reused TID resets baseline
            path.write_text(stat_line(101, start=6, cpu=3))
            self.assertFalse(scanner.scan())
            path.write_text(stat_line(102, start=6, state='R'))
            self.assertTrue(scanner.scan())
            process_scanner = cw.Scanner({2}, set(), directory, scope='process')
            with mock.patch.object(cw.os, 'scandir', wraps=os.scandir) as scan_dirs:
                self.assertFalse(process_scanner.scan())  # active worker is not a main thread
                self.assertEqual(scan_dirs.call_count, 1)  # no task directory traversal
            self.assertEqual(process_scanner.scanned, 1)
            (leader / 'stat').write_text(stat_line(1, state='R'))
            self.assertEqual(process_scanner.scan()[0][0], (987654, 987654, 5))
            self.assertFalse(cw.Scanner({2}, {456}, directory, scope='process').scan())
            (leader / 'stat').write_text(leader_data[0] + ') ' + ' '.join(fields))
            self.assertFalse(cw.Scanner({2}, {456}, directory).scan())
            path.unlink()  # racing exit is harmless
            thread.rmdir()
            self.assertFalse(scanner.scan())

    def test_idle_placement_respects_original_mask(self):
        with mock.patch.object(cw.os, 'sched_getaffinity', return_value={1, 2, 3, 4}), \
             mock.patch.object(cw.os, 'sched_setaffinity') as setter, \
             mock.patch.object(cw, 'cpu_times', side_effect=[
                 {c: (100, 10) for c in range(6)},
                 {c: (200, 100 if c == 3 else 20) for c in range(6)}]):
            placement = cw.IdlePlacement({1})
            self.assertEqual(setter.call_args[0][1], {2, 3, 4})
            placement.update(placement.next_update + 1)
            self.assertEqual(setter.call_args[0][1], {3})


class LinuxTests(unittest.TestCase):
    def test_real_worker_thread_and_exclusion(self):
        cpus = sorted(os.sched_getaffinity(0))
        cpu = cpus[-1]
        worker = '''import os, threading, time
def work():
    os.sched_setaffinity(0, {%d})
    end = time.monotonic() + 2
    while time.monotonic() < end: pass
t = threading.Thread(target=work)
t.start()
t.join()
''' % cpu
        process = subprocess.Popen([sys.executable, '-c', worker])
        try:
            scanner = cw.Scanner({cpu}, set())
            deadline = time.monotonic() + 1.8
            found = False
            while time.monotonic() < deadline:
                if any(key[0] == process.pid and key[1] != process.pid
                       for key, *_ in scanner.scan()):
                    found = True
                    break
                time.sleep(0.05)
            self.assertTrue(found, 'worker thread was not detected')
            excluded = cw.Scanner({cpu}, {os.getuid()})
            self.assertFalse(any(key[0] == process.pid for key, *_ in excluded.scan()))
        finally:
            process.terminate()
            process.wait(timeout=3)

    def test_low_priority_applied_to_child(self):
        code = '''import coreward as c, os, subprocess
c.low_priority(set())
print('RESULT', os.sched_getscheduler(0), os.getpriority(os.PRIO_PROCESS, 0))
print(subprocess.check_output(['ionice', '-p', str(os.getpid())], text=True))
'''
        result = subprocess.run([sys.executable, '-c', code], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, universal_newlines=True, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RESULT 5 19', result.stdout)
        self.assertIn('idle', result.stdout)

    def test_cli_validation_and_duration(self):
        script = str(Path(cw.__file__).resolve())
        for args in (['2-1'], ['0', '-i', 'nan'], ['0', '--scope', 'invalid'],
                     ['0', '--exclude-users', 'nobody-with-this-name-coreward']):
            result = subprocess.run([sys.executable, script] + args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
        cpu = str(min(os.sched_getaffinity(0)))
        result = subprocess.run([sys.executable, script, cpu, '--duration', '.5'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('interval=1.0s', result.stderr)
        self.assertIn('samples=1 ', result.stderr)
        self.assertIn('scope=thread', result.stderr)
        result = subprocess.run([sys.executable, script, cpu, '-d', '.5', '-s', 'process', '-x', '', '-i', '1', '-r', '3'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scope=process', result.stderr)
        self.assertIn('exclude_uids=[]', result.stderr)
        self.assertIn('main threads only', result.stderr)


if __name__ == '__main__':
    unittest.main()
