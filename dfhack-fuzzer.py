#! python3
"""
This is an experimental fuzzer for DFHack.

What is this?
=============
The guiding principle: no matter what an end-user does, DFHack should show an
error message rather than a traceback... and above all else, should never
DF to crash.  So my fuzzer tries to cause such bad things to happen!

It simply tries to run every DFHack command in fortress mode with no arguments.
This leads to obvious false-positive error reports if not meeting required
    - execution context or lack of cursor
    - arguments to the command
    - usage (ie should be `enable command`, not `command`)
    - order of stateful commands (eg `revflood` not after `reveal`)

Results are therefore categorised; eg for 43.05-alpha3
    'crashed_DF': 2,            # via dfhack-run, though not in console...
    'failed': 52,               # mostly due to fuzzer calling errors
    'ok': 149,                  # exit code 0 hopefully means it's OK
    'script_traceback': 24,     # traceback from a lua script - needs handling
    'wrong_UI_context': 26      # known to be fuzzer problems

This shows two commands which outright crash DF and should be fixed, along
with 24 scripts which need better error handling than dumping a traceback to
the console.  The 78 wrong context and other failed commands suggest a more
sophisticated fuzzer might be useful.  149 commands 'ok' is nice to see, but
note that this doesn't mean they worked - only that the eit code was zero!


How does it work?
=================
The code below is an almost trivial fuzzer - basically, it just starts DF then
uses `dfhack-run` to execute each command name.

Requires Python 3.4 or later.  Run in an interactive shell and inspect output,
or just read the json dump.


Why bother?
===========
It's trivial, and I already found two plugins that crash DF if you call
them (instead `enable $plugin`).  Isn't that enough?

Potential upgrades:
- Try multiple execution contexts, to explore some more commands or find
  some more crashes or tracebacks
- Know about and use command arguments, `enable`, required contexts, etc.
  This would massively improve coverage.
- Actual fuzzing, ie random inputs / simplification / etc.

"""

import collections
import glob
from os import path
import subprocess
import sys
import time


class DFInstance:
    """Provides an object which can run DFHack commands against a DF process,
    and restart it if it crashes."""

    def __init__(self, pattern='Dwarf Fortress 0.??.??'):
        """Find the DF and dfhack-run executables with `glob`."""
        pattern = pattern or 'Dwarf Fortress 0.??.??'
        df_dir = glob.glob(pattern)[0]
        self._df_exe = path.abspath(path.join(df_dir, 'Dwarf Fortress.exe'))
        self._dfhack_run = path.abspath(path.join(df_dir, 'dfhack-run.exe'))
        self._proc = None

    def open(self):
        """Starts the DF process and loads region1 if such a save exists."""
        if sys.platform.startswith("win"):
            # avoid popup message (ie manual intervention) on crashes
            # http://stackoverflow.com/a/5103935
            import ctypes
            SEM_NOGPFAULTERRORBOX = 0x0002
            ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)
            subprocess_flags = 0x8000000
        else:
            subprocess_flags = 0
        # Now actually open the process
        if self._proc is None or self._proc.returncode is not None:
            self._proc = subprocess.Popen(
                [self._df_exe], cwd=path.dirname(self._df_exe),
                creationflags=subprocess_flags)
            if path.isdir(path.join(path.dirname(self._df_exe),
                                    'data', 'save', 'region1')):
                # then load region1, which is assumed to be an embarked fort
                self.run('load-save', 'region1', safe=False)
                time.sleep(10)
            else:
                print('region1 not found - create world and embark for more '
                      'useful results (fewer UI context failures)')

    def run(self, *commands, safe=True):
        """Run a command consisting of the string arguments."""
        assert commands
        self.open()
        out = subprocess.run([self._dfhack_run, *commands],
                             stdout=subprocess.PIPE)
        if out.stdout.startswith(
                b'In call to ::RunCommand: I/O error in receive header.'):
            # DF just crashed without Popen noticing...
            self._proc = None
        return out

    # Generally best as a contet manager for automatic shutdown when done.
    def __enter__(self):
        return self.run

    def __exit__(self, type, value, traceback):
        subprocess.run([self._dfhack_run, 'die'])


def get_commands(hack=None):
    """Parse output of 'dfhack-run ls' to find commands to run."""
    if hack:
        result = hack('ls', '-a')
    else:
        with DFInstance() as run:
            result = run('ls', '-a')
    lines = [line.rstrip() for line in
             result.stdout.decode('utf-8').split('\n')]
    lines = lines[lines.index('plugins:')+ 1:]
    commands = [line.split(' - ')[0].strip() for line in lines
                if line.startswith('  ') and not line[2] == ' ']
    return [c for c in commands if not any(
        c.startswith(p) for p in ('devel/', 'ssense', 'stonesense'))]


def check(glob_pattern=None):
    """Check all DFHack commands """
    results = collections.defaultdict(dict)
    with DFInstance(glob_pattern) as hack:
        for cmd in get_commands(hack):
            proc = hack(cmd)
            out = proc.stdout.decode('utf-8').replace('\r\n', '\n')
            firstline = out.split('\n')[0].strip()
            # categorise results by some simple heuristics...
            if proc.returncode == 0:
                results['ok'][cmd] = out
            elif '/hack/scripts/' + cmd in out:
                results['script_traceback'][cmd] = out
            elif out.startswith(
                    'In call to ::RunCommand: I/O error in receive header.'):
                results['crashed_DF'][cmd] = out
            elif ' UI' in firstline or 'cursor' in firstline.lower():
                results['wrong_UI_context'][cmd] = out
            else:
                results['failed'][cmd] = out
    print({k: len(v) for k, v in results.items()})
    return dict(results)


if __name__ == '__main__':
    import json
    with open('fuzz_report.json', 'w') as f:
        json.dump(check(), f, indent=4)
