// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The sandbox's egress proxy environment.
//
// OpenShell 0.1.1 drops every *_PROXY variable and NODE_USE_ENV_PROXY passed
// at `sandbox create --env` (the gateway stores them, the workload never
// sees them), so Spec.Env passes the proxy URL and its bypass list as
// openshell.EnvEgressURL and openshell.EnvEgressBypass as well, and one
// shell fragment, egressEnvScript, exports the standard variables from them
// wherever a process starts:
//
//   - every harness launcher runs it first (launcherPreamble), so the
//     harness and every tool it runs use the proxy;
//   - SandboxProfilePath runs it for login shells: the `sandbox connect`
//     shell and `openshell sandbox exec` without --no-login-shell (which
//     OpenShell runs as `bash -lc`);
//   - SandboxEnvPath runs it for `defenseclaw-gateway sandbox exec`, which
//     OpenShell starts without a login shell.
//
// SandboxProfilePath and SandboxEnvPath also put ShimDir first on PATH,
// where the harness command starts its launcher, so typing the harness name
// in a connect or exec shell gets the launcher's protections. A user
// start-up file can reset PATH after the profile ran (the community base
// image's ~/.bashrc does), so for bash the profile also defines, and
// exports, a function of the harness command's name that runs the shim.
// A process started by absolute path, from an emptied environment (env -i)
// or through `openshell sandbox exec --no-login-shell` directly gets
// neither, and a harness run nested inside a tool call inherits the proxy
// but not the launcher's per-start checks. The proxy is a convenience path,
// not the boundary: OpenShell refuses direct egress the policy does not
// allow either way.
const (
	// SandboxProfilePath is the root-owned login-shell profile fragment
	// /etc/profile sources.
	SandboxProfilePath = "/etc/profile.d/defenseclaw-sandbox.sh"
	// SandboxEnvPath is the root-owned command wrapper that
	// `defenseclaw-gateway sandbox exec` starts every command through.
	SandboxEnvPath = LauncherDir + "/sandbox-env"
	// ShimDir holds the root-owned shim that starts the harness command
	// through its launcher.
	ShimDir = connector.SandboxLibDir + "/shims"
)

// egressEnvScript exports the egress proxy settings from
// openshell.EnvEgressURL and openshell.EnvEgressBypass. It is POSIX sh (the
// profile fragment runs in whatever login shell starts). A well-formed
// http:// proxy URL replaces any proxy settings the caller's environment
// carries, so every process started through it goes through the DefenseClaw
// proxy; without one (the strict profile), or with a URL carrying anything
// but URL characters, the caller's environment is left alone. NO_PROXY
// defaults to the ingress host, which hooks reach directly.
const egressEnvScript = `# OpenShell drops the standard proxy variables passed at sandbox creation;
# DefenseClaw passes them under its own names.
case "${` + openshell.EnvEgressURL + `:-}" in
  http://*[!A-Za-z0-9:@._/-]*) ;;
  http://?*)
    HTTPS_PROXY="$` + openshell.EnvEgressURL + `"; HTTP_PROXY="$` + openshell.EnvEgressURL + `"
    https_proxy="$` + openshell.EnvEgressURL + `"; http_proxy="$` + openshell.EnvEgressURL + `"
    NODE_USE_ENV_PROXY=1
    NO_PROXY="${` + openshell.EnvEgressBypass + `:-` + connector.SandboxIngressHost + `}"; no_proxy="$NO_PROXY"
    export HTTPS_PROXY HTTP_PROXY https_proxy http_proxy NODE_USE_ENV_PROXY NO_PROXY no_proxy
    ;;
esac
`

// timeZoneScript exports TZ from openshell.EnvHostTimeZone, the zone of
// the machine the sandbox was created from, when TZ is not set already and
// the image has that zone's file (without it, libc would show UTC under
// the zone's name). A sandbox otherwise runs on UTC, and a harness's
// clock disagrees with the host's. POSIX sh, like egressEnvScript.
const timeZoneScript = `# The host's time zone, where the image has its zone file.
if [ -z "${TZ:-}" ]; then
  case "${` + openshell.EnvHostTimeZone + `:-}" in
    ""|/*|*..*|*[!A-Za-z0-9_+/-]*) ;;
    *)
      if [ -f "/usr/share/zoneinfo/$` + openshell.EnvHostTimeZone + `" ]; then
        TZ="$` + openshell.EnvHostTimeZone + `"
        export TZ
      fi
      ;;
  esac
fi
`

// shimPathScript puts ShimDir first on PATH, once.
const shimPathScript = `case ":${PATH:-}:" in
  *:` + ShimDir + `:*) ;;
  *) PATH="` + ShimDir + `${PATH:+:$PATH}"; export PATH ;;
esac
`

// profile is the login-shell profile fragment: the egress proxy, the shim
// directory first on PATH, and for bash (outside POSIX mode, which refuses
// command names like cursor-agent as function names) an exported function
// of the harness command's name, which survives a later PATH reset and
// reaches child bash shells. The launchers run under bash -p, which imports
// no functions.
func (s *Spec) profile() string {
	return `# defenseclaw-sandbox-profile v1
# DefenseClaw sandbox shell environment (OpenShell sandbox images,
# root-owned). Login shells get the egress proxy settings and the time zone
# every harness launcher exports, and the harness command starts its
# launcher.
` + egressEnvScript + timeZoneScript + shimPathScript + `if [ -n "${BASH_VERSION:-}" ] && ! shopt -oq posix 2>/dev/null; then
  eval '` + s.Command + `() { ` + s.ShimPath() + ` "$@"; }; export -f ` + s.Command + `' 2>/dev/null || true
fi
`
}

var sandboxEnvLauncher = `#!/bin/bash -p
# defenseclaw-sandbox-env v1
# DefenseClaw sandbox command environment (OpenShell sandbox images,
# root-owned). ` + "`defenseclaw-gateway sandbox exec`" + ` starts every command through
# it: OpenShell runs those without a login shell, so this gives them the
# environment the harness launchers set up (system directories first on
# PATH, the egress proxy, the harness shim) and execs the command without
# the shell start-up variables.
set -u
if [ "$#" -eq 0 ]; then
  echo "usage: sandbox-env COMMAND [ARGUMENT]..." >&2
  exit 2
fi
` + launcherPreamble + shimPathScript + `# What a command started through sandbox exec leaves running (a server
# started on purpose) is its own: the supervisor leaves it, and names what
# of it holds the terminal's session, and so a --tty exec, open.
dc_keep_leftovers=1
dc_say_kept=1
` + launcherExec(`"$@"`)

// supervisorScript is the Python supervisor that resumes a stopped harness.
// See launcherJobControl for when it runs.
const supervisorScript = `#!` + SupervisorInterpreter + ` -I -S
"""DefenseClaw sandbox harness supervisor for terminal sessions.

The sandbox's seccomp filter (OpenShell 0.1.1) blocks kill() when the target
is a process group (negative pid or zero): a TUI that suspends itself on
Ctrl-Z cannot stop, and a job-control shell in the sandbox cannot resume a
stopped job (its fg uses killpg). This supervisor forks the harness into its
own process group, makes it the terminal's foreground group, and resumes it
when it stops or when its suspend failed, and tells the user that
suspending is not available. When the harness exits, it ends what the
harness left running (see Leftovers).

This supervisor is invoked only when stdin/stdout/stderr are a terminal whose
foreground process group is the launcher's (checked in the launcher shell
code). For headless runs the launcher execs the harness directly.

It finds group members by scanning /proc and signals each pid individually.
"""

import os
import signal
import sys
import time

# Signal handling: ignore job-control signals for the supervisor itself.
signal.signal(signal.SIGTTOU, signal.SIG_IGN)
signal.signal(signal.SIGTTIN, signal.SIG_IGN)
signal.signal(signal.SIGTSTP, signal.SIG_IGN)

# Parse arguments: [--keep-leftovers [--say-kept]] command [arg...].
# --keep-leftovers leaves what the command started running after it exits
# (see Leftovers); --say-kept also names what of it stays in the terminal's
# session (see Kept).
args = sys.argv[1:]
keep_leftovers = args[:1] == ['--keep-leftovers']
if keep_leftovers:
    args = args[1:]
say_kept_on = keep_leftovers and args[:1] == ['--say-kept']
if say_kept_on:
    args = args[1:]
if not args:
    sys.exit(2)

command = args
child_pid = None
child_pgrp = None


def find_pgrp_members(pgrp):
    """Find all PIDs in the given process group by scanning /proc."""
    members = []
    try:
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            try:
                with open(f'/proc/{entry}/stat', 'r') as f:
                    stat = f.read()
                    # Format: pid (comm) state ppid pgrp ...
                    # Find the comm part (enclosed in parentheses) and skip it.
                    close_paren = stat.rfind(')')
                    if close_paren == -1:
                        continue
                    # After the comm: state, ppid, pgrp, ...
                    fields = stat[close_paren + 2:].split()
                    if len(fields) < 3:
                        continue
                    pid_pgrp = int(fields[2])
                    if pid_pgrp == pgrp:
                        members.append(int(entry))
            except (IOError, OSError, ValueError):
                # Process may have exited or we can't read it.
                continue
    except (IOError, OSError):
        pass
    return members


def send_signal_to_group(pgrp, sig):
    """Send signal to all members of a process group (individual kill calls).

    The group's leader, the harness itself, is always signalled first."""
    members = find_pgrp_members(pgrp)
    for pid in [pgrp] + [p for p in members if p != pgrp]:
        try:
            os.kill(pid, sig)
        except (OSError, ProcessLookupError):
            # Process exited between listing and signaling.
            pass


def forward_signal(signum, frame):
    """Forward SIGHUP and SIGTERM to the child and its group."""
    if child_pgrp is not None:
        send_signal_to_group(child_pgrp, signum)


signal.signal(signal.SIGHUP, forward_signal)
signal.signal(signal.SIGTERM, forward_signal)

# Leftovers. A harness that exits while a command it started still runs
# (OpenCode quitting in the middle of a tool call, a background job) would
# leave that command changing the sandbox after the session ended, while
# DefenseClaw pulls or reviews its work. The supervisor is a child subreaper
# (prctl), so whatever the harness started whose parent exits is re-parented
# to the supervisor, not to the sandbox's init: once the harness is gone,
# what still runs below the supervisor is the session's own (and the
# supervisor collects what of it ends meanwhile, on SIGCHLD). Where prctl is
# refused, the supervisor records what runs below the harness every
# SCAN_EVERY seconds instead (pid and start time, so a reused pid is not
# taken for it). When the harness exits, the leftovers get LEFTOVER_GRACE
# seconds to end on their own (a hook sending its last event and its one
# retry), then SIGTERM, and SIGKILL LEFTOVER_TERM seconds later, each pid
# signalled on its own; the terminal says what was ended. Nothing outside
# the harness's tree is signalled: the sandbox's supervisor and other
# sessions are not below it.
PR_SET_CHILD_SUBREAPER = 36
SCAN_EVERY = 1.0
LEFTOVER_GRACE = 2.0
LEFTOVER_TERM = 2.0
LEFTOVER_KILL = 1.0

subreaper = False
# adopted_ended: a child ended (SIGCHLD), maybe one the supervisor adopted.
adopted_ended = False
# tracked: pid -> start time of what ran below the harness (no subreaper).
tracked = {}


def become_subreaper():
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except Exception:
        return False


def child_ended(signum, frame):
    global adopted_ended
    adopted_ended = True


def process_table():
    """pid -> (state, ppid, start time) of every process /proc lists."""
    table = {}
    try:
        entries = os.listdir('/proc')
    except OSError:
        return table
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f'/proc/{entry}/stat', 'r') as f:
                stat = f.read()
            # After the comm: state, ppid, ...; the start time is field 22.
            fields = stat[stat.rindex(')') + 2:].split()
            table[int(entry)] = (fields[0], int(fields[1]), fields[19])
        except (OSError, ValueError, IndexError):
            continue
    return table


def below(table, roots):
    """The processes in table that descend from any of roots."""
    children = {}
    for pid, (_, ppid, _) in table.items():
        children.setdefault(ppid, []).append(pid)
    found = set()
    todo = list(roots)
    while todo:
        for pid in children.get(todo.pop(), ()):
            if pid not in found:
                found.add(pid)
                todo.append(pid)
    return found


def scan():
    """While the harness runs: collect adopted leftovers that ended, or
    without the subreaper, record what runs below the harness."""
    table = process_table()
    if subreaper:
        me = os.getpid()
        for pid, (state, ppid, _) in table.items():
            if ppid == me and pid != child_pid and state == 'Z':
                try:
                    os.waitpid(pid, os.WNOHANG)
                except OSError:
                    pass
        return
    for pid, start in list(tracked.items()):
        if table.get(pid, (None, None, None))[2] != start:
            del tracked[pid]
    for pid in below(table, [child_pid]):
        tracked[pid] = table[pid][2]


def leftovers():
    """pid -> ppid of what the harness left running."""
    table = process_table()
    me = os.getpid()
    roots = {pid for pid, start in tracked.items() if table.get(pid, (None, None, None))[2] == start}
    found = (below(table, roots | {me}) | roots) - {me}
    return {pid: table[pid][1] for pid in found if table[pid][0] not in ('Z', 'X')}


def reap():
    """Collect the supervisor's children that ended (the harness is gone)."""
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except OSError:
            return
        if pid == 0:
            return


def settle(seconds):
    """Wait up to seconds for the leftovers to end; what still runs."""
    deadline = time.monotonic() + seconds
    while True:
        reap()
        left = leftovers()
        if not left or time.monotonic() >= deadline:
            return left
        time.sleep(0.1)


def command_text(pid):
    """A leftover as the notice names it: a shell's -c script, else its
    command line, with every unprintable character shown as '?'."""
    try:
        with open(f'/proc/{pid}/cmdline', 'rb') as f:
            argv = f.read().split(b'\0')
    except OSError:
        argv = []
    while argv and argv[-1] == b'':
        argv.pop()
    if len(argv) >= 3 and argv[1] == b'-c' and os.path.basename(argv[0]) in (b'sh', b'bash', b'dash', b'zsh'):
        argv = [argv[2]]
    text = ''.join(c if c.isprintable() else '?' for c in b' '.join(argv).decode('utf-8', 'replace'))
    if not text:
        text = f'pid {pid}'
    return text if len(text) <= 60 else text[:59] + '…'


def end_leftovers():
    """End what the harness left running (see Leftovers) and say so."""
    left = settle(LEFTOVER_GRACE)
    if not left:
        return
    roots = sorted(pid for pid, ppid in left.items() if ppid not in left)
    shown = [command_text(pid) for pid in roots[:3]]
    if len(roots) > 3:
        shown.append(f'(+{len(roots) - 3} more)')
    for sig, wait in ((signal.SIGTERM, LEFTOVER_TERM), (signal.SIGKILL, LEFTOVER_KILL)):
        for pid in left:
            try:
                os.kill(pid, sig)
                if sig == signal.SIGTERM:
                    os.kill(pid, signal.SIGCONT)
            except OSError:
                pass
        left = settle(wait)
        if not left:
            break
    one = len(roots) == 1
    text = f'defenseclaw: the harness exited with {len(roots)} command{"" if one else "s"} still running in the sandbox; '
    if left:
        text += f'{"it" if one else "not all of them"} could not be ended, so the session\'s work may still change: '
    else:
        text += f'ended {"it" if one else "them"}, so the session\'s work is final: '
    try:
        os.write(2, b'\r\n' + (text + '; '.join(shown)).encode('utf-8', 'replace') + b'\r\n')
    except OSError:
        pass


# Kept. What a sandbox exec command leaves running stays (a server started
# on purpose), but while it runs in the terminal's session OpenShell 0.1.1
# holds the --tty exec open, for about 30 seconds, and then ends it with
# status 74 and no word (a nohup'd process: the exit's SIGHUP does not end
# it). So with --say-kept the supervisor names what of the session still
# runs once the exit's SIGHUP had KEPT_WAIT seconds to act.
KEPT_WAIT = 0.5


def in_session():
    """pid -> ppid of what runs in the supervisor's session besides the
    supervisor and the processes above it (the exec's own shells)."""
    try:
        sid = os.getsid(0)
        entries = os.listdir('/proc')
    except OSError:
        return {}
    info = {}
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f'/proc/{entry}/stat', 'r') as f:
                stat = f.read()
            # After the comm: state, ppid, pgrp, session, ...
            fields = stat[stat.rindex(')') + 2:].split()
            info[int(entry)] = (fields[0], int(fields[1]), int(fields[3]))
        except (OSError, ValueError, IndexError):
            continue
    me = os.getpid()
    above = set()
    pid = os.getppid()
    while pid > 1 and pid in info and pid not in above:
        above.add(pid)
        pid = info[pid][1]
    return {pid: ppid for pid, (state, ppid, session) in info.items()
            if session == sid and pid != me and pid not in above and state not in ('Z', 'X')}


def say_kept():
    """Name what the command left running in the terminal's session."""
    deadline = time.monotonic() + KEPT_WAIT
    while True:
        left = in_session()
        if not left or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    if not left:
        return
    roots = sorted(pid for pid, ppid in left.items() if ppid not in left)
    shown = [command_text(pid) for pid in roots[:3]]
    if len(roots) > 3:
        shown.append(f'(+{len(roots) - 3} more)')
    one = len(roots) == 1
    text = (f'defenseclaw: the command left {len(roots)} process{"" if one else "es"} running in the sandbox: ' +
            '; '.join(shown) + f'. {"It keeps" if one else "They keep"} running, and OpenShell keeps this --tty exec '
            f'open while {"it does" if one else "they do"}, for up to about 30 seconds (then status 74); '
            'without --tty the exec returns at once.')
    try:
        os.write(2, b'\r\n' + text.encode('utf-8', 'replace') + b'\r\n')
    except OSError:
        pass


if not keep_leftovers:
    subreaper = become_subreaper()
    if subreaper:
        signal.signal(signal.SIGCHLD, child_ended)

# Fork the harness.
child_pid = os.fork()
if child_pid == 0:
    # Child: create a new process group and become the terminal's foreground group.
    try:
        os.setpgid(0, 0)

        # Make this process group the terminal's foreground group (fd 0;
        # /dev/tty cannot be opened in the sandbox). SIGTTOU is still
        # ignored here, so the call cannot stop the new background group.
        os.tcsetpgrp(0, os.getpgrp())

        # Restore default signal handlers for job-control signals.
        signal.signal(signal.SIGTTOU, signal.SIG_DFL)
        signal.signal(signal.SIGTTIN, signal.SIG_DFL)
        signal.signal(signal.SIGTSTP, signal.SIG_DFL)

        # Exec the harness.
        os.execvp(command[0], command)
    except Exception as e:
        sys.stderr.write(f"dc_supervisor: child setup failed: {e}\n")
        sys.exit(1)

# Parent: set the child's process group too, whichever runs first. The
# group's ID is the child's PID either way.
child_pgrp = child_pid
try:
    os.setpgid(child_pid, child_pid)
except (OSError, ProcessLookupError):
    # The child already set it, or has exec'd.
    pass

# A TUI that suspends itself restores the terminal (canonical mode) and
# signals its process group, then waits for SIGCONT to take the terminal
# back. The sandbox refuses a kill() aimed at a process group, so on
# OpenShell that signal fails, nothing stops, and the harness waits for a
# SIGCONT forever. The supervisor therefore also watches the terminal: when
# the harness, as the terminal's foreground group, left raw mode for
# canonical mode and stays there for SUSPEND_WAIT seconds, it is treated as
# suspended and resumed. It arms again only once the terminal is raw again.
SUSPEND_WAIT = 0.5
POLL = 0.2


def terminal_canonical():
    """Whether the terminal on fd 0 is in canonical (cooked) mode."""
    try:
        import termios
        return bool(termios.tcgetattr(0)[3] & termios.ICANON)
    except Exception:
        return None


def harness_owns_terminal():
    try:
        return os.tcgetpgrp(0) == child_pgrp
    except OSError:
        return False


# NOTICE is what the terminal shows when a suspend was turned into a resume.
# It answers the harness's own "suspended, use fg" line, which the harness
# prints itself.
NOTICE = (b"\r\ndefenseclaw: Ctrl-Z cannot suspend a harness in an OpenShell sandbox "
          b"(the sandbox refuses the signal): it keeps running, and there is nothing "
          b"to bring back with fg.\r\n")

# TITLE says the same at once, while the harness's TUI owns the screen: in
# the terminal's title and as a desktop notification (OSC 9, where the
# terminal has them), which leave the screen alone. The title the session
# had comes back when the harness exits.
TITLE = b"[defenseclaw] Ctrl-Z cannot suspend a harness in an OpenShell sandbox: it keeps running"

# explain_at_exit: a harness whose own suspend failed took the terminal back
# after the supervisor's SIGCONT, so it had been waiting to be resumed; the
# title says so at once and the notice follows its exit, when its TUI no
# longer owns the screen. A TUI that restores the terminal only to shut
# down never takes it back, and gets neither.
explain_at_exit = False
titled = False


def notice():
    try:
        os.write(2, NOTICE)
    except OSError:
        pass


def notice_now():
    """Say it in the title (kept to restore at exit) and as a notification,
    and ring the bell (the harness may take the title back at once), as a
    DefenseClaw session's own notices do."""
    global titled
    seq = b"" if titled else b"\x1b[22;0t"
    seq += b"\x1b]2;" + TITLE + b"\x07\x1b]9;DefenseClaw: " + TITLE[len(b"[defenseclaw] "):] + b"\x07\x07"
    try:
        os.write(2, seq)
        titled = True
    except OSError:
        pass


def finish(status):
    """Exit with the harness's status once it ended."""
    # What it left in its group gets the SIGHUP a session leader's exit
    # would send its foreground group.
    send_signal_to_group(child_pgrp, signal.SIGHUP)
    send_signal_to_group(child_pgrp, signal.SIGCONT)
    if not keep_leftovers:
        end_leftovers()
    elif say_kept_on:
        say_kept()
    # Try to give the terminal back to the supervisor's group.
    try:
        os.tcsetpgrp(0, os.getpgrp())
    except OSError:
        pass
    if titled:
        try:
            os.write(2, b"\x1b[23;0t")
        except OSError:
            pass
    if explain_at_exit:
        notice()
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    sys.exit(128 + os.WTERMSIG(status))


armed = False       # the harness had the terminal in raw mode
cooked_since = None  # when it went back to canonical mode
woken = False        # a SIGCONT went to a harness that seemed suspended
next_scan = 0.0      # when scan() runs next

# Main loop: wait for the child to stop or exit, and watch the terminal.
while True:
    try:
        pid, status = os.waitpid(child_pid, os.WUNTRACED | os.WNOHANG)
    except ChildProcessError:
        # Child is gone.
        sys.exit(1)

    if pid == child_pid and (os.WIFEXITED(status) or os.WIFSIGNALED(status)):
        finish(status)

    if pid == child_pid and os.WIFSTOPPED(status):
        # Child stopped (SIGTSTP, SIGTTIN, SIGTTOU, or SIGSTOP).
        # Re-assert that the child's group is the terminal's foreground group.
        try:
            os.tcsetpgrp(0, child_pgrp)
        except OSError:
            pass
        # Say why it keeps running, then send SIGCONT to the child and all
        # members of its process group.
        notice()
        send_signal_to_group(child_pgrp, signal.SIGCONT)
        armed, cooked_since = False, None
        continue

    canonical = terminal_canonical()
    if canonical is False and harness_owns_terminal():
        if woken:
            explain_at_exit, woken = True, False
            notice_now()
        armed, cooked_since = True, None
    elif canonical and armed and harness_owns_terminal():
        now = time.monotonic()
        if cooked_since is None:
            cooked_since = now
        elif now - cooked_since >= SUSPEND_WAIT:
            send_signal_to_group(child_pgrp, signal.SIGCONT)
            armed, cooked_since, woken = False, None, True
    if subreaper and adopted_ended:
        adopted_ended = False
        scan()
    elif not subreaper and not keep_leftovers and time.monotonic() >= next_scan:
        next_scan = time.monotonic() + SCAN_EVERY
        scan()
    time.sleep(POLL)
`

// ShellFiles are the root-owned files every overlay image carries next to
// the launcher: the login-shell profile fragment, the `sandbox exec` command
// wrapper, the harness command's shim, and the supervisor that resumes a
// stopped harness.
func (s *Spec) ShellFiles() []connector.SandboxFile {
	return []connector.SandboxFile{
		{Path: SandboxProfilePath, Mode: 0o644, Owner: connector.SandboxOwnerRoot, Data: []byte(s.profile())},
		{Path: SandboxEnvPath, Mode: 0o755, Owner: connector.SandboxOwnerRoot, Data: []byte(sandboxEnvLauncher)},
		{Path: s.ShimPath(), Mode: 0o755, Owner: connector.SandboxOwnerRoot, Data: []byte(s.shim())},
		{Path: SupervisorPath, Mode: 0o755, Owner: connector.SandboxOwnerRoot, Data: []byte(supervisorScript)},
	}
}

// ShimPath is the shim of the harness command.
func (s *Spec) ShimPath() string { return ShimDir + "/" + s.Command }

func (s *Spec) shim() string {
	return "#!/bin/sh\n# defenseclaw-sandbox-shim v1\n# Starts " + s.DisplayName +
		" through its DefenseClaw launcher (OpenShell sandbox images, root-owned).\nexec " +
		s.LauncherPath() + " \"$@\"\n"
}
