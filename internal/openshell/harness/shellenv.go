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
# root-owned). Login shells get the egress proxy settings every harness
# launcher exports, and the harness command starts its launcher.
` + egressEnvScript + shimPathScript + `if [ -n "${BASH_VERSION:-}" ] && ! shopt -oq posix 2>/dev/null; then
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
` + launcherPreamble + shimPathScript + launcherExec(`"$@"`)

// supervisorScript is the Python supervisor that resumes a stopped harness.
// See launcherJobControl for when it runs.
const supervisorScript = `#!/usr/bin/python3 -I -S
"""DefenseClaw sandbox harness supervisor for terminal sessions.

The sandbox's seccomp filter (OpenShell 0.1.1) blocks kill() when the target
is a process group (negative pid or zero): a TUI that suspends itself on
Ctrl-Z cannot stop, and a job-control shell in the sandbox cannot resume a
stopped job (its fg uses killpg). This supervisor forks the harness into its
own process group, makes it the terminal's foreground group, and resumes it
when it stops or when its suspend failed, and tells the user that
suspending is not available.

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

# Parse arguments: command and its args.
if len(sys.argv) < 2:
    sys.exit(2)

command = sys.argv[1:]
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
NOTICE = (b"\r\ndefenseclaw: Ctrl-Z cannot suspend a harness in an OpenShell sandbox "
          b"(the sandbox refuses the signal); it keeps running.\r\n")

# explain_at_exit: a harness whose own suspend failed took the terminal back
# after the supervisor's SIGCONT, so it had been waiting to be resumed; the
# notice follows its exit, when its TUI no longer owns the screen. A TUI
# that restores the terminal only to shut down never takes it back, and
# gets no notice.
explain_at_exit = False


def notice():
    try:
        os.write(2, NOTICE)
    except OSError:
        pass


def finish(status):
    """Exit with the harness's status once it ended."""
    # What it left in its group gets the SIGHUP a session leader's exit
    # would send its foreground group.
    send_signal_to_group(child_pgrp, signal.SIGHUP)
    send_signal_to_group(child_pgrp, signal.SIGCONT)
    # Try to give the terminal back to the supervisor's group.
    try:
        os.tcsetpgrp(0, os.getpgrp())
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
        armed, cooked_since = True, None
    elif canonical and armed and harness_owns_terminal():
        now = time.monotonic()
        if cooked_since is None:
            cooked_since = now
        elif now - cooked_since >= SUSPEND_WAIT:
            send_signal_to_group(child_pgrp, signal.SIGCONT)
            armed, cooked_since, woken = False, None, True
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
