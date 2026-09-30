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

package sandboxcli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Ending a `sandbox exec` client does not stop its command: OpenShell 0.1.1
// leaves a command running when its exec stream ends (see openshell.Exec).
// So `sandbox exec` starts the command under a session shell whose argv
// carries a session id (execSessionArgv), and when the client is told to end
// (untilTerminated) it runs reapScript in the sandbox, which stops that
// shell and every process below it. The mark is in argv, not in the
// environment: a sandbox process cannot read another exec's
// /proc/<pid>/environ (Yama ptrace_scope 1), but it can read its cmdline and
// status and signal it.

// execSessionMark prefixes the session id in the session shell's argv.
const execSessionMark = "defenseclaw-exec-"

// execSessionShell runs the command as a child (not by exec, so the shell
// and its mark stay) and exits with its status. With a terminal, Ctrl-C,
// Ctrl-\ and Ctrl-Z reach every process of the foreground group, the shell
// included: it catches them with a no-op (a caught signal, unlike an
// ignored one, is back to its default in the command), so only the command
// decides what they mean.
const execSessionShell = `trap : INT QUIT TSTP; "$@"; exit $?`

// execSessionArgv is command under the session shell of session.
func execSessionArgv(session string, command []string) []string {
	return append([]string{"/bin/sh", "-c", execSessionShell, execSessionMark + session}, command...)
}

// reapTimeout bounds the exec that stops a terminated session's processes.
const reapTimeout = 30 * time.Second

// reapScript stops the session shell whose argv carries
// defenseclaw-exec-$1 ($1: the session id, 32 hex digits) and every process
// below it, found by parent links: SIGTERM, then SIGKILL for what is left
// after five seconds. It runs as the sandbox user, so it reaches that user's
// processes only, and its own argv does not carry the mark.
const reapScript = `PATH=/usr/bin:/bin
case "$1" in ''|*[!0-9a-f]*) exit 2 ;; esac
mark="` + execSessionMark + `$1"
pids=""
for p in /proc/[0-9]*; do
  pid="${p#/proc/}"
  [ "$pid" = "$$" ] && continue
  hit="$(tr '\0' '\n' <"$p/cmdline" 2>/dev/null | while IFS= read -r arg; do [ "$arg" = "$mark" ] && echo y; done)"
  [ -n "$hit" ] && pids="$pids $pid"
done
[ -n "$pids" ] || exit 0
while :; do
  added=""
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    case " $pids " in *" $pid "*) continue ;; esac
    ppid="$(sed -n 's/^PPid:[[:space:]]*//p' "$p/status" 2>/dev/null)"
    [ -n "$ppid" ] || continue
    case " $pids " in *" $ppid "*) added="$added $pid" ;; esac
  done
  [ -n "$added" ] || break
  pids="$pids$added"
done
kill -TERM $pids 2>/dev/null
for i in 1 2 3 4 5; do
  alive=""
  for pid in $pids; do
    kill -0 "$pid" 2>/dev/null && ! grep -q '^State:[[:space:]]*Z' "/proc/$pid/status" 2>/dev/null && alive="$alive $pid"
  done
  [ -n "$alive" ] || exit 0
  pids="$alive"
  sleep 1
done
kill -KILL $pids 2>/dev/null
exit 0
`

// newExecSession returns a fresh session id.
func newExecSession() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// reapExec stops what a terminated `sandbox exec` session left running in
// the sandbox (reapScript). It reports nothing but a failure to stop it.
func (a *App) reapExec(ctx context.Context, cli openshell.CLI, sandbox, session string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reapTimeout)
	defer cancel()
	inv, err := cli.Exec(sandbox, []string{"/bin/sh", "-c", reapScript, "defenseclaw-reap", session},
		openshell.CLIExecOptions{Timeout: reapTimeout})
	if err == nil {
		var code int
		if code, err = a.Streamer.Stream(ctx, inv, io.Discard, io.Discard); err == nil && code != 0 {
			err = &ExitError{Code: code}
		}
	}
	if err != nil {
		a.warn("the command may still run in " + sandbox + " (" + err.Error() + "); stop it with `" + CommandName + " stop " + sandbox + "`")
	}
}

// untilTerminated derives a context that ends when this process is told
// to end (terminationSignals: a hangup or SIGTERM, and without a terminal
// the interrupt the terminal sends the whole job), so the caller can clean
// up before it exits. stop releases the signals (a later one takes its
// default action again) and returns the one that ended the context, nil
// when none did.
func untilTerminated(ctx context.Context, interactive bool) (context.Context, func() os.Signal) {
	ctx, cancel := context.WithCancel(ctx)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, terminationSignals(interactive)...)
	var (
		mu  sync.Mutex
		got os.Signal
	)
	done := make(chan struct{})
	go func() {
		select {
		case s := <-ch:
			mu.Lock()
			got = s
			mu.Unlock()
			cancel()
		case <-done:
		}
	}()
	var once sync.Once
	return ctx, func() os.Signal {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
			cancel()
		})
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}
