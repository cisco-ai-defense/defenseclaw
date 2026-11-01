// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// stderrStreamer answers every non-interactive invocation with a fixed
// standard error and exit status.
type stderrStreamer struct {
	stderr string
	stdout string
	code   int
}

func (s stderrStreamer) Stream(_ context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if inv.Interactive {
		return -1, io.ErrUnexpectedEOF
	}
	_, _ = io.WriteString(stdout, s.stdout)
	_, _ = io.WriteString(stderr, s.stderr)
	return s.code, nil
}

// rawTransportTrace is what the OpenShell command printed when its gateway
// had just been killed (rel-1-0-4 GAP-2437 evidence, rel-1-0-6 GAP-0340).
const rawTransportTrace = "Error:   \u00d7 transport error\n  \u251c\u2500\u25b6 tcp connect error\n  \u251c\u2500\u25b6 tcp connect error\n  \u2570\u2500\u25b6 Connection refused (os error 111)\n\n"

// GAP-0340 (the GAP-0186 class): `sandbox exec` right after the OpenShell
// gateway was killed printed the OpenShell command's transport trace. It now
// says that the gateway is not answering, that the sandbox is not changed, and
// what to do; the command's own lines still reach the person.
func TestExecWordsAnOpenShellGatewayThatDoesNotAnswer(t *testing.T) {
	for _, managed := range []bool{false, true} {
		name := map[bool]string{false: "per-user", true: "managed"}[managed]
		t.Run(name, func(t *testing.T) {
			ta := newTestApp(t, "", sampleSandbox("box"))
			ta.IO.TTY = false
			if managed {
				ta.daemon.status.Managed = &sandboxapi.ManagedStatus{Profile: "eng", RequestAccess: "it-security@example.com"}
			}
			ta.Streamer = stderrStreamer{stderr: "build: warning kept\n" + rawTransportTrace, code: 1}
			wantExit(t, ta.Exec(bg, ExecOptions{Name: "box", Command: []string{"true"}}), 1)
			all := ta.output() + ta.err.String()
			has(t, all, "the OpenShell gateway of your sandboxes is not answering", "so the command did not run in box",
				"box itself is not changed", "run the command again", "defenseclaw sandbox doctor", "build: warning kept")
			lacks(t, all, "transport error", "tcp connect", "Connection refused", "os error", "\u2570")
			if managed {
				has(t, all, "your organization's sandbox service starts it again", "If it lasts, tell IT: it-security@example.com")
			} else {
				lacks(t, all, "your organization")
			}
		})
	}
}

// The filter holds back only the connect failure of a command that failed: a
// command that succeeded, or one whose own output has other lines, is shown
// as it wrote it.
func TestExecKeepsOutputThatIsNotAGatewayFailure(t *testing.T) {
	ta := newTestApp(t, "", sampleSandbox("box"))
	ta.IO.TTY = false
	ta.Streamer = stderrStreamer{stderr: "Error: no such file or directory\nsecond line\n", stdout: "out\n", code: 2}
	wantExit(t, ta.Exec(bg, ExecOptions{Name: "box", Command: []string{"cat", "x"}}), 2)
	all := ta.output() + ta.err.String()
	has(t, all, "Error: no such file or directory", "second line", "out")
	lacks(t, all, "OpenShell gateway of your sandboxes is not answering")
	// A held block of a command that exited 0 is written back unchanged.
	ta = newTestApp(t, "", sampleSandbox("box"))
	ta.IO.TTY = false
	ta.Streamer = stderrStreamer{stderr: rawTransportTrace, code: 0}
	ta.ok(t, ta.Exec(bg, ExecOptions{Name: "box", Command: []string{"true"}}))
	has(t, ta.output()+ta.err.String(), "transport error", "Connection refused")
}

func TestGatewayLostFilterHandlesSplitWrites(t *testing.T) {
	var out strings.Builder
	f := newGatewayLostFilter(&out)
	for _, chunk := range []string{"keep 1\nErr", "or:   \u00d7 transport er", "ror\n  \u2570\u2500\u25b6 Connection refused (os er", "ror 111)\n\nkeep 2"} {
		if _, err := f.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if !f.finish(1) {
		t.Fatal("the connect failure was not recognised")
	}
	if got := out.String(); got != "keep 1\nkeep 2" {
		t.Fatalf("passed through %q, want only the command's own lines", got)
	}
}
