// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// missingClientStreamer cannot run the OpenShell command at all, as when
// the account's copy is gone: exec's own "executable file not found".
type missingClientStreamer struct{ inner *fakeStreamer }

func (s missingClientStreamer) Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if !inv.Interactive {
		s.inner.timeline.add(execStep(inv.Argv))
		return -1, &exec.Error{Name: "openshell", Err: exec.ErrNotFound}
	}
	return s.inner.Stream(ctx, inv, stdout, stderr)
}

// GAP-0196: after the administrator switched the sandbox setup away and
// back, the account's OpenShell copy was missing for a moment; connect
// printed Go's exec error and stopped the sandbox it had just started. It
// now says in plain words what is missing and what to do, with the
// contact on a managed computer, and the sandbox keeps running.
func TestConnectWithoutTheOpenShellCommandKeepsTheSandboxAndSaysWhatToDo(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(map[bool]string{false: "per-user", true: "managed"}[managed], func(t *testing.T) {
			connectWithoutTheOpenShellCommand(t, managed)
		})
	}
}

func connectWithoutTheOpenShellCommand(t *testing.T, managed bool) {
	ta := newTestApp(t, "s\n", copySandbox("copybox"))
	if managed {
		ta.daemon.status.Managed = &sandboxapi.ManagedStatus{Profile: "eng", RequestAccess: "it-security@example.com"}
	}
	ta.daemon.edit("copybox", func(sb *sandboxapi.Sandbox) { sb.Phase = "stopped" })
	ta.Streamer = missingClientStreamer{inner: ta.stream}
	err := ta.Connect(bg, ConnectOptions{Name: "copybox"})
	if err == nil {
		t.Fatal("connect without the OpenShell command succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"the OpenShell command that reaches your sandboxes is not installed for your account right now", "copybox keeps running", "sandbox doctor"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("refusal %q lacks %q", msg, want)
		}
	}
	for _, raw := range []string{"executable file not found", "exec:", "$PATH"} {
		if strings.Contains(msg, raw) {
			t.Fatalf("raw Go text reached the person: %q", msg)
		}
	}
	if managed && !strings.Contains(msg, "it-security@example.com") {
		t.Fatalf("managed refusal %q lacks the organization's contact", msg)
	}
	lacks(t, ta.output(), "stopped copybox after the failure")
	ta.daemon.mu.Lock()
	calls := append([]call(nil), ta.daemon.calls...)
	ta.daemon.mu.Unlock()
	for _, c := range calls {
		if strings.HasSuffix(c.Path, "/stop") {
			t.Fatalf("the sandbox was stopped: %s %s", c.Method, c.Path)
		}
	}
}
