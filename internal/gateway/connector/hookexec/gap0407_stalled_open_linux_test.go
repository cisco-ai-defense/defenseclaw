//go:build linux

package hookexec

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A balanced per-user call can start a fail-open missing-token log, then hit
// its answer deadline while that log append stalls. The watchdog delivers
// its fail-closed answer; the fallback record must describe that delivery.
func TestGAP0407StalledOpenFailureKeepsDeliveredAnswer(t *testing.T) {
	shortAnswerBudget(t, 450*time.Millisecond)
	shortAnswerFloor(t)
	var stdout bytes.Buffer
	var logPath string
	type exitResult struct {
		code   int
		out    string
		marker []byte
	}
	exited := make(chan exitResult, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		_ = run(t, "claudecode", nil, func(o *Options) {
			o.FailMode = "open"
			o.StartedAt = time.Now()
			o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","session_id":"review-session","tool_name":"Bash","tool_use_id":"review-missing-token","tool_input":{"command":"echo ok"}}`)
			o.Stdout = &stdout
			if err := os.Remove(filepath.Join(o.HookDir, ".token")); err != nil {
				t.Error(err)
			}
			logPath = filepath.Join(o.Home, "logs", "hook-failures.jsonl")
			if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
				t.Error(err)
			}
			if err := syscall.Mkfifo(logPath, 0o600); err != nil {
				t.Error(err)
			}
			o.Exit = func(code int) {
				marker, _ := os.ReadFile(filepath.Join(o.Home, "logs", "hook-failures.dropped"))
				exited <- exitResult{code: code, out: stdout.String(), marker: marker}
			}
		})
	}()
	defer func() {
		if logPath != "" {
			reader, _ := os.OpenFile(logPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
			if reader != nil {
				defer reader.Close()
			}
		}
		select {
		case <-returned:
		case <-time.After(3 * time.Second):
			t.Error("hook did not finish after the stalled log was released")
		}
	}()
	select {
	case got := <-exited:
		if !claudeBlocked(runResult{code: got.code, stdout: got.out}) {
			t.Fatalf("watchdog did not deliver a block: code=%d", got.code)
		}
		if !bytes.Contains(got.marker, []byte(`"tool_id":"review-missing-token"`)) ||
			!bytes.Contains(got.marker, []byte(`"outcome":"fail_closed"`)) {
			t.Fatalf("denied call has no per-ID block record: marker=%s", got.marker)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watchdog did not exit at its answer deadline")
	}
}

func TestGAP0407QuickOpenFailureStaysAllowed(t *testing.T) {
	shortAnswerBudget(t, 450*time.Millisecond)
	shortAnswerFloor(t)
	var home string
	result := run(t, "claudecode", nil, func(o *Options) {
		o.FailMode = "open"
		o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","session_id":"review-session","tool_name":"Bash","tool_use_id":"review-allowed","tool_input":{"command":"echo ok"}}`)
		if err := os.Remove(filepath.Join(o.HookDir, ".token")); err != nil {
			t.Fatal(err)
		}
		home = o.Home
	})
	if claudeBlocked(result) {
		t.Fatalf("ordinary open-mode missing-token call was blocked: code=%d", result.code)
	}
	line, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line, []byte(`"outcome":"fail_open"`)) ||
		!bytes.Contains(line, []byte(`"tool_id":"review-allowed"`)) {
		t.Fatalf("allowed call lost its open audit line: %s", line)
	}
}
