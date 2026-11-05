//go:build linux

package hookexec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The ordinary log is absent when the preparer looks. A stalled marker
// descriptor must not prevent the ordinary logger from creating the row.
func TestGAP0407MarkerStallKeepsOrdinaryBlockRecord(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := int(writer.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{'x'}, 4096)
	for {
		_, err := syscall.Write(fd, chunk)
		if errors.Is(err, syscall.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	logDir := filepath.Join(home, "logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	previous := openHookFailureLog
	openHookFailureLog = func(path string, flag int, perm os.FileMode) (*os.File, error) {
		if strings.HasSuffix(path, "hook-failures.dropped") {
			return writer, nil
		}
		return previous(path, flag, perm)
	}
	defer func() { openHookFailureLog = previous }()

	type result struct {
		code    int
		elapsed time.Duration
		out     string
		line    []byte
	}
	var output bytes.Buffer
	exited := make(chan result, 1)
	start := time.Now()
	opts := withDefaults(Options{
		Home: home, Event: "PreToolUse", FailMode: "closed",
		Stdout: &output, Stderr: io.Discard,
		Exit: func(code int) {
			line, _ := os.ReadFile(filepath.Join(logDir, "hook-failures.jsonl"))
			exited <- result{code, time.Since(start), output.String(), line}
		},
	})
	opts.failurePayload = []byte(`{"session_id":"s","tool_use_id":"marker-stall-record"}`)
	w := startAnswerWatchdog(&opts, specs["claudecode"], "closed", start.Add(450*time.Millisecond), start.Add(450*time.Millisecond))
	var got result
	select {
	case got = <-exited:
	case <-time.After(900 * time.Millisecond):
		reader.Close()
		t.Fatal("hook did not exit within budget")
	}
	reader.Close() // release any pending marker write before returning
	w.failureLog.mu.Lock()
	w.failureLog.mu.Unlock()
	if !claudeBlocked(runResult{code: got.code, stdout: got.out}) {
		t.Fatalf("hook answer was not a block: code=%d out=%q", got.code, got.out)
	}
	if !bytes.Contains(got.line, []byte(`"tool_id":"marker-stall-record"`)) ||
		!bytes.Contains(got.line, []byte(`"outcome":"fail_closed"`)) {
		t.Fatalf("blocked call left no ordinary decision record at exit: elapsed=%v line=%q", got.elapsed, got.line)
	}
}
