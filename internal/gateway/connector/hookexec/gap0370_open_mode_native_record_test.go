package hookexec

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGAP0370OpenModeNativeDeadlineRecordMatchesDelivery(t *testing.T) {
	for _, tc := range []struct{ connector, event string }{
		{"hermes", "pre_tool_call"},
		{"copilot", "preToolUse"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			home := t.TempDir()
			if err := os.Mkdir(filepath.Join(home, "logs"), 0o700); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			type result struct {
				code             int
				out              string
				ordinary, marker []byte
			}
			exited := make(chan result, 1)
			opts := withDefaults(Options{
				Connector: tc.connector, Home: home, Event: tc.event, FailMode: "open",
				Stdout: &output, Stderr: io.Discard,
				Exit: func(code int) {
					ordinary, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
					marker, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.dropped"))
					exited <- result{code, output.String(), ordinary, marker}
				},
			})
			opts.failurePayload = []byte(`{"session_id":"s","tool_call_id":"open-mode-deadline"}`)
			deadline := time.Now().Add(450 * time.Millisecond)
			startAnswerWatchdog(&opts, specs[tc.connector], "open", deadline, deadline)
			select {
			case got := <-exited:
				wantNative := []byte(`"action":"block"`)
				if tc.connector == "copilot" {
					wantNative = []byte(`"permissionDecision":"deny"`)
				}
				blocked := bytes.Contains([]byte(got.out), wantNative)
				line := got.ordinary
				if bytes.HasPrefix(got.marker, []byte("DCID")) {
					line = got.marker[4:]
				}
				if len(line) == 0 {
					t.Fatal("native answer has no local record")
				}
				var entry hookFailureEntry
				if err := json.Unmarshal(line, &entry); err != nil {
					t.Fatal(err)
				}
				wantOutcome, wantMode := "fail_open", "open"
				if blocked {
					wantOutcome, wantMode = "fail_closed", "closed"
				}
				if entry.Outcome != wantOutcome || entry.FailMode != wantMode {
					t.Fatalf("native answer block=%t recorded as %+v", blocked, entry)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("watchdog did not exit")
			}
		})
	}
}
