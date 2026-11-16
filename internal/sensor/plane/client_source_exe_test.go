// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientSourcesPreserveExecutablePath(t *testing.T) {
	for _, tc := range []struct {
		name, path string
	}{
		{"client", "/Users/dev/.local/bin/claude"},
		{"other program", "/Users/dev/bin/tool"},
	} {
		t.Run("macOS/"+tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"event_type": 9,
				"process":    map[string]any{"audit_token": map[string]any{"pid": 42}, "ppid": 1},
				"event": map[string]any{"exec": map[string]any{
					"target": map[string]any{"audit_token": map[string]any{"pid": 42}, "executable": map[string]any{
						"path": tc.path, "stat": map[string]any{
							"st_dev": 7, "st_ino": 42, "st_size": 9, "st_ctimespec": "2026-10-28T00:54:28.816014709Z",
						},
					}},
					"args": []string{"claude", "--mcp-config", "config.json"},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			var message esMessage
			if err := json.Unmarshal(raw, &message); err != nil {
				t.Fatal(err)
			}
			event, ok := translateES(message, nil, nil)
			if !ok || event.Exe != tc.path {
				t.Fatalf("decoded image = %q, decoded = %t", event.Exe, ok)
			}
			// The exec-time stat darwinClientImage binds the hashed file to.
			var payload esEvent
			if err := json.Unmarshal(message.Event, &payload); err != nil {
				t.Fatal(err)
			}
			if stat := payload.Exec.Target.Executable.Stat; stat.Dev != 7 || stat.Ino != 42 || stat.Size != 9 ||
				stat.Changed != "2026-10-28T00:54:28.816014709Z" {
				t.Fatalf("exec-time stat = %+v", stat)
			}
		})
	}
	t.Run("macOS/truncated path", func(t *testing.T) {
		var message esMessage
		if err := json.Unmarshal([]byte(`{"event_type":9,"process":{"audit_token":{"pid":42},"ppid":1},"event":{"exec":{"target":{"audit_token":{"pid":42},"executable":{"path":"/Users/dev/.local/bin/claude","path_truncated":true,"stat":{"st_dev":7,"st_ino":42}}}}}}`), &message); err != nil {
			t.Fatal(err)
		}
		event, ok := translateES(message, nil, nil)
		if !ok || event.Exe != "" {
			t.Fatalf("truncated image path = %q, decoded = %t", event.Exe, ok)
		}
	})
	for _, tc := range []struct {
		name, path string
	}{
		{"client", `C:\Tools\claude.exe`},
		{"other program", `C:\Tools\tool.exe`},
	} {
		t.Run("Windows/"+tc.name, func(t *testing.T) {
			raw := `<Event><System><EventID>4688</EventID></System><EventData>` +
				`<Data Name="NewProcessId">0x2a</Data><Data Name="NewProcessName">` + tc.path +
				`</Data><Data Name="CommandLine">claude.exe --mcp-config config.json</Data></EventData></Event>`
			record, err := decodeSecurityXML(raw)
			if err != nil {
				t.Fatal(err)
			}
			event, ok := translateSecurityRecord(record)
			if !ok || event.Exe != tc.path {
				t.Fatalf("decoded executable path = %q, decoded = %t", event.Exe, ok)
			}
		})
	}
}

// The Windows reader reads a client image's identity when it reads the
// process-creation record, at the record's exec path and time, so the event
// carries it whether or not the process is still running.
func TestSecurityReaderReadsTheExecImageWithTheRecord(t *testing.T) {
	log := &fakeSecurityLog{lineage: []fakeSecurityRecord{{id: 1, xml: `<Event><System><EventID>4688</EventID>` +
		`<EventRecordID>1</EventRecordID><TimeCreated SystemTime="2026-11-04T03:00:00.5Z"/></System><EventData>` +
		`<Data Name="NewProcessId">0x2a</Data><Data Name="ProcessId">0x4</Data>` +
		`<Data Name="NewProcessName">C:\Users\alice\.local\bin\claude.exe</Data>` +
		`<Data Name="CommandLine">claude.exe --mcp-config config.json</Data></EventData></Event>`}}}
	buffer := NewBuffer()
	reader := newSecurityReader(log.open, buffer, 0)
	var path string
	var at time.Time
	reader.image = func(p string, t time.Time, _ string) (string, string) {
		path, at = p, t
		return "digest", "2.1.317"
	}
	if err := reader.openAll(); err != nil {
		t.Fatal(err)
	}
	reader.pollOnce()
	event := <-buffer.Events()
	if event.ImageSHA256 != "digest" || event.ImageVersion != "2.1.317" ||
		path != `C:\Users\alice\.local\bin\claude.exe` || !at.Equal(time.Date(2026, 11, 4, 3, 0, 0, 5e8, time.UTC)) {
		t.Fatalf("image identity = %q %q, read %q at %v", event.ImageSHA256, event.ImageVersion, path, at)
	}
}

// claude.exe names release 2.1.312 as ProductVersion 2.1.312.0 (dc-win2).
func TestWindowsReleaseVersionFromProductVersion(t *testing.T) {
	for product, want := range map[string]string{
		"2.1.312.0": "2.1.312", "2.1.312": "2.1.312", "2.1.312.7": "2.1.312.7", "": "",
	} {
		if got := windowsReleaseVersion(product); got != want || IsClaudeReleaseVersion(got) != (want == "2.1.312") {
			t.Errorf("windowsReleaseVersion(%q) = %q, want %q", product, got, want)
		}
	}
}

// Each account has its own hash-queue slot: one account's pending hash does
// not take another's (Windows keys accounts by SID).
func TestClientImageHashBudgetIsPerAccount(t *testing.T) {
	hasher := newImageHasher()
	release := make(chan struct{})
	hasher.hash = func(*os.File, int64, time.Time) (string, error) {
		<-release
		return "sum", nil
	}
	defer func() {
		close(release)
		hasher.idle()
	}()
	queue := func(name, account string) {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		key, ok := statImageKey(file)
		if !ok {
			t.Skip("no image key on this volume")
		}
		hasher.digestOf(file, key, account, nil)
	}
	queue("a1", "sid:S-1-5-21-1-1001")
	queue("a2", "sid:S-1-5-21-1-1001")
	queue("b1", "sid:S-1-5-21-1-1002")
	hasher.mu.Lock()
	defer hasher.mu.Unlock()
	if hasher.perAccount["sid:S-1-5-21-1-1001"] != 1 || hasher.perAccount["sid:S-1-5-21-1-1002"] != 1 || len(hasher.pending) != 2 {
		t.Fatalf("queued per account = %v (%d pending), want one each", hasher.perAccount, len(hasher.pending))
	}
}
