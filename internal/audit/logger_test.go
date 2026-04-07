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

package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
)

func TestInferTargetType(t *testing.T) {
	tests := []struct {
		scanner string
		want    string
	}{
		{"skill-scanner", "skill"},
		{"skill_scanner", "skill"},
		{"mcp-scanner", "mcp"},
		{"mcp_scanner", "mcp"},
		{"codeguard", "code"},
		{"aibom", "code"},
		{"aibom-claw", "code"},
		{"clawshield-vuln", "code"},
		{"clawshield-secrets", "code"},
		{"clawshield-pii", "code"},
		{"clawshield-malware", "code"},
		{"clawshield-injection", "code"},
		{"future-scanner", "unknown"},
		{"", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.scanner, func(t *testing.T) {
			if got := inferTargetType(tt.scanner); got != tt.want {
				t.Errorf("inferTargetType(%q) = %q, want %q", tt.scanner, got, tt.want)
			}
		})
	}
}

func TestInferAssetTypeFromAction(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		details string
		want    string
	}{
		{"mcp action", "mcp-block", "", "mcp"},
		{"mcp in details", "block", "type=mcp reason=test", "mcp"},
		{"skill action", "skill-install", "", "skill"},
		{"skill in details", "install-clean", "type=skill scanner=x", "skill"},
		{"default to skill", "block", "reason=test", "skill"},
		{"watcher-block skill", "watcher-block", "type=skill reason=x", "skill"},
		{"watcher-block mcp", "watcher-block", "type=mcp reason=x", "mcp"},
		{"empty action", "", "", "skill"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := inferAssetTypeFromAction(tt.action, tt.details); got != tt.want {
				t.Errorf("inferAssetTypeFromAction(%q, %q) = %q, want %q",
					tt.action, tt.details, got, tt.want)
			}
		})
	}
}

func TestContains(t *testing.T) {
	tests := []struct {
		s, substr string
		want      bool
	}{
		{"hello world", "world", true},
		{"hello", "hello", true},
		{"hello", "xyz", false},
		{"", "", true},
		{"hello", "", true},
		{"", "x", false},
		{"type=skill scanner=x", "type=skill", true},
		{"type=mcp", "type=skill", false},
	}
	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			if got := contains(tt.s, tt.substr); got != tt.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}

func TestLoggerLogActionIncludesRunID(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "logger-run-id")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	logger := NewLogger(store)
	if err := logger.LogAction("skill-block", "test-skill", "reason=test"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if got := events[0].RunID; got != "logger-run-id" {
		t.Fatalf("RunID = %q, want %q", got, "logger-run-id")
	}
}

func TestLoggerSplunkForwardingIncludesDefaultedFields(t *testing.T) {
	t.Setenv("DEFENSECLAW_RUN_ID", "logger-splunk-run-id")

	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	var payload []byte
	forwarder := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		payload = append([]byte(nil), body...)
		w.WriteHeader(http.StatusOK)
	})

	logger := NewLogger(store)
	logger.SetSplunkForwarder(forwarder)
	if err := logger.LogAction("skill-block", "test-skill", "reason=test"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}
	logger.Close()

	lines := bytes.Split(bytes.TrimSpace(payload), []byte{'\n'})
	if len(lines) != 1 {
		t.Fatalf("expected 1 forwarded event, got %d", len(lines))
	}

	var env struct {
		Event struct {
			ID     string `json:"id"`
			Actor  string `json:"actor"`
			RunID  string `json:"run_id"`
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"event"`
	}
	if err := json.Unmarshal(lines[0], &env); err != nil {
		t.Fatalf("Unmarshal forwarded payload: %v", err)
	}

	if env.Event.ID == "" {
		t.Fatal("forwarded event id was empty")
	}
	if env.Event.Actor != "defenseclaw" {
		t.Fatalf("forwarded actor = %q, want %q", env.Event.Actor, "defenseclaw")
	}
	if env.Event.RunID != "logger-splunk-run-id" {
		t.Fatalf("forwarded run_id = %q, want %q", env.Event.RunID, "logger-splunk-run-id")
	}
	if env.Event.Action != "skill-block" || env.Event.Target != "test-skill" {
		t.Fatalf("forwarded event mismatch: %+v", env.Event)
	}
}

func TestLoggerSplunkFlushesWatchStartImmediately(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	var payload []byte
	forwarder := testSplunkForwarder(t, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		body, _ := io.ReadAll(r.Body)
		payload = append([]byte(nil), body...)
		w.WriteHeader(http.StatusOK)
	})
	forwarder.cfg.BatchSize = 50

	logger := NewLogger(store)
	logger.SetSplunkForwarder(forwarder)
	if err := logger.LogAction("watch-start", "", "dirs=3 debounce=500ms"); err != nil {
		t.Fatalf("LogAction: %v", err)
	}

	if len(bytes.TrimSpace(payload)) == 0 {
		t.Fatal("expected watch-start to flush to Splunk immediately")
	}
}
