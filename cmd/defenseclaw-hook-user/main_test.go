// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPerUserNativeCursorImportTwin(t *testing.T) {
	if !cursorEvent(strings.NewReader(`{"cursor_version":"1","tool_input":{"command":"echo ok"}}`)) {
		t.Fatal("Cursor import marker was missed")
	}
	if cursorEvent(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_input":{"command":"echo ok"}}`)) {
		t.Fatal("Claude Code event was identified as Cursor")
	}
}

func TestGAP0322MissingGuardFallbackAndOrdinaryTwin(t *testing.T) {
	account := t.TempDir()
	bin := filepath.Join(account, ".local", "bin")
	home := filepath.Join(account, ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	for _, dir := range []string{bin, hooks} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self := filepath.Join(bin, "defenseclaw-hook-user")
	guard := filepath.Join(bin, "defenseclaw-hook-post")
	if err := os.WriteFile(self, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hook-claudecode.token"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var reply atomic.Value
	reply.Store(`{"action":"block","reason":"policy"}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, reply.Load().(string))
	}))
	defer server.Close()
	args := []string{"fallback-guard-user-hook", guard, "hook", "--connector", "claudecode", "--hook-home", home,
		"--api-addr", strings.TrimPrefix(server.URL, "http://")}
	payload := `{"hook_event_name":"PreToolUse","session_id":"session","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	for _, tc := range []struct {
		name, response string
		want           int
	}{
		{"protected", `{"action":"block","reason":"policy"}`, 2},
		{"ordinary", `{"action":"allow"}`, 0},
	} {
		reply.Store(tc.response)
		var out, errOut bytes.Buffer
		if got := runFallbackGuardAt(self, args, strings.NewReader(payload), &out, &errOut, time.Now()); got != tc.want {
			t.Fatalf("%s: exit %d, want %d; stdout %q, stderr %q", tc.name, got, tc.want, out.String(), errOut.String())
		}
	}
	if err := os.WriteFile(guard, []byte("#!/bin/sh\n[ \"$1\" = --guard-user-hook-capability ] || exit 1\nprintf 'defenseclaw-hook-post guard-user-hook v1\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if got := runFallbackGuardAt(self, args, strings.NewReader(payload), &out, &errOut, time.Now()); got != 0 || out.Len() != 0 {
		t.Fatalf("present guard: exit %d, stdout %q, stderr %q", got, out.String(), errOut.String())
	}
	if err := os.WriteFile(guard, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reply.Store(`{"action":"block","reason":"policy"}`)
	out.Reset()
	errOut.Reset()
	if got := runFallbackGuardAt(self, args, strings.NewReader(payload), &out, &errOut, time.Now()); got != 2 {
		t.Fatalf("unavailable guard: exit %d, stdout %q, stderr %q", got, out.String(), errOut.String())
	}
	alias := filepath.Join(filepath.Dir(account), "alias")
	if err := os.Symlink(account, alias); err != nil {
		t.Fatal(err)
	}
	if !sameExecutable(self, filepath.Join(alias, ".local", "bin", "defenseclaw-hook-user")) {
		t.Fatal("account alias does not resolve to the installed native hook")
	}
	args[1] = filepath.Join(bin, "other")
	if got := runFallbackGuardAt(self, args, strings.NewReader(payload), &out, &errOut, time.Now()); got != 2 {
		t.Fatalf("other guard path: exit %d", got)
	}
}

func TestGAP0322StaleGuardFallbackAndOrdinaryTwin(t *testing.T) {
	account := t.TempDir()
	bin := filepath.Join(account, ".local", "bin")
	home := filepath.Join(account, ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	for _, dir := range []string{bin, hooks} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	self := filepath.Join(bin, "defenseclaw-hook-user")
	guard := filepath.Join(bin, "defenseclaw-hook-post")
	if err := os.WriteFile(self, []byte("fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stale := "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'defenseclaw-hook-post version old'; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(guard, []byte(stale), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hook-claudecode.token"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	var reply atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, reply.Load().(string))
	}))
	defer server.Close()
	args := []string{"fallback-guard-user-hook", guard, "hook", "--connector", "claudecode", "--hook-home", home,
		"--api-addr", strings.TrimPrefix(server.URL, "http://")}
	payload := `{"hook_event_name":"PreToolUse","session_id":"session","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	for _, tc := range []struct {
		name, response string
		want           int
	}{
		{"protected", `{"action":"block","reason":"policy"}`, 2},
		{"ordinary", `{"action":"allow"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply.Store(tc.response)
			requests.Store(0)
			var out, errOut bytes.Buffer
			if got := runFallbackGuardAt(self, args, strings.NewReader(payload), &out, &errOut, time.Now()); got != tc.want || requests.Load() != 1 {
				t.Fatalf("exit %d, requests %d, stdout %q, stderr %q", got, requests.Load(), out.String(), errOut.String())
			}
		})
	}
}
