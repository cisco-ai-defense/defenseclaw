// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"reflect"
	"strings"
	"testing"
)

func TestCoworkSessionFromEnv(t *testing.T) {
	env := map[string]string{
		CoworkEnvFlag:               "1",
		CoworkEnvSessionID:          "c29dbbfa-8209-4e91-84c4-7191c9491c94",
		CoworkEnvWorkspaceHostPaths: `["/Users/alice/Desktop/project"]`,
	}
	got, ok := CoworkSessionFromEnv(func(k string) string { return env[k] })
	want := CoworkContext{SessionID: "c29dbbfa-8209-4e91-84c4-7191c9491c94", WorkspaceHostPaths: []string{"/Users/alice/Desktop/project"}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("CoworkSessionFromEnv = %+v, %v; want %+v", got, ok, want)
	}
	for _, flag := range []string{"", "0", "true", "yes", "11"} {
		env[CoworkEnvFlag] = flag
		if _, ok := CoworkSessionFromEnv(func(k string) string { return env[k] }); ok {
			t.Errorf("%s=%q marked a Cowork session; only 1 does", CoworkEnvFlag, flag)
		}
	}
	if _, ok := CoworkSessionFromEnv(nil); ok {
		t.Error("a nil environment marked a Cowork session")
	}
}

func TestParseCoworkWorkspaceHostPaths(t *testing.T) {
	long := "/" + strings.Repeat("a", maxCoworkWorkspacePathBytes)
	cases := []struct {
		name, raw string
		want      []string
	}{
		{"json array", `["/Users/a/Desktop/x","/Users/a/Documents/y"]`, []string{"/Users/a/Desktop/x", "/Users/a/Documents/y"}},
		{"single path", "/Users/a/Desktop/x", []string{"/Users/a/Desktop/x"}},
		{"colon list", "/Users/a/x:/Users/a/y", []string{"/Users/a/x", "/Users/a/y"}},
		{"newline list", "/Users/a/x\n/Users/a/y\n", []string{"/Users/a/x", "/Users/a/y"}},
		{"windows semicolon list", `C:\Users\a\x;C:\Users\a\y`, []string{`C:\Users\a\x`, `C:\Users\a\y`}},
		{"windows single path", `C:\Users\a\Desktop`, []string{`C:\Users\a\Desktop`}},
		{"unc path", `\\server\share\dir`, []string{`\\server\share\dir`}},
		{"relative paths dropped", `["x","/ok","../y"]`, []string{"/ok"}},
		{"duplicates dropped", `["/ok","/ok"]`, []string{"/ok"}},
		{"control characters dropped", "[\"/bad\\u0007\",\"/ok\"]", []string{"/ok"}},
		{"oversized path dropped", `["` + long + `","/ok"]`, []string{"/ok"}},
		{"malformed json", `["/ok"`, nil},
		{"trailing json", `["/ok"] []`, nil},
		{"empty", "  ", nil},
	}
	for _, tc := range cases {
		if got := ParseCoworkWorkspaceHostPaths(tc.raw); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: ParseCoworkWorkspaceHostPaths(%q) = %q, want %q", tc.name, tc.raw, got, tc.want)
		}
	}
	var many []string
	for i := 0; i < maxCoworkWorkspacePaths+4; i++ {
		many = append(many, "/p/"+strings.Repeat("x", i+1))
	}
	if got := boundedCoworkPaths(many); len(got) != maxCoworkWorkspacePaths {
		t.Errorf("bounded paths = %d, want %d", len(got), maxCoworkWorkspacePaths)
	}
}

func TestCoworkHeaderRoundTrip(t *testing.T) {
	in := CoworkContext{SessionID: "s-1", WorkspaceHostPaths: []string{"/Users/a/Desktop/x", "relative"}}
	got, ok := ParseCoworkHeader(in.HeaderValue())
	want := CoworkContext{SessionID: "s-1", WorkspaceHostPaths: []string{"/Users/a/Desktop/x"}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %+v, %v; want %+v", got, ok, want)
	}
	for _, bad := range []string{"", "x", `{"session_id":"s","extra":1}`, `{"session_id":"s"} {}`, `[]`, "{" + strings.Repeat(" ", maxCoworkHeaderBytes) + "}"} {
		if _, ok := ParseCoworkHeader(bad); ok {
			t.Errorf("ParseCoworkHeader(%.40q) accepted", bad)
		}
	}
	// A session ID outside the identifier alphabet is dropped, not rewritten.
	if got, ok := ParseCoworkHeader(`{"session_id":"a b"}`); !ok || got.SessionID != "" {
		t.Errorf("session id with a space = %+v, %v; want accepted with no session id", got, ok)
	}
}

// The hook sends the Cowork context only on the claudecode route.
func TestCoworkHeaderSentOnlyForClaudeCode(t *testing.T) {
	cowork := &CoworkContext{SessionID: "s-1", WorkspaceHostPaths: []string{"/Users/a/Desktop/x"}}
	r := run(t, "claudecode", ok(`{"action":"allow"}`), func(opts *Options) { opts.Cowork = cowork })
	got, parsed := ParseCoworkHeader(r.rt.gotReq.Header.Get(CoworkHeader))
	if !parsed || !reflect.DeepEqual(got, *cowork) {
		t.Fatalf("%s = %q, want %+v", CoworkHeader, r.rt.gotReq.Header.Get(CoworkHeader), *cowork)
	}
	r = run(t, "claudecode", ok(`{"action":"allow"}`), nil)
	if v := r.rt.gotReq.Header.Get(CoworkHeader); v != "" {
		t.Fatalf("a call outside Cowork sent %s=%q", CoworkHeader, v)
	}
	r = run(t, "codex", ok(`{"action":"allow"}`), func(opts *Options) { opts.Cowork = cowork })
	if v := r.rt.gotReq.Header.Get(CoworkHeader); v != "" {
		t.Fatalf("a codex call sent %s=%q", CoworkHeader, v)
	}
}
