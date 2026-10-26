// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Per-user OpenCode hooks close on outages even when an earlier install
// requested open. Neither DEFENSECLAW_FAIL_MODE nor strict availability can
// reopen a closed hook. HTTP 503 is an outage too.
func TestOpenCodePluginTakesItsInstalledModeAndStrictAvailability(t *testing.T) {
	nodeForTest(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := listener.Addr().String()
	_ = listener.Close()
	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unavailable.Close)
	outages := map[string]string{"unreachable": unreachable, "http503": strings.TrimPrefix(unavailable.URL, "http://")}
	dataDir := testenv.PrivateTempDir(t)
	token := filepath.Join(dataDir, "hooks", ".hook-opencode.token")
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for outage, addr := range outages {
		for _, tc := range []struct {
			installed, strict, envMode string
			wantBlock                  bool
		}{
			{"open", "", "", true},
			{"open", "1", "", true},
			{"open", "yes", "", true},
			{"open", "", "closed", true},
			{"open", "1", "open", true},
			{"closed", "", "open", true},
			{"closed", "", "", true},
		} {
			t.Run(outage+"/"+tc.installed+"/strict="+tc.strict+"/env="+tc.envMode, func(t *testing.T) {
				t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", tc.strict)
				t.Setenv("DEFENSECLAW_FAIL_MODE", tc.envMode)
				lines := runOpenCodePluginHarness(t, templateData{
					APIAddr:     addr,
					TokenFileJS: javaScriptStringContent(token),
					FailMode:    tc.installed,
				}, 1)
				if len(lines) == 0 {
					t.Fatal("no verdict")
				}
				if blocked := strings.HasPrefix(lines[0], "block:"); blocked != tc.wantBlock {
					t.Fatalf("verdict %q, want blocked=%v", lines[0], tc.wantBlock)
				}
			})
		}
	}
}

func TestManagedOpenCodeHonorsExplicitAdminOpenDuringOutage(t *testing.T) {
	nodeForTest(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := listener.Addr().String()
	_ = listener.Close()
	dataDir := testenv.PrivateTempDir(t)
	token := filepath.Join(dataDir, ".hook-opencode.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		mode, strict string
		blocked      bool
	}{
		{"closed", "", true},
		{"open", "", false},
		{"open", "1", true},
	} {
		t.Run(tc.mode+"/strict="+tc.strict, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", tc.strict)
			lines := runOpenCodePluginHarness(t, templateData{
				APIAddr: unreachable, TokenFileJS: javaScriptStringContent(token),
				Managed: true, FailMode: tc.mode,
			}, 1)
			if len(lines) == 0 || strings.HasPrefix(lines[0], "block:") != tc.blocked {
				t.Fatalf("managed mode %s strict %s verdict %q, want blocked=%v", tc.mode, tc.strict, lines, tc.blocked)
			}
		})
	}
}
