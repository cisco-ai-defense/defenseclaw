// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestEnterpriseManagedAllNativeConnectorsDefaultOpen(t *testing.T) {
	for _, name := range []string{"amp", "claudecode", "codex", "cursor", "copilot", "geminicli", "antigravity", "hermes", "windsurf", "openhands"} {
		t.Run(name, func(t *testing.T) {
			stageTrustedNativeHookForTest(t, "closed")
			t.Setenv("DEFENSECLAW_FAIL_MODE", "closed")
			t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "1")
			runtimeHome := filepath.Join(t.TempDir(), ".defenseclaw")
			stubEnterpriseManagedRuntimeResolver(t, func(_, gotName string) (enterprisehooks.WindowsManagedHookRuntime, error) {
				if gotName != name {
					t.Fatalf("resolver connector=%q, want %q", gotName, name)
				}
				return enterprisehooks.WindowsManagedHookRuntime{
					Connector: name, DataDir: runtimeHome, PolicyActive: true, Registered: true,
					GatewayAddr: "127.0.0.1:18977", GatewayServiceName: "DefenseClawGateway",
					ScopedToken: "authenticated-test-token", GenerationID: "0123456789abcdef0123456789abcdef",
				}, nil
			})
			if enterpriseManagedHookRuntimeNoop(name) {
				t.Fatal("active managed runtime was treated as a no-op")
			}
			opts := buildHookOptionsForRuntime(name, "PreToolUse", "127.0.0.1:1", "closed", true)
			if opts.Connector != name || !opts.ManagedEnterprise || opts.FailMode != "open" || opts.StrictAvailability {
				t.Fatalf("managed connector options lost uniform open default: %+v", opts)
			}
			if opts.APIAddr != "127.0.0.1:18977" || opts.AuthenticatedManagedToken == nil || *opts.AuthenticatedManagedToken != "authenticated-test-token" {
				t.Fatal("protected endpoint or authenticated snapshot was not preserved")
			}
		})
	}
}

func TestEnterpriseManagedRejectedCodexRuntimeAllowsWithoutGatewayContact(t *testing.T) {
	stageTrustedNativeHookForTest(t, "closed")
	stubEnterpriseManagedRuntimeResolver(t, func(_, _ string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{Connector: "codex", PolicyActive: true}, errors.New("invalid managed state")
	})
	if enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("runtime rejection must retain a diagnostic")
	}
	opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
	if opts.ManagedRuntimeFailure == "" || opts.Home != "" || opts.AuthenticatedManagedToken != nil {
		t.Fatal("invalid runtime selected untrusted state")
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(503) }))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	opts.APIAddr = strings.TrimPrefix(server.URL, "http://")
	opts.Home = t.TempDir()
	opts.HTTPClient = server.Client()
	opts.Stdin = strings.NewReader(`{"tool_name":"exec_command"}`)
	opts.Stdout, opts.Stderr = &stdout, &stderr
	code := hookexec.Run(context.Background(), opts)
	if code != 0 || requests != 0 || stdout.Len() != 0 {
		t.Fatalf("rejected runtime result: exit=%d requests=%d stdout=%q stderr=%q", code, requests, stdout.String(), stderr.String())
	}
}
