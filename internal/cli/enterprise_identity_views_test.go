// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A managed host has no Python CLI: `enterprise <platform> profile-explain`
// asks the managed gateway for the same answer as `defenseclaw guardrail
// profile explain` (GAP-0022, GAP-0023).
func TestEnterpriseProfileExplainReadsTheManagedGateway(t *testing.T) {
	previous := enterpriseIdentityViewGet
	t.Cleanup(func() { enterpriseIdentityViewGet = previous })
	var asked string
	enterpriseIdentityViewGet = func(path string, out any) (string, error) {
		asked = path
		return "127.0.0.1:18970", json.Unmarshal([]byte(`{"profile":"ml-team","match":"group"}`), out)
	}
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	cmd := newEnterpriseIdentityViewCommand(platform, enterpriseIdentityViews[0])
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--user", "alice@corp.example", "--connector", "codex"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if asked != "/api/v1/guardrail/profiles/resolve?connector=codex&user=alice%40corp.example" {
		t.Fatalf("asked the gateway for %q", asked)
	}
	if out.String() != "{\n  \"profile\": \"ml-team\",\n  \"match\": \"group\"\n}\n" {
		t.Fatalf("printed %q", out.String())
	}
}

func TestEnterpriseAgentIdentitiesRejectsUnknownAccount(t *testing.T) {
	previous := enterpriseIdentityViewGet
	t.Cleanup(func() { enterpriseIdentityViewGet = previous })
	enterpriseIdentityViewGet = func(path string, out any) (string, error) {
		if strings.HasPrefix(path, "/api/v1/guardrail/profiles/resolve?") {
			return "", json.Unmarshal([]byte(`{"lookup_error":"no account named \"nosuchuser99\" on this host; check the current spelling with getent passwd or use the account uid","subject":{"user_id":""}}`), out)
		}
		t.Fatalf("unexpected request: %s", path)
		return "", nil
	}
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	cmd := newEnterpriseIdentityViewCommand(platform, enterpriseIdentityViews[1])
	cmd.SetArgs([]string{"--user", "nosuchuser99"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "no account named") || commandExitCode(err) != enterprisestatus.InvalidArgsExitCode(runtime.GOOS) {
		t.Fatalf("agent identities error = %v", err)
	}
}

func TestEnterpriseProfileExplainRequiresUserForAgent(t *testing.T) {
	previous := enterpriseIdentityViewGet
	t.Cleanup(func() { enterpriseIdentityViewGet = previous })
	enterpriseIdentityViewGet = func(_ string, out any) (string, error) { return "", json.Unmarshal([]byte("{}"), out) }
	platform := runtime.GOOS
	if platform == "darwin" {
		platform = "macos"
	}
	cmd := newEnterpriseIdentityViewCommand(platform, enterpriseIdentityViews[0])
	cmd.SetArgs([]string{"--agent", "agt-0123456789abcdef"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("an agent alone was silently ignored")
	}
}
