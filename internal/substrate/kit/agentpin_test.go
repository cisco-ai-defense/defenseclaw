// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
)

// GAP-0114: the actor image's Claude Code is the kit's pin, new enough for
// Haiku 5.5 and covered by a reviewed hook contract.
func TestClaudeCodePin(t *testing.T) {
	r := AgentReleases["claudecode"]
	if !versionAtLeast(r.Version, ClaudeCodeHaiku55MinVersion) {
		t.Fatalf("pinned %s is older than %s", r.Version, ClaudeCodeHaiku55MinVersion)
	}
	res := connector.ResolveSandboxHookContract("claudecode", r.Version)
	if res.Status != connector.HookCompatibilityKnown || res.Contract.ContractID != "claudecode-hooks-v2" {
		t.Fatalf("hook contract for %s: %+v", r.Version, res)
	}
	if AgentVersion("claudecode", harness.ClaudeCode.DefaultVersion) != r.Version || AgentVersion("codex", "0.146.0") != "0.146.0" {
		t.Fatal("AgentVersion")
	}
	if claudeCodeDefaultModel(AgentVersion("claudecode", harness.ClaudeCode.DefaultVersion)) != ClaudeCodeBedrockModel {
		t.Fatal("the pinned build does not get Haiku 5.5")
	}
	for _, a := range []string{"amd64", "arm64"} {
		if len(r.SHA256[a]) != 64 || !strings.HasPrefix(r.URL(a), "https://downloads.claude.ai/claude-code-releases/"+r.Version+"/linux-") {
			t.Fatalf("%s: %q %q", a, r.SHA256[a], r.URL(a))
		}
	}
	s := AgentInstallScript("claudecode")
	for _, want := range []string{r.SHA256["amd64"], r.SHA256["arm64"], "sha256sum -c", "--proto '=https'", r.Path, "[ \"$got\" = " + r.Version + " ]"} {
		if !strings.Contains(s, want) {
			t.Errorf("install script lacks %q", want)
		}
	}
	if AgentInstallScript("codex") != "" {
		t.Fatal("codex has no pin")
	}
	art, err := SubstrateArtifacts(harness.ClaudeCode.Provider, r.Version, DefaultConfig())
	if err != nil || art.HookContract != "claudecode-hooks-v2" {
		t.Fatalf("render %v %s", err, art.HookContract)
	}
}

func TestFetchAgentChecksTheChecksum(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "not claude") }))
	defer srv.Close()
	saved := AgentReleases["claudecode"]
	defer func() { AgentReleases["claudecode"] = saved }()
	r := saved
	r.URL = func(string) string { return srv.URL }
	AgentReleases["claudecode"] = r
	if _, err := FetchAgent(context.Background(), srv.Client(), "claudecode", "amd64"); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a wrong binary was accepted: %v", err)
	}
	if _, err := FetchAgent(context.Background(), srv.Client(), "claudecode", "riscv64"); err == nil {
		t.Fatal("an architecture without a pin was accepted")
	}
	if b, err := FetchAgent(context.Background(), nil, "codex", "amd64"); b != nil || err != nil {
		t.Fatal("a connector without a pin")
	}
}
