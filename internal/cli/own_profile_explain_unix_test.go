// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// GAP-0431, GAP-0422: a standard user of a managed Linux or macOS computer
// could not explain their own guardrail profile: the launcher refused
// `guardrail profile explain` and profile-explain answered
// elevation_required. Both now ask the gateway on the hook socket, which
// explains its kernel-verified caller only; another account is refused.
func TestStandardUserExplainsOwnGuardrailProfile(t *testing.T) {
	previousExplain, previousSocket := ownProfileExplain, ownProfileExplainSocket
	t.Cleanup(func() { ownProfileExplain, ownProfileExplainSocket = previousExplain, previousSocket })
	ownProfileExplainSocket = func() string { return "/run/defenseclaw/hook.sock" }
	var asked []string
	ownProfileExplain = func(_ context.Context, socket, user, connectorName, agent string) (int, []byte, error) {
		asked = append(asked, socket+"|"+user+"|"+connectorName)
		if user != "" && user != "r106eu1" {
			return http.StatusForbidden, []byte(`{"error":"own_profile_only","message":"you can explain only your own guardrail profile"}`), nil
		}
		return http.StatusOK, []byte(`{"own":true,"profile":"engineering","subject":{"user_id":"5001"}}`), nil
	}
	if !launcherOffers([]string{"guardrail", "profile", "explain", "--connector", "codex"}) || launcherOffers([]string{"guardrail", "status"}) {
		t.Fatal("the launcher must offer guardrail profile explain and nothing else of the guardrail tree")
	}
	var ran []string
	root := launcherTestRoot(&ran)
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	if code := executeLauncher(context.Background(), root, []string{"guardrail", "profile", "explain", "--connector", "codex"}); code != 0 {
		t.Fatalf("launcher explain exit %d, stderr %q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"profile": "engineering"`) || len(asked) != 1 || asked[0] != "/run/defenseclaw/hook.sock||codex" {
		t.Fatalf("launcher explain printed %q after asking %v", stdout.String(), asked)
	}

	refusal := errors.New("an administrator runs it: `sudo defenseclaw-gateway enterprise linux profile-explain`")
	stdout.Reset()
	if err := explainOwnGuardrailProfile(root, "r106eu1", "codex", "", refusal, refusal, true); err != nil || !strings.Contains(stdout.String(), "engineering") {
		t.Fatalf("own explain by name = %v, printed %q", err, stdout.String())
	}
	stdout.Reset()
	err := explainOwnGuardrailProfile(root, "someone-else", "codex", "", refusal, refusal, true)
	if err == nil || !strings.Contains(stdout.String(), "elevation_required") || !strings.Contains(stdout.String(), "only your own") ||
		strings.Contains(stdout.String(), "engineering") {
		t.Fatalf("explain of another account = %v, printed %q; want the own-only refusal", err, stdout.String())
	}
}
