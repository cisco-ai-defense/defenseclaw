// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// vault list says which sandbox each unconfirmed capture came from and how
// to confirm or remove it (a sandbox that posts prompts it was never given
// shows up here), and --output json carries the sandbox.
func TestVaultListNamesTheSandboxOfAnUnconfirmedCapture(t *testing.T) {
	ta := newTestApp(t, "")
	from := "claudecode prompt (UserPromptSubmit) in sandbox dc-demo"
	if _, err := ta.vault().Capture(vault.CaptureInput{Value: fakeVaultValue(), Kind: "stripe-secret-key", From: from, Sandbox: "dc-demo"}); err != nil {
		t.Fatal(err)
	}
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputText))
	has(t, ta.output(), "STRIPE_API_KEY was captured from "+from)
	has(t, ta.output(), "vault remove STRIPE_API_KEY")
	doc := listJSON(t, ta)
	if len(doc.Entries) != 1 || doc.Entries[0]["sandbox"] != "dc-demo" {
		t.Fatalf("json entries = %+v", doc.Entries)
	}
}
