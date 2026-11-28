// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/vault"
)

// fakeVaultValue is built at run time: no credential-shaped literal in the tree.
func fakeVaultValue() string { return "sk" + "_live_" + strings.Repeat("Vv7Ww8", 5) }

func TestVaultLivesInTheDataDirectory(t *testing.T) {
	ta := newTestApp(t, "")
	if got, want := ta.VaultDir(), filepath.Join(ta.Cfg.DataDir, "vault"); got != want {
		t.Fatalf("vault dir = %s, want %s", got, want)
	}
}

// The value is typed with echo off (ReadSecret) or piped; it is never
// printed, and list/show/json carry names, hosts and status only.
func TestVaultAddListShowRemove(t *testing.T) {
	ta := newTestApp(t, "")
	ta.ReadSecret = func(string) (string, error) { return fakeVaultValue(), nil }
	ta.ok(t, ta.VaultAdd("STRIPE_API_KEY", "api.stripe.com", VaultValueOptions{}))
	has(t, ta.output(), "added STRIPE_API_KEY for api.stripe.com", "--vault STRIPE_API_KEY")
	ta.ok(t, ta.VaultList(OutputText))
	ta.ok(t, ta.VaultShow("STRIPE_API_KEY", OutputText))
	has(t, ta.output(), "STRIPE_API_KEY", "api.stripe.com", "ready", "manual", "$STRIPE_API_KEY")
	ta.out.Reset()
	ta.ok(t, ta.VaultList(OutputJSON))
	var got struct {
		Entries []map[string]any `json:"entries"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil || len(got.Entries) != 1 {
		t.Fatalf("json = %s (%v)", ta.output(), err)
	}
	if got.Entries[0]["status"] != "ready" || got.Entries[0]["target"] != "api.stripe.com" {
		t.Fatalf("entry = %v", got.Entries[0])
	}
	if _, has := got.Entries[0]["value"]; has {
		t.Fatal("json carries a value field")
	}
	lacks(t, ta.output()+ta.err.String(), fakeVaultValue())
	ta.ok(t, ta.VaultRemove("STRIPE_API_KEY", true))
	if _, err := vault.Open(ta.VaultDir()).Get("STRIPE_API_KEY"); !vault.IsNotFound(err) {
		t.Fatalf("still in the vault: %v", err)
	}
}

func TestVaultAddFromStdinAndRefusals(t *testing.T) {
	ta := newTestApp(t, fakeVaultValue()+"\n")
	ta.ok(t, ta.VaultAdd("PAY_KEY", "api.example.com:8443", VaultValueOptions{Stdin: true}))
	if _, v, err := vault.Open(ta.VaultDir()).Resolve("PAY_KEY"); err != nil || v != fakeVaultValue() {
		t.Fatalf("stdin value not stored: %v", err)
	}
	ta = newTestApp(t, "")
	ta.IO.InTTY = false
	if err := ta.VaultAdd("PAY_KEY", "api.example.com", VaultValueOptions{}); err == nil || !strings.Contains(err.Error(), "--value-stdin") {
		t.Fatalf("no terminal and no --value-stdin: %v", err)
	}
	if err := ta.VaultAdd("PAY_KEY", "https://api.example.com", VaultValueOptions{Stdin: true}); err == nil {
		t.Fatal("a URL host was accepted")
	}
	ta.IO.TTY = false
	ta.ReadSecret = func(string) (string, error) { return "value-1", nil }
	ta.ok(t, ta.VaultAdd("A_KEY", "api.example.com", VaultValueOptions{}))
	if err := ta.VaultRemove("A_KEY", false); err == nil {
		t.Fatal("remove without a terminal and without --yes did not refuse")
	}
}

// --vault binds the vault's value to the vault's host, records the use and
// never prints the value.
func TestRunVault(t *testing.T) {
	ta := newTestApp(t, "")
	st := vault.Open(ta.VaultDir())
	if _, err := st.Add(vault.AddInput{Name: "STRIPE_API_KEY", Value: fakeVaultValue(), Host: "api.stripe.com"}); err != nil {
		t.Fatal(err)
	}
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Vault: []string{"STRIPE_API_KEY"}}))
	req := createRequest(t, ta.daemon)
	found := false
	for _, c := range req.Credentials {
		if c.Name == "STRIPE_API_KEY" {
			found = c.Value == fakeVaultValue() && c.Host == "api.stripe.com" && c.Port == 443
		}
	}
	if !found {
		t.Fatalf("create request credentials = %+v", req.Credentials)
	}
	lacks(t, ta.output()+ta.err.String(), fakeVaultValue())
	e, err := st.Get("STRIPE_API_KEY")
	if err != nil || e.UseCount != 1 || e.LastUsedBy == "" {
		t.Fatalf("use not recorded: %+v %v", e, err)
	}
}

func TestRunVaultRefusals(t *testing.T) {
	ta := newTestApp(t, "")
	st := vault.Open(ta.VaultDir())
	if _, err := st.Add(vault.AddInput{Name: "UNBOUND", Value: "value-u"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Add(vault.AddInput{Name: "PAY_KEY", Value: "value-p", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	noChanges(ta)
	if err := ta.Run(bg, RunOptions{Harness: "claude", Vault: []string{"UNBOUND"}}); err == nil || !strings.Contains(err.Error(), "vault bind UNBOUND") {
		t.Fatalf("unbound secret: %v", err)
	}
	if err := ta.Run(bg, RunOptions{Harness: "claude", Vault: []string{"MISSING"}}); err == nil || !strings.Contains(err.Error(), "no such secret") {
		t.Fatalf("missing secret: %v", err)
	}
	ta.env["PAY_KEY"] = "env-value"
	if err := ta.Run(bg, RunOptions{Harness: "claude", Credentials: []string{"PAY_KEY=api.example.com"}, Vault: []string{"PAY_KEY"}}); err == nil || !strings.Contains(err.Error(), "given twice") {
		t.Fatalf("same name twice: %v", err)
	}
}

// A piped value is one line: more text after it is refused, never dropped.
func TestVaultAddRefusesAMultiLineStdin(t *testing.T) {
	ta := newTestApp(t, fakeVaultValue()+"\nsecond line\n")
	if err := ta.VaultAdd("PAY_KEY", "api.example.com", VaultValueOptions{Stdin: true}); err == nil || !strings.Contains(err.Error(), "more than one line") {
		t.Fatalf("multi-line stdin = %v", err)
	}
	if list, _ := vault.Open(ta.VaultDir()).List(); len(list) != 0 {
		t.Fatalf("stored %d entries", len(list))
	}
	ta = newTestApp(t, fakeVaultValue()+"\n\n")
	ta.ok(t, ta.VaultAdd("PAY_KEY", "api.example.com", VaultValueOptions{Stdin: true}))
}

// A stopped sandbox created with a vault secret is not started again once
// that secret was removed or changed: it would keep the old value.
func TestStartRefusesAChangedVaultGrant(t *testing.T) {
	ta := newTestApp(t, "")
	st := vault.Open(ta.VaultDir())
	if _, err := st.Add(vault.AddInput{Name: "PAY_KEY", Value: "value-p1", Host: "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Vault: []string{"PAY_KEY"}}))
	var sb *sandboxapi.Sandbox
	for _, v := range ta.daemon.sandboxes {
		sb = v
	}
	if sb == nil {
		t.Fatal("no sandbox created")
	}
	if err := ta.vaultGrantsCurrent(sb); err != nil {
		t.Fatalf("unchanged grant refused: %v", err)
	}
	if _, err := st.ReplaceValue("PAY_KEY", "value-p2"); err != nil {
		t.Fatal(err)
	}
	if err := ta.vaultGrantsCurrent(sb); err == nil || !strings.Contains(err.Error(), "delete it") {
		t.Fatalf("replaced grant = %v", err)
	}
	if err := st.Remove("PAY_KEY"); err != nil {
		t.Fatal(err)
	}
	if err := ta.vaultGrantsCurrent(sb); err == nil || !strings.Contains(err.Error(), "no longer in your vault") {
		t.Fatalf("removed grant = %v", err)
	}
}

func TestVaultConfirm(t *testing.T) {
	ta := newTestApp(t, "")
	st := vault.Open(ta.VaultDir())
	if _, err := st.Capture(vault.CaptureInput{Value: fakeVaultValue(), Kind: "stripe-secret-key", From: "claudecode prompt in sandbox sb"}); err != nil {
		t.Fatal(err)
	}
	ta.ok(t, ta.VaultConfirm("STRIPE_API_KEY", true))
	has(t, ta.output(), "Captured from", "claudecode prompt in sandbox sb", "Ends with", fakeVaultValue()[len(fakeVaultValue())-4:], "confirmed STRIPE_API_KEY")
	lacks(t, ta.output(), fakeVaultValue())
	if _, _, err := st.Resolve("STRIPE_API_KEY"); err != nil {
		t.Fatalf("confirmed entry = %v", err)
	}
}
