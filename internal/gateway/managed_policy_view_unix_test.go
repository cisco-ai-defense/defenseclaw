//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// withoutManagedPolicyView keeps a test's hook socket server from proving
// this machine's own vendor policy; a test that needs a view publishes it.
func withoutManagedPolicyView(t *testing.T) {
	t.Helper()
	restore := managedPolicyViewOptions
	managedPolicyViewOptions = func(string) (enterprisepolicy.Options, string, bool) {
		return enterprisepolicy.Options{}, "", false
	}
	t.Cleanup(func() { managedPolicyViewOptions = restore })
}

func writePolicyViewTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func claudePolicyViewTestRoot(t *testing.T, goos string) (enterprisepolicy.Options, string) {
	t.Helper()
	opts := enterprisepolicy.Options{GOOS: goos, Root: t.TempDir(), SkipTrustChecks: true}
	dir, err := enterprisepolicy.ClaudeManagedDir(opts)
	if err != nil {
		t.Fatal(err)
	}
	writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.json"), `{"hooks": {}}`)
	return opts, dir
}

func pinPolicyView(t *testing.T, opts enterprisepolicy.Options, descriptor *managed.RuntimeDescriptor) {
	t.Helper()
	descriptor.PolicyViewDigests = map[string]string{}
	descriptor.PolicyViewUserSources = map[string]map[string]string{}
	for _, name := range descriptor.MachinePolicyConnectors {
		digest, err := enterprisepolicy.PolicyViewDigest(opts, name)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.PolicyViewDigests[name] = digest
		pins, _, err := enterprisepolicy.PolicyViewUserPins(opts, name)
		if err != nil {
			t.Fatal(err)
		}
		descriptor.PolicyViewUserSources[name] = pins
	}
}

// Review loop round 1 (P1): the gateway, not the hook, proves the vendor
// view, from exactly the sources the vendor reads. A drop-in the vendor
// ignores (a hidden draft, a non-JSON backup) is not policy; a new effective
// drop-in, changed content, a hidden or unreadable file and a descriptor
// from before pins are unproven. Unproven is never a refusal: it is the
// alert decision for calls that are still inspected.
func TestManagedPolicyViewProvesTheVendorView(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			opts, dir := claudePolicyViewTestRoot(t, goos)
			descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{enterprisepolicy.ConnectorClaudeCode}}
			pinPolicyView(t, opts, descriptor)
			settings := filepath.Join(dir, "managed-settings.json")
			check := func(what string, want bool) {
				t.Helper()
				view := computeManagedPolicyView(opts, descriptor)
				if got := view.unproven(enterprisepolicy.ConnectorClaudeCode, "alice"); got != want {
					t.Fatalf("%s: unproven = %v, want %v", what, got, want)
				}
				if view.unproven(enterprisepolicy.ConnectorCodex, "alice") {
					t.Fatalf("%s: a connector without machine policy was unproven", what)
				}
			}
			check("the pinned view", false)
			writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.d", ".draft.json"), `{"hooks": null}`)
			writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.d", "90-defenseclaw.json.bak"), `{}`)
			if err := os.MkdirAll(filepath.Join(dir, "managed-settings.d", "old.json"), 0o755); err != nil {
				t.Fatal(err)
			}
			check("the pinned view with drop-ins the vendor ignores", false)
			writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.d", "50-other.json"), `{"permissions": {}}`)
			check("a new effective drop-in", true)
			pinPolicyView(t, opts, descriptor)
			check("the re-pinned view", false)
			writePolicyViewTestFile(t, settings, `{"hooks": {"x": 1}}`)
			check("changed content", true)
			pinPolicyView(t, opts, descriptor)
			if err := os.Remove(settings); err != nil {
				t.Fatal(err)
			}
			check("a hidden policy file", true)
			if err := os.Symlink(filepath.Join(dir, "elsewhere.json"), settings); err != nil {
				t.Fatal(err)
			}
			check("an unreadable (symlinked) policy file", true)
			_ = os.Remove(settings)
			writePolicyViewTestFile(t, settings, `{"hooks": {"x": 1}}`)
			check("the pinned content back", false)
			descriptor.PolicyViewDigests = nil
			check("a descriptor from before pins", true)
			if computeManagedPolicyView(opts, nil).unproven(enterprisepolicy.ConnectorClaudeCode, "alice") {
				t.Fatal("no descriptor alerted: a hook without one refuses its call itself")
			}
		})
	}
}

// On macOS each account's own managed preference is proven by content
// against its pin, with the gateway's permissions: another account's
// change never affects an account, a byte-identical MDM rewrite keeps it
// proven, and a changed, removed, unpinned, unreadable or symlinked
// preference is unproven for that account only.
func TestManagedPolicyViewProvesEachMacAccountByContent(t *testing.T) {
	opts := enterprisepolicy.Options{GOOS: "darwin", Root: t.TempDir(), SkipTrustChecks: true}
	requirements, err := enterprisepolicy.CodexRequirementsPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	writePolicyViewTestFile(t, requirements, "allowed_sandbox_modes = []\n")
	preference := func(account string) string {
		return filepath.Join(opts.Root, "Library", "Managed Preferences", account, "com.openai.codex.plist")
	}
	writePolicyViewTestFile(t, preference("alice"), "alice policy")
	writePolicyViewTestFile(t, preference("bob"), "bob policy")
	descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{enterprisepolicy.ConnectorCodex}}
	pinPolicyView(t, opts, descriptor)
	check := func(what string, want map[string]bool) {
		t.Helper()
		view := computeManagedPolicyView(opts, descriptor)
		for _, account := range []string{"alice", "bob", "carol", "dave"} {
			if got := view.unproven(enterprisepolicy.ConnectorCodex, account); got != want[account] {
				t.Fatalf("%s: %s unproven = %v, want %v", what, account, got, want[account])
			}
		}
	}
	check("pinned preferences", nil)
	writePolicyViewTestFile(t, preference("bob"), "bob changed")
	check("bob's changed preference", map[string]bool{"bob": true})
	replacement := preference("alice") + ".new"
	writePolicyViewTestFile(t, replacement, "alice policy")
	if err := os.Rename(replacement, preference("alice")); err != nil {
		t.Fatal(err)
	}
	check("alice's byte-identical rewrite", map[string]bool{"bob": true})
	writePolicyViewTestFile(t, preference("carol"), "carol policy")
	check("carol's unpinned preference", map[string]bool{"bob": true, "carol": true})
	if err := os.Symlink(filepath.Join(opts.Root, "elsewhere"), filepath.Join(opts.Root, "Library", "Managed Preferences", "dave")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(opts.Root, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	check("dave's symlinked folder", map[string]bool{"bob": true, "carol": true, "dave": true})
	if os.Geteuid() != 0 {
		if err := os.Chmod(preference("alice"), 0o000); err != nil {
			t.Fatal(err)
		}
		check("alice's preference the gateway can not read", map[string]bool{"alice": true, "bob": true, "carol": true, "dave": true})
		_ = os.Chmod(preference("alice"), 0o644)
	}
	if err := os.Remove(preference("alice")); err != nil {
		t.Fatal(err)
	}
	check("alice's removed pinned preference", map[string]bool{"alice": true, "bob": true, "carol": true, "dave": true})
}

// The gateway recomputes the view only when a source or the descriptor
// changes: a metadata stamp is all an unchanged poll costs, a drop-in the
// vendor ignores is no source, and a same-size content change or a re-pin
// by the lifecycle is published by the running watch without a hook call.
func TestManagedPolicyViewRecomputesOnlyWhenTheVendorPolicyChanges(t *testing.T) {
	opts, dir := claudePolicyViewTestRoot(t, "linux")
	descriptorPath := filepath.Join(t.TempDir(), "managed-runtime.json")
	writePolicyViewTestFile(t, descriptorPath, "v1")
	var mu sync.Mutex
	descriptor := &managed.RuntimeDescriptor{MachinePolicyConnectors: []string{enterprisepolicy.ConnectorClaudeCode}}
	pinPolicyView(t, opts, descriptor)
	restoreLoad, restoreCompute, restoreOptions, restoreInterval := loadStandaloneRuntimeDescriptor, computeManagedPolicyViewFor, managedPolicyViewOptions, managedPolicyViewPollInterval
	t.Cleanup(func() {
		loadStandaloneRuntimeDescriptor, computeManagedPolicyViewFor, managedPolicyViewOptions, managedPolicyViewPollInterval = restoreLoad, restoreCompute, restoreOptions, restoreInterval
	})
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		mu.Lock()
		defer mu.Unlock()
		copied := *descriptor
		return &copied, nil
	}
	computes := 0
	computeManagedPolicyViewFor = func(o enterprisepolicy.Options, d *managed.RuntimeDescriptor) *managedPolicyView {
		mu.Lock()
		computes++
		mu.Unlock()
		return computeManagedPolicyView(o, d)
	}
	computed := func() int {
		mu.Lock()
		defer mu.Unlock()
		return computes
	}
	api := &APIServer{}
	watch := &managedPolicyViewWatch{api: api, goos: "linux", opts: opts, descriptorPath: descriptorPath}
	watch.refresh()
	watch.refresh()
	watch.refresh()
	if n := computed(); n != 1 || api.managedPolicyView.Load().unproven(enterprisepolicy.ConnectorClaudeCode, "") {
		t.Fatalf("three polls of an unchanged pinned view computed it %d times (want 1), unproven %v", n, api.managedPolicyView.Load().unproven(enterprisepolicy.ConnectorClaudeCode, ""))
	}
	writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.d", ".draft.json"), `{"hooks": null}`)
	writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.d", "notes.txt"), "x")
	watch.refresh()
	if n := computed(); n != 1 {
		t.Fatalf("drop-ins the vendor ignores made the gateway recompute the view (%d computes)", n)
	}

	// The running watch publishes a change by itself.
	managedPolicyViewPollInterval = 20 * time.Millisecond
	managedPolicyViewOptions = func(string) (enterprisepolicy.Options, string, bool) { return opts, descriptorPath, true }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	running := &APIServer{}
	running.startManagedPolicyView(ctx, "linux")
	waitFor := func(what string, want bool) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); running.managedPolicyView.Load().unproven(enterprisepolicy.ConnectorClaudeCode, "") != want; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: the running watch did not publish unproven = %v", what, want)
			}
		}
	}
	waitFor("the pinned view at start", false)
	before := computed()
	time.Sleep(100 * time.Millisecond)
	if n := computed(); n != before {
		t.Fatalf("an unchanged view was recomputed %d times in 100ms of polls", n-before)
	}
	// Same size, other bytes.
	writePolicyViewTestFile(t, filepath.Join(dir, "managed-settings.json"), `{"hooks": []}`)
	waitFor("a same-size content change", true)
	// The lifecycle re-pins the accepted view and rewrites the descriptor.
	mu.Lock()
	digest, err := enterprisepolicy.PolicyViewDigest(opts, enterprisepolicy.ConnectorClaudeCode)
	descriptor.PolicyViewDigests = map[string]string{enterprisepolicy.ConnectorClaudeCode: digest}
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	writePolicyViewTestFile(t, descriptorPath, "v2")
	waitFor("the re-pinned descriptor", false)
}

// A view that becomes unproven is reported once, as a host alert, without
// any hook call: an administrator learns of a vendor policy change that
// dropped a managed hook even when no call follows it (GAP-1061). The same
// unproven view is not reported again; a changed set of accounts is.
func TestManagedPolicyViewChangeAlertsWithoutACall(t *testing.T) {
	var mu sync.Mutex
	var written []managedPolicyViewAlert
	restore := writeManagedPolicyViewAlert
	writeManagedPolicyViewAlert = func(_ *APIServer, alert managedPolicyViewAlert) {
		mu.Lock()
		written = append(written, alert)
		mu.Unlock()
	}
	t.Cleanup(func() { writeManagedPolicyViewAlert = restore })
	api := &APIServer{}
	view := func(state managedPolicyViewConnector) *managedPolicyView {
		return &managedPolicyView{connectors: map[string]managedPolicyViewConnector{"claudecode": state}}
	}
	api.publishManagedPolicyView(view(managedPolicyViewConnector{}))
	api.publishManagedPolicyView(view(managedPolicyViewConnector{shared: true}))
	api.publishManagedPolicyView(view(managedPolicyViewConnector{shared: true}))
	api.publishManagedPolicyView(view(managedPolicyViewConnector{shared: true, accounts: map[string]bool{"bob": true}}))
	api.publishManagedPolicyView(nil)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		n := len(written)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
	}
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(written) != 2 {
		t.Fatalf("host alerts = %+v, want one for the unproven view and one for its changed accounts", written)
	}
	for _, alert := range written {
		if alert.uid != managedPolicyViewHostAlert || alert.connector != "claudecode" || !strings.Contains(alert.route, "policy-view") {
			t.Fatalf("host alert = %+v", alert)
		}
	}
	if api.managedPolicyView.Load() != nil {
		t.Fatal("a nil view was not published")
	}
}
