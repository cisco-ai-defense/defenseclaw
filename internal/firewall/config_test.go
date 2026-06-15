// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"testing"
)

// TestDefaultFirewallConfig_CoversAllConnectors pins the per-connector
// hostnames the deny-by-default firewall must allow on first boot.
// Without these, a Codex / Claude Code / ZeptoClaw user with a
// default-deny firewall sees "DNS lookup blocked" on first chat —
// exactly the symptom F26 was filed for.
//
// We don't assert the *exact* list (it's expected to grow); we
// assert that one representative host per connector survives the
// dedup pass.
func TestDefaultFirewallConfig_CoversAllConnectors(t *testing.T) {
	t.Parallel()
	cfg := DefaultFirewallConfig()

	want := map[string]string{
		// connector → representative host the connector needs.
		"openclaw":   "us.api.inspect.aidefense.security.cisco.com",
		"zeptoclaw":  "openrouter.ai",
		"claudecode": "claude.ai",
		"codex":      "objects.githubusercontent.com",
	}

	got := make(map[string]struct{}, len(cfg.Allowlist.Domains))
	for _, d := range cfg.Allowlist.Domains {
		got[d] = struct{}{}
	}
	for connector, host := range want {
		if _, ok := got[host]; !ok {
			t.Errorf("connector %q: host %q missing from default allowlist (have %v)", connector, host, cfg.Allowlist.Domains)
		}
	}
}

// TestMergeAllowedHosts_AppendsAndDedupes is the contract test for
// the helper that folds connector.AllowedHostsProvider results onto
// the static baseline at sidecar boot. Three cases:
//
//   - new host → appended
//   - duplicate of an existing host → skipped
//   - empty / whitespace-only string → skipped
//
// Order of survivors must follow first-write-wins so existing tests
// that snapshot the default list don't drift on additions.
func TestMergeAllowedHosts_AppendsAndDedupes(t *testing.T) {
	t.Parallel()
	cfg := DefaultFirewallConfig()
	original := append([]string{}, cfg.Allowlist.Domains...)

	cfg.MergeAllowedHosts([]string{
		"new-connector-host.example",
		// Duplicate of one of the static defaults — must be skipped.
		"api.openai.com",
		// Whitespace-only string — must be skipped (not appended as
		// an empty-string entry, which would match nothing).
		"   ",
		// Empty string — same.
		"",
	})

	// First-write-wins: every original host is still present in the
	// same position relative to its peers. We don't strictly require
	// stable indices because the merge appends at the end, but we do
	// require the original prefix is intact.
	for i, want := range original {
		if cfg.Allowlist.Domains[i] != want {
			t.Errorf("original allowlist mutated at idx %d: got %q, want %q",
				i, cfg.Allowlist.Domains[i], want)
		}
	}

	// The new host is appended exactly once.
	count := 0
	for _, d := range cfg.Allowlist.Domains {
		if d == "new-connector-host.example" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("new host count = %d, want 1", count)
	}

	// Duplicate didn't get re-added.
	openaiCount := 0
	for _, d := range cfg.Allowlist.Domains {
		if d == "api.openai.com" {
			openaiCount++
		}
	}
	if openaiCount != 1 {
		t.Errorf("api.openai.com appears %d times after merge, want 1 (dedup broken)", openaiCount)
	}

	// Empty / whitespace strings never landed.
	for _, d := range cfg.Allowlist.Domains {
		if d == "" || d == "   " {
			t.Errorf("empty/whitespace host slipped through MergeAllowedHosts: %q present", d)
		}
	}
}

// TestMergeAllowedHosts_DropsInvalid asserts that hostnames failing
// validateDestination are silently skipped rather than panic'ing or
// exploding the firewall config. A connector implementer who
// returns garbage (e.g. an empty result of `os.Getenv`) should
// degrade to "no extra allowance" rather than break boot.
func TestMergeAllowedHosts_DropsInvalid(t *testing.T) {
	t.Parallel()
	cfg := DefaultFirewallConfig()
	original := len(cfg.Allowlist.Domains)

	cfg.MergeAllowedHosts([]string{
		// Hostname too long — validateDestination rejects.
		string(make([]byte, 300)),
		// One legit host so we know we still merged anything that
		// passed validation.
		"new-connector-host.example",
	})

	// Exactly one new host appended; the long one was rejected.
	if len(cfg.Allowlist.Domains) != original+1 {
		t.Errorf("len after merge = %d, want %d (invalid host should be dropped)",
			len(cfg.Allowlist.Domains), original+1)
	}
}

// TestMergeAllowedHosts_NilSafe documents the intentional no-op
// behavior on nil receiver — caller can chain merge() without an
// existence check on the upstream factory.
func TestMergeAllowedHosts_NilSafe(t *testing.T) {
	t.Parallel()
	var cfg *FirewallConfig
	if got := cfg.MergeAllowedHosts([]string{"foo.example"}); got != nil {
		t.Errorf("nil receiver should return nil, got %v", got)
	}
}
