// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// TestSIDIsInteractiveUserAcceptsRealUserSIDs pins the shape spec 005
// REQ-11 requires: an S-1-5-21-… SID with at least 5 sub-authorities
// (21, A, B, C, RID) is accepted; anything else is refused. The
// boundary case (`S-1-5-21-A-B-C`, 4 sub-authorities — the bare
// domain SID without a trailing RID) MUST be rejected: enumerating a
// bare domain as an interactive user would emit garbage manifest
// rows. See CR spec-005:PRRT_kwDORuAK-s6atyfL.
func TestSIDIsInteractiveUserAcceptsRealUserSIDs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"typical local user (5 sub-auths)", "S-1-5-21-1000-2000-3000-1001", true},
		{"domain user with high RID (5 sub-auths)", "S-1-5-21-1234567890-987654321-1111111111-4321", true},
		// Exact 5-sub-authority boundary — smallest legal user SID.
		{"minimum accepted (exactly 5 sub-auths)", "S-1-5-21-0-0-0-500", true},
		// The bare domain SID (`S-1-5-21-A-B-C`) has 4 sub-auths and
		// MUST be rejected — this is the boundary the earlier
		// `< 4` check missed.
		{"bare domain SID (4 sub-auths)", "S-1-5-21-1000-2000-3000", false},
		{"NT AUTHORITY too short (1 sub-auth)", "S-1-5-21", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sid, err := windows.StringToSid(tc.raw)
			if err != nil {
				t.Fatalf("StringToSid(%q): %v", tc.raw, err)
			}
			if got := sidIsInteractiveUser(sid); got != tc.want {
				t.Fatalf("sidIsInteractiveUser(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestSIDIsInteractiveUserRejectsWellKnown pins REQ-11's exclusion
// list. Every principal listed here is a well-known SID the CLI /
// enumerator MUST refuse — accepting any of them would let a
// misconfigured install rewrite the machine's SYSTEM / BUILTIN /
// NT SERVICE hook wiring, which is nonsensical (those principals
// don't run hook-based agents).
func TestSIDIsInteractiveUserRejectsWellKnown(t *testing.T) {
	wellKnown := []struct {
		name string
		raw  string
	}{
		{"Everyone", "S-1-1-0"},
		{"Anonymous", "S-1-5-7"},
		{"Authenticated Users", "S-1-5-11"},
		{"LocalSystem", "S-1-5-18"},
		{"LocalService", "S-1-5-19"},
		{"NetworkService", "S-1-5-20"},
		{"BUILTIN\\Administrators", "S-1-5-32-544"},
		{"BUILTIN\\Users", "S-1-5-32-545"},
		{"NT SERVICE\\TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"},
	}
	for _, tc := range wellKnown {
		t.Run(tc.name, func(t *testing.T) {
			sid, err := windows.StringToSid(tc.raw)
			if err != nil {
				t.Fatalf("StringToSid(%q): %v", tc.raw, err)
			}
			if sidIsInteractiveUser(sid) {
				t.Fatalf("sidIsInteractiveUser(%q) = true, want false — well-known SID leaked", tc.raw)
			}
		})
	}
}

// TestEffectiveWindowsHookConnectorsFiltersUnsupported drives the
// connector-list filter that decides which per-user rows the
// enumerator emits. Coverage:
//   - Unsupported connector ("openclaw", "gemini") is dropped.
//   - Duplicate names (map + scalar overlap) are deduped.
//   - `Enabled=false` in the per-connector map drops that connector.
//   - Empty config → empty output.
func TestEffectiveWindowsHookConnectorsFiltersUnsupported(t *testing.T) {
	disabled := false
	cases := []struct {
		name string
		cfg  *config.Config
		want []string
	}{
		{
			name: "empty",
			cfg:  &config.Config{},
			want: []string{},
		},
		{
			name: "scalar only, supported",
			cfg: &config.Config{
				Guardrail: config.GuardrailConfig{Connector: "codex"},
			},
			want: []string{"codex"},
		},
		{
			name: "scalar unsupported (openclaw) → dropped",
			cfg: &config.Config{
				Guardrail: config.GuardrailConfig{Connector: "openclaw"},
			},
			want: []string{},
		},
		{
			name: "map with supported entries, alphabetical order",
			cfg: &config.Config{
				Guardrail: config.GuardrailConfig{
					Connector: "codex",
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex":      {},
						"claudecode": {},
						"cursor":     {},
					},
				},
			},
			want: []string{"claudecode", "codex", "cursor"},
		},
		{
			name: "map contains explicitly-disabled connector",
			cfg: &config.Config{
				Guardrail: config.GuardrailConfig{
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex":      {},
						"claudecode": {Enabled: &disabled},
					},
				},
			},
			want: []string{"codex"},
		},
		{
			// CR spec-005:PRRT_kwDORuAK-s6atyfM regression:
			// a disabled map entry MUST beat the scalar
			// re-declaration. A config that names claudecode
			// both as the scalar Connector AND as an explicitly
			// disabled Connectors[claudecode].Enabled=false must
			// emit ZERO per-user rows for claudecode.
			name: "map disable beats scalar re-declaration",
			cfg: &config.Config{
				Guardrail: config.GuardrailConfig{
					Connector: "claudecode",
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"claudecode": {Enabled: &disabled},
					},
				},
			},
			want: []string{},
		},
		{
			name: "map contains gemini (unsupported) alongside codex",
			cfg: &config.Config{
				Guardrail: config.GuardrailConfig{
					Connectors: map[string]config.PerConnectorGuardrailConfig{
						"codex":  {},
						"gemini": {},
					},
				},
			},
			want: []string{"codex"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveWindowsHookConnectors(tc.cfg)
			if len(got) != len(tc.want) {
				t.Fatalf("length mismatch: got %v (len=%d), want %v (len=%d)", got, len(got), tc.want, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("index %d: got %q, want %q (full: got=%v want=%v)", i, got[i], tc.want[i], got, tc.want)
				}
			}
		})
	}
}

func prepareWindowsTargetsManifestTestDirectory(t *testing.T) string {
	t.Helper()
	originalAncestorTrust := windowsTargetsManifestAncestorTrust
	windowsTargetsManifestAncestorTrust = func(string) error { return nil }
	t.Cleanup(func() { windowsTargetsManifestAncestorTrust = originalAncestorTrust })
	dir := t.TempDir()
	if err := protectWindowsTargetsManifestObject(dir, true); err != nil {
		t.Fatalf("protect manifest test directory: %v", err)
	}
	return dir
}

func windowsTargetsManifestDescriptor(t *testing.T, path string) string {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("read manifest descriptor: %v", err)
	}
	return descriptor.String()
}

func TestProtectWindowsTargetsManifestObjectAppliesExactInstallerContract(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(file, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		path      string
		directory bool
	}{
		{name: "AdminFile", path: file},
		{name: "AdminDirectory", path: dir, directory: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := protectWindowsTargetsManifestObject(test.path, test.directory); err != nil {
				t.Fatalf("protect %s: %v", test.name, err)
			}
			if err := validateWindowsTargetsManifestObject(test.path, test.directory); err != nil {
				t.Fatalf("validate exact %s contract: %v", test.name, err)
			}
		})
	}
}

func TestValidateWindowsTargetsManifestObjectRejectsGenericSplitDirectoryDACL(t *testing.T) {
	dir := t.TempDir()
	// This is the four-ACE representation produced when inheritable
	// GENERIC_ALL entries are materialized by NTFS: concrete effective access
	// plus generic inherit-only access for each trusted principal. It is not the
	// installer's exact two-ACE AdminDirectory contract.
	split, err := windows.SecurityDescriptorFromString(
		"O:BAG:BAD:P" +
			"(A;;FA;;;SY)(A;OICIIO;GA;;;SY)" +
			"(A;;FA;;;BA)(A;OICIIO;GA;;;BA)",
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := split.Owner()
	if err != nil {
		t.Fatal(err)
	}
	group, _, err := split.Group()
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := split.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("resolve split DACL: %v", err)
	}
	extended, err := winpath.Extended(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		group,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("apply split DACL fixture: %v", err)
	}
	if err := validateWindowsTargetsManifestObject(dir, true); err == nil ||
		!strings.Contains(err.Error(), "has 4 ACEs, want 2") {
		t.Fatalf("split DACL validation error = %v, want exact four-vs-two rejection", err)
	}
}

// TestWriteTargetsManifestAtomicNoOpNoWrite pins spec 005 REQ-05: a
// byte-identical manifest must not touch the on-disk file. This is
// the CORE property that prevents guardian fsnotify wakes every 5-min
// tick on a stable box. If regressions land here, the test-fixture's
// mtime check catches it.
func TestWriteTargetsManifestAtomicNoOpNoWrite(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := filepath.Join(dir, "targets.yaml")

	disabled := false
	initial := Manifest{
		Version: 1,
		Targets: []ManifestTarget{
			{
				SID:       "S-1-5-21-1000-2000-3000-1001",
				UserHome:  filepath.FromSlash(`C:\Users\alice`),
				Connector: "codex",
				DataDir:   filepath.FromSlash(`C:\Users\alice\.defenseclaw`),
				Enabled:   &disabled,
			},
		},
	}

	// Round 1: write from scratch.
	changed, err := WriteTargetsManifestAtomic(path, initial)
	if err != nil {
		t.Fatalf("initial WriteTargetsManifestAtomic: %v", err)
	}
	if !changed {
		t.Fatal("initial write reported changed=false; want true")
	}

	firstInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after initial write: %v", err)
	}
	firstMtime := firstInfo.ModTime()
	firstBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after initial write: %v", err)
	}

	// Round 2: write the same manifest. Must be a no-op no-write.
	changed, err = WriteTargetsManifestAtomic(path, initial)
	if err != nil {
		t.Fatalf("second WriteTargetsManifestAtomic: %v", err)
	}
	if changed {
		t.Fatal("second write reported changed=true on byte-identical input; want false")
	}

	secondInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after second write: %v", err)
	}
	if !secondInfo.ModTime().Equal(firstMtime) {
		t.Fatalf("byte-identical write mutated mtime: was %v, now %v", firstMtime, secondInfo.ModTime())
	}

	secondBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after second write: %v", err)
	}
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("byte-identical write mutated file contents")
	}
}

// TestWriteTargetsManifestAtomicReplacesOnDifference asserts the
// atomic-replace half: a non-identical serialisation lands via the
// ACL-preserving Windows replacement path and the new bytes are on disk.
func TestWriteTargetsManifestAtomicReplacesOnDifference(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := filepath.Join(dir, "targets.yaml")

	first := Manifest{
		Version: 1,
		Targets: []ManifestTarget{{SID: "S-1-5-21-1000-2000-3000-1001", UserHome: `C:\Users\alice`, Connector: "codex", DataDir: `C:\Users\alice\.defenseclaw`}},
	}
	changed, err := WriteTargetsManifestAtomic(path, first)
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if !changed {
		t.Fatal("first write: changed=false, want true")
	}
	if err := validateWindowsTargetsManifestObject(path, false); err != nil {
		t.Fatalf("first write did not publish exact AdminFile protection: %v", err)
	}
	descriptorBefore := windowsTargetsManifestDescriptor(t, path)

	second := first
	second.Targets = append(second.Targets, ManifestTarget{
		SID: "S-1-5-21-1000-2000-3000-1002", UserHome: `C:\Users\bob`, Connector: "codex", DataDir: `C:\Users\bob\.defenseclaw`,
	})
	changed, err = WriteTargetsManifestAtomic(path, second)
	if err != nil {
		t.Fatalf("second write: %v", err)
	}
	if !changed {
		t.Fatal("second write on distinct content: changed=false, want true")
	}
	if err := validateWindowsTargetsManifestObject(path, false); err != nil {
		t.Fatalf("replacement lost exact AdminFile protection: %v", err)
	}
	if descriptorAfter := windowsTargetsManifestDescriptor(t, path); descriptorAfter != descriptorBefore {
		t.Fatalf("replacement changed protected manifest descriptor: before=%q after=%q", descriptorBefore, descriptorAfter)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after distinct write: %v", err)
	}
	if !strings.Contains(string(raw), "S-1-5-21-1000-2000-3000-1002") {
		t.Fatalf("second-row SID missing from on-disk file:\n%s", string(raw))
	}
}

func TestWriteTargetsManifestAtomicProtectionFailureLeavesKnownGoodDestination(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := filepath.Join(dir, "targets.yaml")
	first := Manifest{
		Version: 1,
		Targets: []ManifestTarget{{
			SID:       "S-1-5-21-1000-2000-3000-1001",
			UserHome:  `C:\Users\alice`,
			Connector: "codex",
			DataDir:   `C:\Users\alice\.defenseclaw`,
		}},
	}
	if changed, err := WriteTargetsManifestAtomic(path, first); err != nil || !changed {
		t.Fatalf("seed protected manifest: changed=%t err=%v", changed, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	descriptorBefore := windowsTargetsManifestDescriptor(t, path)

	originalProtect := windowsTargetsManifestProtect
	windowsTargetsManifestProtect = func(string, bool) error {
		return errors.New("injected staging ACL failure")
	}
	t.Cleanup(func() { windowsTargetsManifestProtect = originalProtect })
	second := first
	second.Targets = append(second.Targets, ManifestTarget{
		SID:       "S-1-5-21-1000-2000-3000-1002",
		UserHome:  `C:\Users\bob`,
		Connector: "codex",
		DataDir:   `C:\Users\bob\.defenseclaw`,
	})
	changed, err := WriteTargetsManifestAtomic(path, second)
	if err == nil || changed {
		t.Fatalf("staging protection failure: changed=%t err=%v, want false/error", changed, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("staging protection failure replaced known-good manifest bytes")
	}
	if descriptorAfter := windowsTargetsManifestDescriptor(t, path); descriptorAfter != descriptorBefore {
		t.Fatal("staging protection failure changed known-good manifest DACL")
	}
}

func TestWriteTargetsManifestAtomicRejectsHardLinkedDestination(t *testing.T) {
	dir := prepareWindowsTargetsManifestTestDirectory(t)
	path := filepath.Join(dir, "targets.yaml")
	manifest := Manifest{
		Version: 1,
		Targets: []ManifestTarget{{
			SID:       "S-1-5-21-1000-2000-3000-1001",
			UserHome:  `C:\Users\alice`,
			Connector: "codex",
			DataDir:   `C:\Users\alice\.defenseclaw`,
		}},
	}
	if changed, err := WriteTargetsManifestAtomic(path, manifest); err != nil || !changed {
		t.Fatalf("seed protected manifest: changed=%t err=%v", changed, err)
	}
	alias := filepath.Join(dir, "targets-alias.yaml")
	if err := os.Link(path, alias); err != nil {
		t.Fatalf("create manifest hard link: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := WriteTargetsManifestAtomic(path, manifest)
	if err == nil || changed || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard-linked destination: changed=%t err=%v, want false/hard-link error", changed, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("hard-link rejection changed manifest bytes")
	}
}

// TestApplyPreviousRowStatePreservesAgentVersion asserts the
// AgentVersion + Enabled + Deferred preservation invariant spec
// 005 REQ-08's design says: a row that already exists in the file
// keeps its agent_version + enabled state across enumeration
// cycles. A NEW row is auto-authorized at the per-user CLI's
// discovered version (macOS parity) — or dropped entirely if no
// per-user CLI is present.
func TestApplyPreviousRowStatePreservesAgentVersion(t *testing.T) {
	enabled := true
	previous := map[string]ManifestTarget{
		previousManifestKey("S-1-5-21-1000-2000-3000-1001", "codex"): {
			SID:          "S-1-5-21-1000-2000-3000-1001",
			Connector:    "codex",
			AgentVersion: "0.145.0",
			Enabled:      &enabled,
			Deferred:     true,
		},
	}

	// Match: preserve AgentVersion + Enabled + Deferred.
	matched := ManifestTarget{
		SID:       "s-1-5-21-1000-2000-3000-1001", // deliberate case
		Connector: "codex",
	}
	if !applyPreviousRowState(&matched, previous, nil) {
		t.Fatal("existing-row emission signal: want true, got false")
	}
	if matched.AgentVersion != "0.145.0" {
		t.Fatalf("existing-row AgentVersion not preserved: got %q, want %q", matched.AgentVersion, "0.145.0")
	}
	if matched.Enabled == nil || !*matched.Enabled {
		t.Fatal("existing-row Enabled=true not preserved")
	}
	if !matched.Deferred {
		t.Fatal("existing-row Deferred=true not preserved")
	}
}

// TestApplyPreviousRowStateAutoAuthorizesNewRowWithDiscoverableCLI
// pins the macOS-parity auto-authorize path: a newly-discovered
// (SID, Connector) whose per-user profile contains a supported CLI
// (via the package.json probe added in the previous commit) is
// emitted with Enabled=true, AgentVersion set to the discovered
// value, and Deferred=false.
func TestApplyPreviousRowStateAutoAuthorizesNewRowWithDiscoverableCLI(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@openai", "codex")
	writeWindowsAgentPackageJSON(t, dir, "0.42.0")

	fresh := ManifestTarget{
		SID:       "S-1-5-21-9999-8888-7777-1001",
		UserHome:  home,
		Connector: "codex",
	}
	if !applyPreviousRowState(&fresh, nil, nil) {
		t.Fatal("new row with discoverable CLI: emission signal want true, got false")
	}
	if fresh.AgentVersion != "0.42.0" {
		t.Fatalf("new row AgentVersion: got %q, want 0.42.0", fresh.AgentVersion)
	}
	if fresh.Enabled == nil || !*fresh.Enabled {
		t.Fatal("new row Enabled: want pointer-to-true")
	}
	if fresh.Deferred {
		t.Fatal("new row Deferred: want false")
	}
}

// TestApplyPreviousRowStateDropsNewRowWithoutDiscoverableCLI pins
// the macOS-parity silent-skip: a newly-discovered (SID, Connector)
// whose per-user profile has NO supported CLI is dropped entirely.
// applyPreviousRowState returns false; the caller in EnumerateWindows
// treats false as "skip this row" (no target emitted).
func TestApplyPreviousRowStateDropsNewRowWithoutDiscoverableCLI(t *testing.T) {
	home := t.TempDir()
	// No package.json under home — every probe path is absent.

	fresh := ManifestTarget{
		SID:       "S-1-5-21-9999-8888-7777-1001",
		UserHome:  home,
		Connector: "claudecode",
	}
	if applyPreviousRowState(&fresh, nil, nil) {
		t.Fatal("new row without discoverable CLI: emission signal want false, got true (row would have been emitted)")
	}
}

// TestLoadPreviousManifestForEnumerationHandlesMissingFile asserts
// that a missing existing manifest is not a hard error — enumeration
// proceeds with a nil previous map (every row is treated as new).
func TestLoadPreviousManifestForEnumerationHandlesMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.yaml")
	got := loadPreviousManifestForEnumeration(path, nil)
	if got != nil {
		t.Fatalf("missing file: got non-nil map (len=%d); want nil", len(got))
	}
}

// TestLoadPreviousManifestForEnumerationHandlesEmptyPath asserts an
// empty path (the target-uninstall regenerate-from-scratch case)
// returns nil without an error.
func TestLoadPreviousManifestForEnumerationHandlesEmptyPath(t *testing.T) {
	got := loadPreviousManifestForEnumeration("", nil)
	if got != nil {
		t.Fatalf("empty path: got non-nil map (len=%d); want nil", len(got))
	}
}

// TestMarshalTargetsManifestIsDeterministic asserts the byte-output
// of `marshalTargetsManifest` is stable for the same input, which is
// what the no-op-no-write invariant in WriteTargetsManifestAtomic
// depends on.
func TestMarshalTargetsManifestIsDeterministic(t *testing.T) {
	disabled := false
	m := Manifest{
		Version: 1,
		Targets: []ManifestTarget{
			{SID: "S-1-5-21-1000-2000-3000-1001", UserHome: `C:\Users\alice`, Connector: "codex", DataDir: `C:\Users\alice\.defenseclaw`, Enabled: &disabled},
			{SID: "S-1-5-21-1000-2000-3000-1002", UserHome: `C:\Users\bob`, Connector: "claudecode", DataDir: `C:\Users\bob\.defenseclaw`, Enabled: &disabled},
		},
	}
	first, err := marshalTargetsManifest(m)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}
	second, err := marshalTargetsManifest(m)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("marshal not deterministic:\nfirst:  %q\nsecond: %q", first, second)
	}
}

// TestEnumerateWindowsRejectsNilConfig pins the guard clause — a nil
// config would panic on `cfg.Guardrail` deref if we didn't refuse it
// up front.
func TestEnumerateWindowsRejectsNilConfig(t *testing.T) {
	_, err := EnumerateWindows(context.Background(), nil, EnumerateOptions{})
	if err == nil {
		t.Fatal("EnumerateWindows(nil): want error, got nil")
	}
}

// TestEnumerateWindowsEmptyConnectorsReturnsEmptyManifest asserts
// the no-connector-configured path emits `Version: 1, Targets: []`
// (not nil) so the on-disk YAML always has a well-defined shape.
func TestEnumerateWindowsEmptyConnectorsReturnsEmptyManifest(t *testing.T) {
	cfg := &config.Config{} // no guardrail.connector configured
	m, err := EnumerateWindows(context.Background(), cfg, EnumerateOptions{})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if m.Version != 1 {
		t.Fatalf("Version = %d, want 1", m.Version)
	}
	if len(m.Targets) != 0 {
		t.Fatalf("Targets = %v, want empty", m.Targets)
	}
	if m.Targets == nil {
		t.Fatal("Targets is nil; want non-nil empty slice for stable YAML shape")
	}
}

// TestEnumerateWindowsHonoursCancelledContext asserts the cycle-
// timeout invariant CR spec-005:PRRT_kwDORuAK-s6atyfD asks for: a
// ctx that's already cancelled returns immediately without touching
// the registry / filesystem. Belt-and-braces on top of the per-row
// ctx.Err() checks; a cancelled ctx at ENTRY must never proceed.
func TestEnumerateWindowsHonoursCancelledContext(t *testing.T) {
	cfg := &config.Config{Guardrail: config.GuardrailConfig{Connector: "codex"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := EnumerateWindows(ctx, cfg, EnumerateOptions{})
	if err == nil {
		t.Fatal("cancelled ctx: want error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ctx: err = %v, want context.Canceled", err)
	}
}

func staticEnrollmentLookup(account, domain string, err error) (windowsEnrollmentAccountLookup, *int) {
	calls := 0
	return func(string) (string, string, error) {
		calls++
		return account, domain, err
	}, &calls
}

func TestWindowsProfileEnrollmentDecision(t *testing.T) {
	profile := windowsUserProfile{SID: "S-1-5-21-1-2-3-1012", Home: `C:\Users\alice.CONTOSO`}
	lookup, calls := staticEnrollmentLookup("alice", "CONTOSO", nil)
	for _, tc := range []struct {
		name            string
		exclude, exempt []string
		want            windowsEnrollmentDecision
	}{
		{name: "no filters", want: windowsEnrollmentEnrolled},
		{name: "exclude by directory name", exclude: []string{"ALICE.CONTOSO"}, want: windowsEnrollmentExcluded},
		{name: "exclude by SID", exclude: []string{"s-1-5-21-1-2-3-1012"}, want: windowsEnrollmentExcluded},
		{name: "exclude by account", exclude: []string{"alice"}, want: windowsEnrollmentExcluded},
		{name: "exclude by domain account", exclude: []string{`contoso\ALICE`}, want: windowsEnrollmentExcluded},
		{name: "exclude someone else", exclude: []string{"bob", "S-1-5-21-1-2-3-1013"}, want: windowsEnrollmentEnrolled},
		{name: "exempt by account", exempt: []string{"alice"}, want: windowsEnrollmentExempt},
		{name: "exclusion wins over exemption", exclude: []string{`CONTOSO\alice`}, exempt: []string{"alice.CONTOSO"}, want: windowsEnrollmentExcluded},
	} {
		got, _ := windowsProfileEnrollmentDecision(profile, tc.exclude, tc.exempt, lookup)
		if got != tc.want {
			t.Errorf("%s: decision = %d, want %d", tc.name, got, tc.want)
		}
	}
	before := *calls
	windowsProfileEnrollmentDecision(profile, []string{"S-1-5-21-9-9-9-1001", "alice.CONTOSO"}, nil, lookup)
	windowsProfileEnrollmentDecision(profile, nil, nil, lookup)
	if *calls != before {
		t.Fatal("SID, directory-name and empty filters must be decided without an account lookup")
	}
}

func TestWindowsEnrollmentAccountLookupIsBounded(t *testing.T) {
	previous, previousTimeout, previousBudget := windowsEnrollmentLookupAccountSID, windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget
	t.Cleanup(func() {
		windowsEnrollmentLookupAccountSID, windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = previous, previousTimeout, previousBudget
	})
	release := make(chan struct{})
	defer close(release)
	windowsEnrollmentLookupAccountSID = func(string) (string, string, error) {
		<-release
		return "alice", "CONTOSO", nil
	}
	windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = 20*time.Millisecond, 50*time.Millisecond
	lookup := newWindowsEnrollmentAccountLookup()
	start := time.Now()
	for i := 0; i < 10; i++ {
		if _, _, err := lookup("S-1-5-21-1-2-3-1012"); err == nil {
			t.Fatal("a hung lookup must fail")
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("ten hung lookups took %s; the cycle budget must bound them", elapsed)
	}

	// The lookup budget counts only time spent waiting on lookups. Probing the
	// profiles before a lookup (package manifests, executables) must not use it
	// up, or a slow host would leave later profiles undecided with a healthy
	// domain controller.
	t.Run("only lookup time counts", func(t *testing.T) {
		previous, previousTimeout, previousBudget := windowsEnrollmentLookupAccountSID, windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget
		t.Cleanup(func() {
			windowsEnrollmentLookupAccountSID, windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = previous, previousTimeout, previousBudget
		})
		windowsEnrollmentLookupAccountSID = func(string) (string, string, error) { return "alice", "CONTOSO", nil }
		windowsEnrollmentLookupTimeout, windowsEnrollmentLookupBudget = 20*time.Millisecond, 40*time.Millisecond
		lookup := newWindowsEnrollmentAccountLookup()
		for i := 0; i < 3; i++ {
			// Profile probing between lookups, longer than the whole budget.
			time.Sleep(60 * time.Millisecond)
			account, domain, err := lookup("S-1-5-21-1-2-3-1012")
			if err != nil || account != "alice" || domain != "CONTOSO" {
				t.Fatalf("lookup %d after probing = %q, %q, %v; want the account name", i, account, domain, err)
			}
		}
	})
}

// An exempt user gets no new per-user connector rows, but a row already
// enrolled stays: dropping it would revoke the SID while its hook registration
// stays in the user's own agent config and fails closed as unregistered.
func TestEnumerateWindowsStandaloneExemptUserKeepsEnrolledPerUserRows(t *testing.T) {
	stubMachineWinGet(t, nil)
	const (
		carolSID = "S-1-5-21-1004336348-1177238915-682003330-1003"
		daveSID  = "S-1-5-21-1004336348-1177238915-682003330-1004"
	)
	previousStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	homes := map[string]string{}
	for _, sid := range []string{carolSID, daveSID} {
		home := codexProfile(t, "0.150.0")
		devin := filepath.Join(home, "AppData", "Local", "devin", "cli", "_versions", "3000.4.25", "bin")
		if err := os.MkdirAll(devin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(devin, "devin.exe"), []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
		homes[sid] = home
	}
	injectWindowsProfileList(t, homes)
	enabled := true
	existing := Manifest{Version: 1, Targets: []ManifestTarget{{
		SID: carolSID, Connector: "devin", UserHome: homes[carolSID],
		DataDir: filepath.Join(homes[carolSID], ".defenseclaw"), AgentVersion: "3000.4.25", Enabled: &enabled,
	}}}
	path := filepath.Join(t.TempDir(), "targets.yaml")
	raw, err := marshalTargetsManifest(existing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := standaloneEnumeratorConfig("codex")
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"devin": {Enabled: &enabled}}
	manifest, err := EnumerateWindows(context.Background(), cfg, EnumerateOptions{
		ExistingManifestPath: path,
		ExemptUsers:          []string{carolSID, daveSID},
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	rows := map[string][]string{}
	for _, target := range manifest.Targets {
		rows[target.SID] = append(rows[target.SID], target.Connector)
	}
	if got := strings.Join(rows[carolSID], ","); got != "codex,devin" {
		t.Fatalf("the exempt user with an enrolled Devin row has rows %s, want codex,devin", got)
	}
	if got := strings.Join(rows[daveSID], ","); got != "codex" {
		t.Fatalf("the exempt user without a Devin row has rows %s, want only codex", got)
	}
}

func TestEnumerateWindowsStandaloneEnrollmentSemantics(t *testing.T) {
	stubMachineWinGet(t, nil)
	const (
		aliceSID = "S-1-5-21-1004336348-1177238915-682003330-1001"
		bobSID   = "S-1-5-21-1004336348-1177238915-682003330-1002"
		carolSID = "S-1-5-21-1004336348-1177238915-682003330-1003"
	)
	previousStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	homes := map[string]string{}
	for _, sid := range []string{aliceSID, bobSID, carolSID} {
		home := codexProfile(t, "0.150.0")
		writeWindowsAgentPackageJSON(t, filepath.Join(home, "AppData", "Roaming", "npm", "node_modules", "@github", "copilot"), "1.0.88")
		devin := filepath.Join(home, "AppData", "Local", "devin", "cli", "_versions", "3000.4.25", "bin")
		if err := os.MkdirAll(devin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(devin, "devin.exe"), []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
		homes[sid] = home
	}
	injectWindowsProfileList(t, homes)
	names := map[string]string{aliceSID: "alice", bobSID: "bob", carolSID: "carol"}
	previousLookup := windowsEnrollmentLookupAccountSID
	t.Cleanup(func() { windowsEnrollmentLookupAccountSID = previousLookup })
	windowsEnrollmentLookupAccountSID = func(sid string) (string, string, error) {
		return names[strings.ToUpper(sid)], "CONTOSO", nil
	}
	cfg := standaloneEnumeratorConfig("codex")
	enabled := true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"copilot": {Enabled: &enabled}, "devin": {Enabled: &enabled},
	}
	manifest, err := EnumerateWindows(context.Background(), cfg, EnumerateOptions{
		IncludeUsers: []string{`CONTOSO\alice`},
		ExcludeUsers: []string{"bob"},
		ExemptUsers:  []string{"carol"},
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	rows := map[string][]string{}
	for _, target := range manifest.Targets {
		rows[target.SID] = append(rows[target.SID], target.Connector)
	}
	if got := strings.Join(rows[aliceSID], ","); got != "codex,copilot,devin" {
		t.Fatalf("the included user rows = %s, want codex,copilot,devin", got)
	}
	if len(rows[bobSID]) != 0 {
		t.Fatalf("the excluded user has rows %v", rows[bobSID])
	}
	if got := strings.Join(rows[carolSID], ","); got != "codex,copilot" {
		t.Fatalf("the exempt user rows = %s, want only the machine-policy connectors codex,copilot", got)
	}
}

// include_users is additive, as documented and as on Linux and macOS: a
// non-empty list never unenrolls anyone else.
func TestEnumerateWindowsStandaloneIncludeUsersIsAdditive(t *testing.T) {
	stubMachineWinGet(t, nil)
	const otherSID = "S-1-5-21-1004336348-1177238915-682003330-1002"
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: codexProfile(t, "0.150.0"),
		otherSID:         codexProfile(t, "0.150.0"),
	})
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		IncludeUsers: []string{"alice"},
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 2 {
		t.Fatalf("targets = %+v, want both profiles enrolled", manifest.Targets)
	}
}

// A lookup failure keeps a profile's published rows and adds none, so a
// domain controller outage revokes nobody.
func TestEnumerateWindowsStandaloneKeepsRowsWhenTheAccountNameIsUnavailable(t *testing.T) {
	stubMachineWinGet(t, nil)
	const newSID = "S-1-5-21-1004336348-1177238915-682003330-1002"
	injectWindowsProfileList(t, map[string]string{
		testLocalUserSID: codexProfile(t, "0.150.0"),
		newSID:           codexProfile(t, "0.150.0"),
	})
	previousLookup := windowsEnrollmentLookupAccountSID
	t.Cleanup(func() { windowsEnrollmentLookupAccountSID = previousLookup })
	windowsEnrollmentLookupAccountSID = func(string) (string, string, error) {
		return "", "", windows.RPC_S_SERVER_UNAVAILABLE
	}
	enabled := true
	existing := Manifest{Version: 1, Targets: []ManifestTarget{{
		SID: testLocalUserSID, Connector: "codex", UserHome: `C:\Users\alice`,
		DataDir: `C:\Users\alice\.defenseclaw`, AgentVersion: "0.140.0", Enabled: &enabled,
	}}}
	path := filepath.Join(t.TempDir(), "targets.yaml")
	raw, err := marshalTargetsManifest(existing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var logged []string
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("codex"), EnumerateOptions{
		ExistingManifestPath: path,
		ExcludeUsers:         []string{`CONTOSO\bob`},
		Logger:               func(subject, reason string) { logged = append(logged, subject+": "+reason) },
	})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].SID != testLocalUserSID || manifest.Targets[0].AgentVersion != "0.140.0" {
		t.Fatalf("targets = %+v, want only the known row, unchanged", manifest.Targets)
	}
	if !strings.Contains(strings.Join(logged, "\n"), "account name lookup failed") {
		t.Fatalf("the lookup failure must be logged; log:\n%s", strings.Join(logged, "\n"))
	}

	// A directory outage must never turn a name-form entry into a non-match.
	t.Run("the decision stays undecided", func(t *testing.T) {
		profile := windowsUserProfile{SID: "S-1-5-21-1-2-3-1012", Home: `C:\Users\bob`}
		failing, _ := staticEnrollmentLookup("", "", windows.ERROR_NONE_MAPPED)
		got, reason := windowsProfileEnrollmentDecision(profile, []string{`CONTOSO\alice`}, nil, failing)
		if got != windowsEnrollmentUndecided || !strings.Contains(reason, "keeping the existing rows unchanged") {
			t.Fatalf("decision = %d (%s), want undecided while the account name is unavailable", got, reason)
		}
		if got, _ := windowsProfileEnrollmentDecision(profile, []string{"bob"}, nil, failing); got != windowsEnrollmentExcluded {
			t.Fatalf("a directory-name exclusion must still apply during a lookup failure, got %d", got)
		}
	})
}

// GAP-1034: a disabled local account cannot sign in, so a never-started
// Claude Code in its profile is not reported as unprotected (which kept
// security_complete false for good); an enabled account's still is.
func TestEnumerateWindowsDisabledLocalAccountIsNotReportedUnprotected(t *testing.T) {
	stubMachineWinGet(t, nil)
	previousDomain, previousDisabled := windowsMachineAccountDomainSID, windowsLocalAccountDisabled
	t.Cleanup(func() { windowsMachineAccountDomainSID, windowsLocalAccountDisabled = previousDomain, previousDisabled })
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".local", "bin", "claude.exe"), []byte("MZ"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubActiveSessions(t, map[string][]string{})
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	for _, disabled := range []bool{true, false} {
		windowsLocalAccountDisabled = func(string) (bool, error) { return disabled, nil }
		var reported []UnprotectedAgent
		if _, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("claudecode"), EnumerateOptions{
			ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
		}); err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 0, false: 1}[disabled]; len(reported) != want {
			t.Fatalf("disabled=%v: reported %+v, want %d", disabled, reported, want)
		}
	}
}

// GAP-0430: a deleted local account (LookupAccountSid says ERROR_NONE_MAPPED)
// is revoked even when its profile folder remains; a domain account whose
// lookup fails, or a lookup that timed out, is not judged deleted.
func TestWindowsDeletedLocalAccountNeedsANoneMappedLocalSID(t *testing.T) {
	previous := windowsMachineAccountDomainSID
	t.Cleanup(func() { windowsMachineAccountDomainSID = previous })
	windowsMachineAccountDomainSID = func() (string, error) { return testMachineDomainSID, nil }
	local := testMachineDomainSID + "-1182"
	noneMapped := func(string) (string, string, error) { return "", "", windows.ERROR_NONE_MAPPED }
	timedOut := func(string) (string, string, error) { return "", "", errors.New("account name lookup timed out") }
	if !windowsDeletedLocalAccount(local, noneMapped) {
		t.Fatal("a deleted local account was not judged deleted")
	}
	if windowsDeletedLocalAccount(local, timedOut) {
		t.Fatal("a timed-out lookup was judged a deleted account")
	}
	if windowsDeletedLocalAccount("S-1-5-21-111-222-333-1104", noneMapped) {
		t.Fatal("a domain account was judged deleted")
	}
}
