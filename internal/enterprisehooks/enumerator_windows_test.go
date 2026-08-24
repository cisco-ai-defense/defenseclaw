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
			got := effectiveWindowsHookConnectors(tc.cfg)
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
// AgentVersion + Enabled preservation invariant spec 005 REQ-08's
// design says: a row that already exists in the file keeps its
// agent_version + enabled state across enumeration cycles. A NEW
// row starts with Enabled=false so LoadManifest's schema validation
// skips it (avoiding a load-time reject on empty AgentVersion).
func TestApplyPreviousRowStatePreservesAgentVersion(t *testing.T) {
	enabled := true
	previous := map[string]ManifestTarget{
		previousManifestKey("S-1-5-21-1000-2000-3000-1001", "codex"): {
			SID:          "S-1-5-21-1000-2000-3000-1001",
			Connector:    "codex",
			AgentVersion: "0.145.0",
			Enabled:      &enabled,
		},
	}

	// Match: preserve AgentVersion + Enabled.
	matched := ManifestTarget{
		SID:       "s-1-5-21-1000-2000-3000-1001", // deliberate case
		Connector: "codex",
	}
	applyPreviousRowState(&matched, previous, nil)
	if matched.AgentVersion != "0.145.0" {
		t.Fatalf("existing-row AgentVersion not preserved: got %q, want %q", matched.AgentVersion, "0.145.0")
	}
	if matched.Enabled == nil || !*matched.Enabled {
		t.Fatal("existing-row Enabled=true not preserved")
	}

	// No match: emit disabled with empty AgentVersion.
	fresh := ManifestTarget{
		SID:       "S-1-5-21-9999-8888-7777-1001",
		Connector: "claudecode",
	}
	applyPreviousRowState(&fresh, previous, nil)
	if fresh.AgentVersion != "" {
		t.Fatalf("fresh row: AgentVersion should be empty; got %q", fresh.AgentVersion)
	}
	if fresh.Enabled == nil || *fresh.Enabled {
		t.Fatal("fresh row: Enabled should be pointer-to-false")
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
