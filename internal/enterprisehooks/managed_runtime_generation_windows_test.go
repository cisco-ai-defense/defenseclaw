// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsManagedRuntimeGenerationOldOrNewPublication(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, ".defenseclaw")
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve test SID: %v", err)
	}
	target := user.User.Sid
	for _, path := range []string{dataDir, hookDir} {
		if err := setWindowsUserPathProtection(path, target, true); err != nil {
			t.Fatalf("protect target directory %s: %v", path, err)
		}
		if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
			t.Fatalf("validate target directory %s: %v", path, err)
		}
	}

	selectorPath := filepath.Join(base, windowsManagedRuntimeSelectorFile)
	originalPath := windowsManagedRuntimeSelectorPathResolver
	originalOwner := windowsManagedPolicyOwnerSID
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalAncestorTrust := windowsManagedPolicyAncestorTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalMutation := windowsManagedRuntimeSelectorMutationAuthorize
	originalVerifyAuthorize := windowsManagedRuntimeSelectorVerifyAuthorize
	originalHookTrust := windowsEnterpriseHookTrustCheck
	windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) {
		return selectorPath, nil
	}
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return target, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	windowsManagedRuntimeSelectorVerifyAuthorize = func() error { return nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver = originalPath
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyAncestorTrustCheck = originalAncestorTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedRuntimeSelectorMutationAuthorize = originalMutation
		windowsManagedRuntimeSelectorVerifyAuthorize = originalVerifyAuthorize
		windowsEnterpriseHookTrustCheck = originalHookTrust
	})

	now := time.Now().UTC().Format(time.RFC3339Nano)
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:                  "codex",
		TargetSID:                  target.String(),
		DataDir:                    dataDir,
		HookExecutable:             filepath.Join(base, "defenseclaw-hook.exe"),
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway",
		ScopedToken:                "scoped-test-token",
		HookContractID:             "codex-hooks-v1",
		HookContractLockUpdatedAt:  now,
		HookContractEntryUpdatedAt: now,
	}
	first, err := PrepareWindowsManagedRuntimeGeneration(desired)
	if err != nil {
		t.Fatalf("prepare first generation: %v", err)
	}
	if first.Reused() || len(first.GenerationID()) != 32 ||
		!strings.HasPrefix(first.BundleSHA256(), "sha256:") {
		t.Fatalf("unexpected first publication: reused=%v generation=%q digest=%q", first.Reused(), first.GenerationID(), first.BundleSHA256())
	}
	firstCommit, err := CommitWindowsManagedRuntimeGeneration(first)
	if err != nil || !firstCommit.Changed() {
		t.Fatalf("commit first generation: changed=%v err=%v", firstCommit.Changed(), err)
	}

	resolve := WindowsManagedRuntimeGenerationResolveOptions{
		Connector:               desired.Connector,
		TargetSID:               desired.TargetSID,
		DataDir:                 desired.DataDir,
		HookExecutable:          desired.HookExecutable,
		MachinePolicyRegistered: true,
	}
	oldRuntime, err := ResolveWindowsManagedRuntimeGeneration(resolve)
	if err != nil {
		t.Fatalf("resolve first generation: %v", err)
	}
	if oldRuntime.GenerationID != first.GenerationID() ||
		oldRuntime.GatewayAddr != desired.GatewayAddr ||
		oldRuntime.ScopedToken() != desired.ScopedToken {
		t.Fatal("first resolved generation does not match its complete immutable bundle")
	}
	if err := VerifyWindowsManagedRuntimeGeneration(desired); err != nil {
		t.Fatalf("privileged read-only generation verification: %v", err)
	}
	// A later connector reconciliation advances the shared lock timestamp,
	// but does not change this connector's entry. The selected generation must
	// remain reusable and verifiable against that stable entry identity.
	globalLockAdvanced := desired
	globalLockAdvanced.HookContractLockUpdatedAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	if err := VerifyWindowsManagedRuntimeGeneration(globalLockAdvanced); err != nil {
		t.Fatalf("shared lock timestamp invalidated unchanged connector generation: %v", err)
	}
	reused, err := PrepareWindowsManagedRuntimeGeneration(globalLockAdvanced)
	if err != nil {
		t.Fatalf("prepare unchanged connector after shared lock update: %v", err)
	}
	if !reused.Reused() || reused.GenerationID() != first.GenerationID() {
		t.Fatalf(
			"shared lock update republished unchanged connector generation: reused=%v generation=%q want=%q",
			reused.Reused(),
			reused.GenerationID(),
			first.GenerationID(),
		)
	}
	changedEntry := globalLockAdvanced
	changedEntry.HookContractEntryUpdatedAt = globalLockAdvanced.HookContractLockUpdatedAt
	if err := VerifyWindowsManagedRuntimeGeneration(changedEntry); err == nil {
		t.Fatal("privileged generation verifier accepted a changed connector entry timestamp")
	}
	wrongToken := desired
	wrongToken.ScopedToken = "wrong-scoped-test-token"
	if err := VerifyWindowsManagedRuntimeGeneration(wrongToken); err == nil {
		t.Fatal("privileged generation verifier accepted a different scoped token")
	}
	oldSelector, err := CaptureWindowsManagedRuntimeSelector("codex")
	if err != nil || !oldSelector.Existed {
		t.Fatalf("capture old complete selector: existed=%v err=%v", oldSelector.Existed, err)
	}

	nextDesired := desired
	nextDesired.GatewayAddr = "127.0.0.1:18971"
	nextDesired.GatewayServiceName = "DefenseClawGatewayNext"
	nextDesired.ScopedToken = "next-scoped-test-token"
	next, err := PrepareWindowsManagedRuntimeGeneration(nextDesired)
	if err != nil {
		t.Fatalf("prepare next generation: %v", err)
	}
	if next.Reused() || next.GenerationID() == first.GenerationID() {
		t.Fatal("changed desired runtime unexpectedly reused the selected generation")
	}
	stillOld, err := ResolveWindowsManagedRuntimeGeneration(resolve)
	if err != nil || stillOld.GenerationID != first.GenerationID() ||
		stillOld.GatewayAddr != desired.GatewayAddr {
		t.Fatalf("uncommitted generation became visible: generation=%q gateway=%q err=%v", stillOld.GenerationID, stillOld.GatewayAddr, err)
	}
	nextCommit, err := CommitWindowsManagedRuntimeGeneration(next)
	if err != nil || !nextCommit.Changed() {
		t.Fatalf("commit next generation: changed=%v err=%v", nextCommit.Changed(), err)
	}
	current, err := ResolveWindowsManagedRuntimeGeneration(resolve)
	if err != nil || current.GenerationID != next.GenerationID() ||
		current.GatewayAddr != nextDesired.GatewayAddr ||
		current.GatewayServiceName != nextDesired.GatewayServiceName ||
		current.ScopedToken() != nextDesired.ScopedToken {
		t.Fatalf("next complete generation was not selected: generation=%q gateway=%q service=%q err=%v", current.GenerationID, current.GatewayAddr, current.GatewayServiceName, err)
	}
	newSelector, err := CaptureWindowsManagedRuntimeSelector("codex")
	if err != nil || !newSelector.Existed || newSelector.CAS == oldSelector.CAS {
		t.Fatalf("capture new complete selector: existed=%v changed=%v err=%v", newSelector.Existed, newSelector.CAS != oldSelector.CAS, err)
	}
	if err := RestoreWindowsManagedRuntimeSelectorCAS(
		WindowsManagedRuntimeSelectorFullRestoreOptions{
			Snapshot:        oldSelector,
			ExpectedCurrent: newSelector.CAS,
		},
	); err != nil {
		t.Fatalf("restore old complete selector by CAS: %v", err)
	}
	rolledBack, err := ResolveWindowsManagedRuntimeGeneration(resolve)
	if err != nil || rolledBack.GenerationID != first.GenerationID() {
		t.Fatalf("selector rollback did not restore first generation: generation=%q err=%v", rolledBack.GenerationID, err)
	}

	thirdDesired := nextDesired
	thirdDesired.GatewayAddr = "127.0.0.1:18972"
	thirdDesired.GatewayServiceName = "DefenseClawGatewayFinal"
	thirdDesired.ScopedToken = "final-scoped-test-token"
	third, err := PrepareWindowsManagedRuntimeGeneration(thirdDesired)
	if err != nil {
		t.Fatalf("prepare committed outer generation: %v", err)
	}
	thirdCommit, err := CommitWindowsManagedRuntimeGeneration(third)
	if err != nil {
		t.Fatalf("commit outer generation: %v", err)
	}
	if err := thirdCommit.Finalize(); err != nil {
		t.Fatalf("finalize prior generation after outer commit: %v", err)
	}
	if _, err := os.Lstat(first.BundlePath()); !os.IsNotExist(err) {
		t.Fatalf("finalized prior bundle still exists: %v", err)
	}

	orphanDesired := thirdDesired
	orphanDesired.GatewayAddr = "127.0.0.1:18973"
	orphanDesired.ScopedToken = "orphan-scoped-test-token"
	orphan, err := PrepareWindowsManagedRuntimeGeneration(orphanDesired)
	if err != nil {
		t.Fatalf("prepare unselected orphan generation: %v", err)
	}
	removed, err := GarbageCollectWindowsManagedRuntimeGenerations(
		WindowsManagedRuntimeGenerationGCOptions{
			Connector:      thirdDesired.Connector,
			TargetSID:      thirdDesired.TargetSID,
			DataDir:        thirdDesired.DataDir,
			HookExecutable: thirdDesired.HookExecutable,
		},
	)
	if err != nil || removed != 2 {
		t.Fatalf("collect unselected prior and orphan generations: removed=%d err=%v", removed, err)
	}
	for _, path := range []string{next.BundlePath(), orphan.BundlePath()} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("unselected bundle survived authenticated GC: %s err=%v", path, err)
		}
	}
	if _, err := os.Lstat(third.BundlePath()); err != nil {
		t.Fatalf("selected generation was removed by GC: %v", err)
	}

	// DataDir is intentionally left empty here: this is the
	// deleted-profile removal shape, where the caller no longer has
	// the profile-owned data directory to compare against. The
	// validator in validateWindowsManagedRuntimeSelectorTargetAgainstRemoval
	// skips the DataDir comparison whenever opts.DataDir is empty, so
	// Connector, TargetSID, and HookExecutable remain the identity
	// checks that authorize the removal.
	removal, err := RemoveWindowsManagedRuntimeGenerationEnrollment(
		WindowsManagedRuntimeGenerationRemovalOptions{
			Connector:                thirdDesired.Connector,
			TargetSID:                thirdDesired.TargetSID,
			HookExecutable:           thirdDesired.HookExecutable,
			PrimaryEnrollmentRemoved: true,
		},
	)
	if err != nil || !removal.Changed() {
		t.Fatalf("remove selector with deleted-profile-compatible authority: changed=%v err=%v", removal.Changed(), err)
	}
	if err := removal.Finalize(); err != nil {
		t.Fatalf("finalize removed selector bundle: %v", err)
	}
	if _, err := os.Lstat(third.BundlePath()); !os.IsNotExist(err) {
		t.Fatalf("removed selector token bundle survived finalization: %v", err)
	}
}

func TestWindowsManagedRuntimeGenerationGCAllowsAbsentHooksWithoutSelection(t *testing.T) {
	fixture := newWindowsManagedRuntimeGenerationMissingHooksGCFixture(t)
	if err := validateWindowsManagedRuntimeGenerationRoots(
		fixture.options.DataDir,
		fixture.target,
	); err == nil {
		t.Fatal("strict publication/verification root validator accepted absent hooks")
	}
	if err := publishWindowsManagedRuntimeSelector(windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     fixture.options.Connector,
		Targets:       []windowsManagedRuntimeSelectorTarget{},
	}); err != nil {
		t.Fatalf("publish protected selector without target SID: %v", err)
	}
	before, err := os.Lstat(fixture.options.DataDir)
	if err != nil {
		t.Fatal(err)
	}

	removed, err := GarbageCollectWindowsManagedRuntimeGenerations(fixture.options)
	if err != nil || removed != 0 {
		t.Fatalf("collect empty pre-activation runtime: removed=%d err=%v", removed, err)
	}
	after, err := os.Lstat(fixture.options.DataDir)
	if err != nil {
		t.Fatalf("authenticated data root disappeared during empty GC: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("empty GC replaced the authenticated data root")
	}
	if err := validateWindowsUserPathElement(
		fixture.options.DataDir,
		fixture.target,
		true,
		true,
		true,
	); err != nil {
		t.Fatalf("empty GC changed the authenticated data root: %v", err)
	}
	entries, err := os.ReadDir(fixture.options.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty GC created user-runtime children: %+v", entries)
	}
	if _, err := os.Lstat(filepath.Join(fixture.options.DataDir, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty GC created or substituted the absent hooks directory: %v", err)
	}
}

func TestWindowsManagedRuntimeGenerationGCFailsClosedWhenSelectedHooksAreAbsent(t *testing.T) {
	fixture := newWindowsManagedRuntimeGenerationMissingHooksGCFixture(t)
	selector := windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     fixture.options.Connector,
		Targets: []windowsManagedRuntimeSelectorTarget{
			{
				Connector:          fixture.options.Connector,
				SID:                fixture.options.TargetSID,
				DataDir:            fixture.options.DataDir,
				HookExecutable:     fixture.options.HookExecutable,
				GatewayAddr:        "127.0.0.1:18970",
				GatewayServiceName: "DefenseClawGateway",
				GenerationID:       strings.Repeat("a", 32),
				BundleSHA256:       "sha256:" + strings.Repeat("b", 64),
			},
		},
	}
	if err := publishWindowsManagedRuntimeSelector(selector); err != nil {
		t.Fatalf("publish protected selected-generation fixture: %v", err)
	}

	removed, err := GarbageCollectWindowsManagedRuntimeGenerations(fixture.options)
	if err == nil || !errors.Is(err, os.ErrNotExist) || removed != 0 {
		t.Fatalf("selected generation with absent hooks did not fail closed: removed=%d err=%v", removed, err)
	}
	if !strings.Contains(err.Error(), "selected managed runtime generation directory is absent") {
		t.Fatalf("selected absent-hooks failure lost its security boundary: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(fixture.options.DataDir, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed closed GC created or substituted the absent hooks directory: %v", err)
	}
	if err := validateWindowsUserPathElement(
		fixture.options.DataDir,
		fixture.target,
		true,
		true,
		true,
	); err != nil {
		t.Fatalf("failed closed GC changed the authenticated data root: %v", err)
	}
}

type windowsManagedRuntimeGenerationMissingHooksGCFixture struct {
	options WindowsManagedRuntimeGenerationGCOptions
	target  *windows.SID
}

func newWindowsManagedRuntimeGenerationMissingHooksGCFixture(
	t *testing.T,
) windowsManagedRuntimeGenerationMissingHooksGCFixture {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve test SID: %v", err)
	}
	target := user.User.Sid
	home := newWindowsTargetOwnedTestHome(t, target)
	dataDir := filepath.Join(home, ".defenseclaw")
	if _, err := ensureWindowsTargetOwnedDirectoryTree(home, dataDir, target); err != nil {
		t.Fatalf("create protected data root without hooks: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hooks")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing-hooks fixture unexpectedly has a hooks child: %v", err)
	}

	policyDir := filepath.Join(t.TempDir(), "managed-policy")
	selectorPath := filepath.Join(policyDir, windowsManagedRuntimeSelectorFile)
	originalPath := windowsManagedRuntimeSelectorPathResolver
	originalOwner := windowsManagedPolicyOwnerSID
	originalDirTrust := windowsManagedPolicyDirTrustCheck
	originalAncestorTrust := windowsManagedPolicyAncestorTrustCheck
	originalFileTrust := windowsManagedPolicyFileTrustCheck
	originalMutation := windowsManagedRuntimeSelectorMutationAuthorize
	windowsManagedRuntimeSelectorPathResolver = func(string) (string, error) {
		return selectorPath, nil
	}
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return target, nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorMutationAuthorize = func() error { return nil }
	t.Cleanup(func() {
		windowsManagedRuntimeSelectorPathResolver = originalPath
		windowsManagedPolicyOwnerSID = originalOwner
		windowsManagedPolicyDirTrustCheck = originalDirTrust
		windowsManagedPolicyAncestorTrustCheck = originalAncestorTrust
		windowsManagedPolicyFileTrustCheck = originalFileTrust
		windowsManagedRuntimeSelectorMutationAuthorize = originalMutation
	})
	if err := ensureWindowsManagedPolicyDirectory(policyDir); err != nil {
		t.Fatalf("create protected selector fixture directory: %v", err)
	}

	return windowsManagedRuntimeGenerationMissingHooksGCFixture{
		target: target,
		options: WindowsManagedRuntimeGenerationGCOptions{
			Connector:      "codex",
			TargetSID:      target.String(),
			DataDir:        dataDir,
			HookExecutable: filepath.Join(home, "defenseclaw-hook.exe"),
		},
	}
}

func TestWindowsManagedRuntimeGenerationSelectorCASRejectsSameSIDRace(t *testing.T) {
	selector := windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     "cursor",
		Targets:       []windowsManagedRuntimeSelectorTarget{},
	}
	entry := windowsManagedRuntimeSelectorTarget{
		Connector:          "cursor",
		SID:                "S-1-5-21-1-2-3-1001",
		DataDir:            `C:\Users\test\.defenseclaw`,
		HookExecutable:     `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		GenerationID:       strings.Repeat("a", 32),
		BundleSHA256:       "sha256:" + strings.Repeat("b", 64),
	}
	selector = setWindowsManagedRuntimeSelectorTarget(selector, &entry)
	current, exists := windowsManagedRuntimeSelectorTargetForSID(selector, entry.SID)
	if !windowsManagedRuntimeOptionalSelectorTargetsEqual(current, exists, &entry) {
		t.Fatal("exact selector preimage was not recognized")
	}
	concurrent := entry
	concurrent.GenerationID = strings.Repeat("c", 32)
	selector = setWindowsManagedRuntimeSelectorTarget(selector, &concurrent)
	current, exists = windowsManagedRuntimeSelectorTargetForSID(selector, entry.SID)
	if windowsManagedRuntimeOptionalSelectorTargetsEqual(current, exists, &entry) {
		t.Fatal("stale same-SID selector preimage was accepted")
	}
}

func TestWindowsManagedRuntimeBundleLeafIsStrictlyDerived(t *testing.T) {
	generationID := strings.Repeat("a", 32)
	leaf, err := windowsManagedRuntimeBundleLeaf("claudecode", generationID)
	if err != nil {
		t.Fatal(err)
	}
	connectorName, parsedGeneration, ok := parseWindowsManagedRuntimeBundleLeaf(leaf)
	if !ok || connectorName != "claudecode" || parsedGeneration != generationID {
		t.Fatalf("bundle leaf did not round trip: connector=%q generation=%q ok=%v", connectorName, parsedGeneration, ok)
	}
	for _, invalid := range []string{
		`..\` + leaf,
		leaf + ".tmp",
		"managed-runtime-claudecode-" + generationID + ".json",
		".managed-runtime-CLAUDECODE-" + generationID + ".json",
		".managed-runtime-claudecode-" + strings.Repeat("g", 32) + ".json",
	} {
		if _, _, ok := parseWindowsManagedRuntimeBundleLeaf(invalid); ok {
			t.Fatalf("unsafe bundle leaf was accepted: %q", invalid)
		}
	}
}

func TestWindowsManagedRuntimeSelectorStrictSchemaAndTokenRedaction(t *testing.T) {
	selector := windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     "codex",
		Targets:       []windowsManagedRuntimeSelectorTarget{},
	}
	data, err := marshalWindowsManagedRuntimeSelector(selector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeWindowsManagedRuntimeSelector(data, "codex"); err != nil {
		t.Fatalf("canonical selector rejected: %v", err)
	}
	noncanonical := append([]byte(" "), data...)
	if _, err := decodeWindowsManagedRuntimeSelector(noncanonical, "codex"); err == nil {
		t.Fatal("noncanonical selector whitespace was accepted")
	}
	unknown := bytes.Replace(data, []byte(`"targets":`), []byte(`"unknown":true,"targets":`), 1)
	if _, err := decodeWindowsManagedRuntimeSelector(unknown, "codex"); err == nil {
		t.Fatal("unknown selector field was accepted")
	}

	desired := WindowsManagedRuntimeGenerationDesired{ScopedToken: "must-not-serialize"}
	encoded, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(desired.ScopedToken)) {
		t.Fatal("scoped token leaked through desired orchestration JSON")
	}
	resolved := WindowsManagedRuntimeGenerationResolved{scopedToken: desired.ScopedToken}
	publication := WindowsManagedRuntimeGenerationPublication{
		desired:     desired,
		bundleBytes: []byte(desired.ScopedToken),
	}
	encoded, err = json.Marshal(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(desired.ScopedToken)) {
		t.Fatal("scoped token leaked through resolved runtime JSON")
	}
	for _, rendered := range []string{
		fmt.Sprintf("%+v", desired),
		fmt.Sprintf("%#v", desired),
		fmt.Sprintf("%+v", resolved),
		fmt.Sprintf("%#v", resolved),
		fmt.Sprintf("%+v", publication),
		fmt.Sprintf("%#v", publication),
	} {
		if strings.Contains(rendered, desired.ScopedToken) {
			t.Fatal("scoped token leaked through ordinary runtime formatting")
		}
	}
}

func TestWindowsManagedRuntimeGenerationPrimaryEnrollmentRemainsAuthoritative(t *testing.T) {
	_, err := ResolveWindowsManagedRuntimeGeneration(
		WindowsManagedRuntimeGenerationResolveOptions{
			Connector:               "codex",
			TargetSID:               "S-1-5-21-1-2-3-1001",
			DataDir:                 `C:\Users\test\.defenseclaw`,
			HookExecutable:          `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`,
			MachinePolicyRegistered: false,
		},
	)
	if err == nil || !strings.Contains(err.Error(), WindowsManagedSIDUnregisteredReason) {
		t.Fatalf("unregistered primary policy was not rejected: %v", err)
	}
}

func TestWindowsManagedRuntimeGenerationEqualityUsesConnectorScopedContractIdentity(t *testing.T) {
	const (
		targetSID   = "S-1-5-21-1000-1000-1000-1001"
		dataDir     = `C:\Users\developer\.defenseclaw`
		hookPath    = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`
		gatewayAddr = "127.0.0.1:18970"
		gatewayName = "DefenseClawGateway-Test"
		finalLock   = "2026-08-24T10:00:03Z"
	)
	tests := []struct {
		connector    string
		contractID   string
		entryUpdated string
		lockUpdated  string
	}{
		{
			connector:    "claudecode",
			contractID:   "claudecode-hooks-v1",
			entryUpdated: "2026-08-24T10:00:01Z",
			lockUpdated:  "2026-08-24T10:00:01Z",
		},
		{
			connector:    "codex",
			contractID:   "codex-hooks-v1",
			entryUpdated: "2026-08-24T10:00:02Z",
			lockUpdated:  "2026-08-24T10:00:02Z",
		},
		{
			connector:    "cursor",
			contractID:   "cursor-hooks-v1",
			entryUpdated: finalLock,
			lockUpdated:  finalLock,
		},
	}
	for _, test := range tests {
		t.Run(test.connector, func(t *testing.T) {
			published := WindowsManagedRuntimeGenerationDesired{
				Connector:                  test.connector,
				TargetSID:                  targetSID,
				DataDir:                    dataDir,
				HookExecutable:             hookPath,
				GatewayAddr:                gatewayAddr,
				GatewayServiceName:         gatewayName,
				ScopedToken:                "scoped-" + test.connector + "-token",
				HookContractID:             test.contractID,
				HookContractLockUpdatedAt:  test.lockUpdated,
				HookContractEntryUpdatedAt: test.entryUpdated,
			}
			bundle := windowsManagedRuntimeBundleFromDesired(
				published,
				strings.Repeat("a", 32),
			)
			current := published
			// This models the shared lock after the last connector was added.
			// Earlier connector entries remain unchanged even though updated_at
			// on hook_contract_lock.json now reflects the Cursor write.
			current.HookContractLockUpdatedAt = finalLock
			if _, _, err := validateWindowsManagedRuntimeGenerationDesired(current); err != nil {
				t.Fatalf("final desired contract is invalid: %v", err)
			}
			if !windowsManagedRuntimeBundleMatchesDesired(bundle, current) {
				t.Fatal("peer connector lock update invalidated unchanged connector generation")
			}

			changedEntry := current
			changedEntry.HookContractEntryUpdatedAt = "2026-08-24T10:00:00Z"
			if windowsManagedRuntimeBundleMatchesDesired(bundle, changedEntry) {
				t.Fatal("changed connector entry timestamp matched immutable generation")
			}
		})
	}
}

func TestWindowsManagedRuntimeGenerationEqualityRejectsEveryAuthenticatedContractDrift(t *testing.T) {
	desired := WindowsManagedRuntimeGenerationDesired{
		Connector:                  "codex",
		TargetSID:                  "S-1-5-21-1000-1000-1000-1001",
		DataDir:                    `C:\Users\developer\.defenseclaw`,
		HookExecutable:             `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:                "127.0.0.1:18970",
		GatewayServiceName:         "DefenseClawGateway-Test",
		ScopedToken:                "scoped-codex-token",
		HookContractID:             "codex-hooks-v1",
		HookContractLockUpdatedAt:  "2026-08-24T10:00:03Z",
		HookContractEntryUpdatedAt: "2026-08-24T10:00:02Z",
	}
	bundle := windowsManagedRuntimeBundleFromDesired(desired, strings.Repeat("b", 32))
	tests := []struct {
		name   string
		mutate func(*windowsManagedRuntimeBundle, *WindowsManagedRuntimeGenerationDesired)
	}{
		{name: "connector", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.Connector = "cursor"
		}},
		{name: "target SID", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.TargetSID = "S-1-5-21-1000-1000-1000-1002"
		}},
		{name: "data directory", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.DataDir = `C:\Users\other\.defenseclaw`
		}},
		{name: "hook executable", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.HookExecutable = `C:\Program Files\DefenseClaw\other-hook.exe`
		}},
		{name: "gateway address", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.GatewayAddr = "127.0.0.1:18971"
		}},
		{name: "gateway service", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.GatewayServiceName = "DefenseClawGateway-Other"
		}},
		{name: "fail mode", mutate: func(got *windowsManagedRuntimeBundle, _ *WindowsManagedRuntimeGenerationDesired) {
			got.FailMode = "open"
		}},
		{name: "scoped token", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.ScopedToken = "different-scoped-codex-token"
		}},
		{name: "hook contract ID", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.HookContractID = "codex-hooks-v2"
		}},
		{name: "connector entry timestamp", mutate: func(_ *windowsManagedRuntimeBundle, want *WindowsManagedRuntimeGenerationDesired) {
			want.HookContractEntryUpdatedAt = "2026-08-24T10:00:01Z"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changedBundle := bundle
			changedDesired := desired
			test.mutate(&changedBundle, &changedDesired)
			if windowsManagedRuntimeBundleMatchesDesired(changedBundle, changedDesired) {
				t.Fatal("authenticated connector contract drift matched immutable generation")
			}
		})
	}
}
