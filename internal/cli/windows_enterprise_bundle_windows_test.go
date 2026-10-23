//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

func TestWindowsBundleHotWriteRecordsPrincipalAndSignedMetadata(t *testing.T) {
	const id = "b-01JA0000000000000000000033"
	opts := &windowsEnterpriseLifecycleOptions{bundle: &windowsBundleRun{prepared: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{
		BundleID: id, Version: 3, Principal: "control-plane:acme/alice", SignerKeyID: "k1", ChangeSummary: "guardrail pack update",
	}}}}
	got, bundle, err := windowsHotConfigWriteOptions(opts, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Actor != "control-plane:acme/alice" || got.LocalActor != configwrite.CurrentOSActor() || got.Bundle.ID != id || got.Bundle.Version != 3 ||
		got.Bundle.SignerKeyID != "k1" || got.Reason != configwrite.BundleReason(id, 3, "guardrail pack update") ||
		!got.Lifecycle || got.ExpectSHA256 != "abc" || bundle.ID != id || bundle.Version != 3 {
		t.Fatalf("Windows bundle hot write = %+v, adoption identity %+v", got, bundle)
	}
}

func TestWindowsBundleHotWriteAttributesAppliedAudit(t *testing.T) {
	layout := stubWindowsBundleHost(t)
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := []byte("config_version: 9\n")
	if err := os.WriteFile(layout.ConfigPath, previous, 0o600); err != nil {
		t.Fatal(err)
	}
	const id = "b-01JA0000000000000000000033"
	opts := &windowsEnterpriseLifecycleOptions{bundle: &windowsBundleRun{prepared: &enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{
		BundleID: id, Version: 3, Principal: "control-plane:acme/alice", SignerKeyID: "k1", ChangeSummary: "guardrail pack update",
	}}}}
	opt, _, err := windowsHotConfigWriteOptions(opts, configwrite.SHA256Hex(previous))
	if err != nil {
		t.Fatal(err)
	}
	_, err = configwrite.Locked(context.Background(), layout.ConfigPath, opt, func() (bool, error) {
		return true, os.WriteFile(layout.ConfigPath, []byte("config_version: 9\nguardrail:\n  enabled: true\n"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := observabilityruntime.ReadBundleAttribution(layout.ConfigPath)
	if !ok || got.Actor != configwrite.CurrentOSActor() || got.Principal != "control-plane:acme/alice" || got.ID != id || got.Version != 3 || got.SignerKeyID != "k1" {
		t.Fatalf("Windows config.change.applied bundle attribution = %+v, ok=%v", got, ok)
	}
}

const windowsBundleTestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestWindowsFirstBundleFailureIsRetryableAndNamesBasePolicy(t *testing.T) {
	result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "9.9.9")
	result.AddError("bundle_apply_failed", "the hot apply did not complete")
	result.Bundle = &enterprisestatus.BundleState{}
	result.SetBundleSessions(enterprisestatus.SessionRestartStatus{State: "unknown", Reason: "context deadline exceeded"})
	receipt := &enterprisebundle.Receipt{}
	recordWindowsBundleSessions(receipt, *result.Bundle.SessionsRestartRequired)
	if len(receipt.WarningCodes) != 1 || receipt.WarningCodes[0] != "sessions_scan_unknown" {
		t.Fatalf("unknown scan missing from receipt: %+v", receipt)
	}
	if got := windowsEnterpriseFailureCodeFor(result); got != enterprisestatus.WindowsExitBusy {
		t.Fatalf("retry exit = %d", got)
	}
	if got := windowsBundleNotApplied(&enterprisebundle.Prepared{Receipt: &enterprisebundle.Receipt{BundleID: "b-01JA0000000000000000000033", Version: 1}}, "apply_failed", false); !strings.Contains(got, "base policy") || strings.Contains(got, "last good") {
		t.Fatalf("first apply refusal = %q", got)
	}
	if len(result.Errors) != 1 || result.Errors[0].Code != "bundle_apply_failed" {
		t.Fatalf("unknown sessions scan changed apply errors: %+v", result.Errors)
	}
}

func TestWindowsBundleDeadlineRecordsSkippedRollback(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	receipt := &enterprisebundle.Receipt{}
	result := &enterprisestatus.Result{}
	if !windowsBundleRollbackDeadlineExpired(ctx, receipt, result) ||
		len(receipt.WarningCodes) != 1 || receipt.WarningCodes[0] != "rollback_skipped_deadline" ||
		len(result.Warnings) != 1 || result.Warnings[0].Code != "rollback_skipped_deadline" {
		t.Fatalf("deadline rollback receipt = %+v, result = %+v", receipt, result)
	}
	if windowsBundleRollbackDeadlineExpired(context.Background(), &enterprisebundle.Receipt{}, &enterprisestatus.Result{}) {
		t.Fatal("live deadline skipped rollback")
	}
}

func TestWindowsStatusSettlesOnlyEnforcedAppliedReceipt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation uint64
		digest     string
		want       bool
	}{
		{"enforced", 1, windowsBundleTestDigest, true},
		{"wrong generation", 2, windowsBundleTestDigest, false},
		{"wrong digest", 1, "sha256:" + strings.Repeat("2", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			layout := stubWindowsBundleHost(t)
			driver := newWindowsBundleDriver(layout)
			if _, _, err := installWindowsBundleAnchors(e.anchors, driver.AnchorsPath); err != nil {
				t.Fatal(err)
			}
			rc, err := driver.Store.Receive("b-01JA0000000000000000000033", 13, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := driver.Store.Stage(rc, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
				t.Fatal(err)
			}
			if err := driver.Store.Advance(rc, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
				r.ManifestSHA256 = strings.Repeat("a", 64)
				r.Principal, r.SignerKeyID = "operator:alice", "k1"
				r.ExpectedDigest = windowsBundleTestDigest
				r.SetDigestComparison(true, false, false)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := driver.Store.Promote(rc); err != nil {
				t.Fatal(err)
			}
			installed := []byte("config_version: 9\n")
			generation := recordWindowsBundleTestCommit(t, layout, rc, installed)
			if err := driver.Store.Advance(rc, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) {
				r.ConfigSHA256 = configwrite.SHA256Hex(installed)
				r.EffectivePolicyDigest = windowsBundleTestDigest
				r.ConfigGeneration = generation
			}); err != nil {
				t.Fatal(err)
			}
			policy := &enterprisebundle.GatewayPolicy{EffectiveDigest: tc.digest, Digest: tc.digest, Generation: tc.generation, BundleID: rc.BundleID, BundleVersion: rc.Version, Applied: true}
			got, err := settleWindowsAppliedBundle(driver, installed, policy)
			if err != nil || got != tc.want {
				t.Fatalf("settled=%v, err=%v", got, err)
			}
			st, err := driver.Store.LoadState()
			if err != nil {
				t.Fatal(err)
			}
			if (st.Current != nil) != tc.want {
				t.Fatalf("current=%+v", st.Current)
			}
			receipts, err := driver.Store.Receipts()
			if err != nil {
				t.Fatal(err)
			}
			wantState := enterprisebundle.StateApplied
			if tc.want {
				wantState = enterprisebundle.StateConfirmed
			}
			if len(receipts) != 1 || receipts[0].State != wantState {
				t.Fatalf("receipts=%+v", receipts)
			}
		})
	}
}

// Status can be the first process to see an applied receipt after the
// gateway upgrade. Its proof uses the stored bundle's current digest while
// the receipt retains the old build's historical digest.
func TestWindowsStatusConfirmsCarriedReceiptWithUpgradedDigest(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "carried.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, _ := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, opts)
	run := opts.bundle
	rc := run.prepared.Receipt
	generation := recordWindowsBundleTestCommit(t, layout, rc, run.prepared.Config)
	oldDigest := run.prepared.EffectivePolicyDigest
	if err := run.driver.Store.Advance(rc, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) {
		r.ConfigSHA256, r.ConfigGeneration, r.EffectivePolicyDigest = run.prepared.ConfigSHA256, generation, oldDigest
	}); err != nil {
		t.Fatal(err)
	}
	baseDigester := run.driver.Digester
	run.driver.Digester = func(ctx context.Context, cfg *config.Config, raw []byte, platform, root string) (string, error) {
		base, err := baseDigester(ctx, cfg, raw, platform, root)
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(base + ":1.0.4"))
		return fmt.Sprintf("sha256:%x", sum), nil
	}
	run.driver.ProductVersion = "1.0.4"
	versionDir := run.driver.Store.VersionDir(rc.Dir)
	stored, err := enterprisebundle.ReadDir(versionDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, rendered, err := enterprisebundle.LoadConfigForDeviceLayout(stored, versionDir,
		enterprisebundle.PlatformWindows, enterprisebundle.DeviceLayoutFromManaged(layout))
	if err != nil {
		t.Fatal(err)
	}
	currentDigest, err := run.driver.Digester(t.Context(), cfg, rendered, enterprisebundle.PlatformWindows, versionDir)
	if err != nil || currentDigest == oldDigest || !rc.DigestComparable {
		t.Fatalf("upgraded digest=%q old=%q comparable=%t error=%v", currentDigest, oldDigest, rc.DigestComparable, err)
	}
	policy := &enterprisebundle.GatewayPolicy{EffectiveDigest: currentDigest, Digest: currentDigest,
		Generation: generation, BundleID: rc.BundleID, BundleVersion: rc.Version, Applied: true}
	confirmed, err := settleWindowsAppliedBundle(run.driver, run.prepared.Config, policy)
	if err != nil || !confirmed {
		t.Fatalf("status did not confirm the enforcing upgraded gateway: confirmed=%t error=%v", confirmed, err)
	}
	if got := windowsBundleReceiptState(t, layout, rc.ReceiptID); got.State != enterprisebundle.StateConfirmed ||
		got.EffectivePolicyDigest != oldDigest {
		t.Fatalf("historical receipt=%+v", got)
	}
}

// recordWindowsBundleTestCommit uses the lifecycle writer rather than treating
// an identical config file as evidence that this signed bundle was installed.
func recordWindowsBundleTestCommit(t *testing.T, layout managed.StandaloneLayout, rc *enterprisebundle.Receipt, raw []byte) uint64 {
	t.Helper()
	opt, ok := enterprisebundle.GenerationOptions(rc)
	if !ok {
		t.Fatal("bundle receipt has no principal")
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := configwrite.Locked(t.Context(), layout.ConfigPath, opt, func() (bool, error) {
		return true, os.WriteFile(layout.ConfigPath, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.Generation
}

func windowsBundleScratchDir(t *testing.T) string {
	t.Helper()
	if scratch := os.Getenv("DC_WINDOWS_BUNDLE_TEST_TEMP_DIR"); scratch != "" {
		// GetTempPath2 ignores TEMP for SYSTEM on current Windows builds.
		root, err := os.MkdirTemp(scratch, "bundle-acl-*")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(root); err != nil {
				t.Error(err)
			}
		})
		return root
	}
	return t.TempDir()
}

func TestWindowsBundleVersionACLGrantsServiceReadOnly(t *testing.T) {
	const sid = "S-1-5-80-1-2-3-4-5"
	if got, want := windowsBundleDirectorySDDL(sid), "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)(A;OICI;0x1200a9;;;"+sid+")"; got != want {
		t.Fatalf("public bundle directory ACL = %q, want %q", got, want)
	}
	if got, want := windowsBundleReceiptSDDL(sid), "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)(A;;FR;;;"+sid+")"; got != want {
		t.Fatalf("public receipt ACL = %q, want %q", got, want)
	}
	if got, want := windowsBundlePrivateSDDL(), "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"; got != want {
		t.Fatalf("private staging ACL = %q, want %q", got, want)
	}
	if got, want := windowsBundleVersionSDDL(sid, true), "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;"+sid+")"; got != want {
		t.Fatalf("bundle version directory ACL = %q, want %q", got, want)
	}
	if got, want := windowsBundleVersionSDDL(sid, false), "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;"+sid+")"; got != want {
		t.Fatalf("bundle version file ACL = %q, want %q", got, want)
	}
	if strings.Contains(windowsBundlePrivateSDDL(), ";;;BU)") || strings.Contains(windowsBundleVersionSDDL(sid, true), ";;;BU)") || strings.Contains(windowsBundleVersionSDDL(sid, false), ";;;BU)") {
		t.Fatal("private staging or version assets grant Users access")
	}
}

func TestWindowsBundleReceiptsDirectoryCreatedProtected(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	path := filepath.Join(t.TempDir(), "install", enterprisebundle.ReceiptsDirName)
	if err := ensureWindowsBundlePrivateDirectory(path); err != nil {
		t.Fatal(err)
	}
	expected, err := windows.SecurityDescriptorFromString(windowsBundlePrivateSDDL())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Dir(path), path} {
		for attempt := 0; attempt < 2; attempt++ {
			if err := ensureWindowsBundlePrivateDirectory(directory); err != nil {
				t.Fatal(err)
			}
			actual, err := windows.GetNamedSecurityInfo(directory, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			control, _, err := actual.Control()
			if err != nil {
				t.Fatal(err)
			}
			if control&windows.SE_DACL_PROTECTED == 0 || strings.Contains(actual.String(), "(A;ID;") {
				t.Fatalf("private directory is not protected: %s: %s", directory, actual.String())
			}
			matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
			if err != nil || !matches {
				t.Fatalf("private directory descriptor differs from AdminDirectory: %s: %s (%v)", directory, actual.String(), err)
			}
		}
	}
}

func TestWindowsBundlePublicReceiptEventsCreatedProtected(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	const sid = "S-1-5-80-1-2-3-4-5"
	for _, inherited := range []bool{false, true} {
		name := "fresh"
		if inherited {
			name = "inherited"
		}
		t.Run(name, func(t *testing.T) {
			root := windowsBundleScratchDir(t)
			bundles := filepath.Join(root, enterprisebundle.BundlesDirName)
			if err := os.MkdirAll(bundles, 0o755); err != nil {
				t.Fatal(err)
			}
			store := enterprisebundle.NewStore(bundles, filepath.Join(root, "lifecycle"))
			store.EnsurePublicReceiptEventsDirectory = func(path string) error {
				return createWindowsBundleDirectory(path, windowsBundleDirectorySDDL(sid))
			}
			store.PublishReceipt = func(path string) error {
				return applyWindowsBundleSDDL(path, windowsBundleReceiptSDDL(sid))
			}
			if inherited {
				// Model the directory left by the old publisher.
				if err := os.MkdirAll(store.PublicReceiptEventsDir(), 0o755); err != nil {
					t.Fatal(err)
				}
				// Hosted runners can leave it owned by the local Administrator
				// account; lab hosts commonly use the Administrators group.
				user, err := windows.GetCurrentProcessToken().GetTokenUser()
				if err != nil {
					t.Fatal(err)
				}
				if err := windows.SetNamedSecurityInfo(store.PublicReceiptEventsDir(), windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
					t.Fatal(err)
				}
				before, err := windows.GetNamedSecurityInfo(store.PublicReceiptEventsDir(), windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("pre-existing receipt-events ACL: %s", before.String())
			}
			receipt, err := store.Receive("b-01JA0000000000000000000033", 1, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Fail(receipt, enterprisebundle.CodeInterrupted, "test refusal"); err != nil {
				t.Fatal(err)
			}
			for path, sddl := range map[string]string{
				store.PublicReceiptEventsDir():                                           windowsBundleDirectorySDDL(sid),
				filepath.Join(store.PublicReceiptEventsDir(), receipt.ReceiptID+".json"): windowsBundleReceiptSDDL(sid),
			} {
				expected, err := windows.SecurityDescriptorFromString(sddl)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
				if err != nil {
					t.Fatal(err)
				}
				matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
				if err != nil || !matches {
					t.Fatalf("public receipt path differs from exact ACL: %s: %s (%v)", path, actual.String(), err)
				}
				if inherited && path == store.PublicReceiptEventsDir() {
					t.Logf("repaired receipt-events ACL: %s", actual.String())
				}
			}
		})
	}
}

func TestWindowsBundleInheritedDirectoriesRepairExactACL(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	const sid = "S-1-5-80-1-2-3-4-5"
	private := windowsBundlePrivateSDDL()
	public := windowsBundleDirectorySDDL(sid)
	cases := []struct {
		name, relative, sddl string
		ensure               func(root, path string) error
	}{
		{"staging", filepath.Join("bundles", ".staging"), private, func(root, path string) error {
			return ensureWindowsBundleStageDirectory(filepath.Join(root, "bundles"), path)
		}},
		{"receipts", filepath.Join("lifecycle", enterprisebundle.ReceiptsDirName), private, func(_, path string) error {
			return ensureWindowsBundlePrivateDirectory(path)
		}},
		{"trust", "trust", private, func(_, path string) error {
			return ensureWindowsBundlePrivateDirectory(path)
		}},
		{"bundles", enterprisebundle.BundlesDirName, public, func(_, path string) error {
			return createWindowsBundleDirectory(path, public)
		}},
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := windowsBundleScratchDir(t)
			path := filepath.Join(root, tc.relative)
			if err := os.MkdirAll(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := tc.ensure(root, path); err != nil {
					t.Fatal(err)
				}
			}
			expected, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}
			matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
			if err != nil || !matches {
				t.Fatalf("inherited %s directory differs from exact ACL: %s (%v)", tc.name, actual.String(), err)
			}
		})
	}
}

func TestWindowsBundleStageDirectoryRepeatedCreationRepairsExactACL(t *testing.T) {
	if !windowsEnterpriseIsElevated() {
		t.Skip("setting the Administrators owner requires elevation")
	}
	root := filepath.Join(t.TempDir(), ".staging-test")
	nested := filepath.Join(root, "policies", "guardrail")
	for _, path := range []string{root, root, nested, nested, root} {
		if err := ensureWindowsBundleStageDirectory(root, path); err != nil {
			t.Fatalf("ensure %s: %v", path, err)
		}
	}
	// A directory with the right owner but a stale DACL must be repaired.
	if err := applyWindowsBundleSDDL(nested, "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)"); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsBundleStageDirectory(root, nested); err != nil {
		t.Fatal(err)
	}
	expected, err := windows.SecurityDescriptorFromString(windowsBundlePrivateSDDL())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "policies"), nested} {
		actual, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		matches, err := windowsEnterpriseExactDescriptorMatch(actual, expected)
		if err != nil || !matches {
			t.Fatalf("stage directory %s descriptor differs from AdminDirectory: %s (%v)", path, actual.String(), err)
		}
	}
}

// stubWindowsBundleHost points the Windows bundle code at a temp standalone
// layout whose gateway enforces windowsBundleTestDigest.
func stubWindowsBundleHost(t *testing.T) managed.StandaloneLayout {
	t.Helper()
	root := t.TempDir()
	layout, err := managed.StandaloneWindowsLayoutForRoots(filepath.Join(root, "pf"), filepath.Join(root, "pd"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
			if err == nil {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	savedLayout, savedPolicy, savedSleep, savedTrust, savedAnchorTrust := windowsBundleLayout, windowsBundlePolicy, windowsBundleSleep, windowsBundleTrust, bundleAnchorTrust
	savedPrivate, savedSeal, savedPublish, savedReceipt, savedEnsure := windowsBundlePrivateStage, windowsBundleSealVersion, windowsBundlePublishVersion, windowsBundlePublishReceipt, windowsBundleEnsureDirectory
	savedEnsurePrivate, savedPublishPrivate := windowsBundleEnsurePrivateDirectory, windowsBundlePublishPrivateFile
	savedEnsureStage, savedPublishStage := windowsBundleEnsureStageDirectory, windowsBundlePublishStageFile
	t.Cleanup(func() {
		windowsBundleLayout, windowsBundlePolicy, windowsBundleSleep, windowsBundleTrust, bundleAnchorTrust = savedLayout, savedPolicy, savedSleep, savedTrust, savedAnchorTrust
		windowsBundlePrivateStage, windowsBundleSealVersion, windowsBundlePublishVersion = savedPrivate, savedSeal, savedPublish
		windowsBundlePublishReceipt = savedReceipt
		windowsBundleEnsureDirectory = savedEnsure
		windowsBundleEnsurePrivateDirectory, windowsBundlePublishPrivateFile = savedEnsurePrivate, savedPublishPrivate
		windowsBundleEnsureStageDirectory, windowsBundlePublishStageFile = savedEnsureStage, savedPublishStage
	})
	windowsBundleLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy {
		policy := &enterprisebundle.GatewayPolicy{EffectiveDigest: windowsBundleTestDigest, Digest: windowsBundleTestDigest, Applied: true}
		state, err := configwrite.ReadGenerationState(layout.ConfigPath)
		if err != nil {
			return policy
		}
		policy.Generation, policy.BundleID, policy.BundleVersion = state.Generation, state.BundleID, state.BundleVersion
		receipts, _ := newWindowsBundleDriver(layout).Store.Receipts()
		for _, rc := range receipts {
			if rc.BundleID == state.BundleID && rc.Version == state.BundleVersion {
				policy.EffectiveDigest, policy.Digest = rc.ExpectedDigest, rc.ExpectedDigest
				break
			}
		}
		return policy
	}
	windowsBundleSleep = func(time.Duration) {}
	windowsBundleTrust = func(string) error { return nil }
	windowsBundlePrivateStage = func(string) error { return nil }
	windowsBundleSealVersion = func(string) error { return nil }
	windowsBundlePublishVersion = func(string) error { return nil }
	windowsBundlePublishReceipt = func(string) error { return nil }
	windowsBundleEnsurePrivateDirectory = func(path string) error { return os.MkdirAll(path, 0o700) }
	windowsBundlePublishPrivateFile = func(string) error { return nil }
	windowsBundleEnsureStageDirectory = func(_, path string) error { return os.MkdirAll(path, 0o700) }
	windowsBundlePublishStageFile = func(string) error { return nil }
	windowsBundleEnsureDirectory = func(layout managed.StandaloneLayout) error {
		return os.MkdirAll(filepath.Join(layout.ConfigDir, enterprisebundle.BundlesDirName), 0o700)
	}
	bundleAnchorTrust = nil
	return layout
}

func windowsBundleCommand() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetContext(context.Background())
	return cmd, &out
}

// Direct prepare callers own the lock until finish or an explicit release.
// Register cleanup immediately so a failing assertion cannot strand the
// Windows handle and prevent TempDir removal.
func cleanupPreparedWindowsBundle(t *testing.T, opts *windowsEnterpriseLifecycleOptions) {
	t.Helper()
	if opts.bundle != nil {
		run := opts.bundle
		t.Cleanup(run.release)
	}
}

func assertWindowsBundleLockRemoved(t *testing.T, layout managed.StandaloneLayout) {
	t.Helper()
	if err := os.Remove(filepath.Join(layout.LifecycleDir, windowsBundleLockName)); err != nil {
		t.Fatalf("bundle lock remained open: %v", err)
	}
}

// windowsBundleCandidateAnchors writes TRUSTANCHORS= for a device that
// already has anchors installed: the same active k1 key with min_version
// raised to 1, so the bytes differ from the installed file while the
// version 5 test bundle still verifies against either.
func windowsBundleCandidateAnchors(t *testing.T, e *bundleCLIEnv) string {
	t.Helper()
	installed, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	candidate := bytes.Replace(installed, []byte(`"min_version":0`), []byte(`"min_version":1`), 1)
	if bytes.Equal(candidate, installed) {
		t.Fatal("candidate anchors equal the installed anchors")
	}
	path := filepath.Join(e.dir, "candidate-anchors.json")
	writeBundleTestFile(t, path, candidate)
	return path
}

// readWindowsBundleAnchors returns the bytes at path, or nil when there is
// no file.
func readWindowsBundleAnchors(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// assertWindowsBundleInstalledAnchors checks that the installed anchor file
// holds want byte for byte; want nil means no installed anchor file.
func assertWindowsBundleInstalledAnchors(t *testing.T, layout managed.StandaloneLayout, want []byte, when string) {
	t.Helper()
	got := readWindowsBundleAnchors(t, newWindowsBundleDriver(layout).AnchorsPath)
	if (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Fatalf("installed anchors %s: present=%v (%d bytes), want present=%v (%d bytes)",
			when, got != nil, len(got), want != nil, len(want))
	}
}

// assertWindowsBundleAnchorsStaged checks a prepared BUNDLE= TRUSTANCHORS=
// run against the GAP-0106 contract: the delivered anchors sit in the
// private stage under the lifecycle directory, the bundle was verified
// against that stage, Finish will commit it over the installed path, and
// the installed anchor file still holds installed (nil: no file).
func assertWindowsBundleAnchorsStaged(t *testing.T, layout managed.StandaloneLayout, run *windowsBundleRun, delivered string, installed []byte) {
	t.Helper()
	installedPath := newWindowsBundleDriver(layout).AnchorsPath
	stage := ""
	if run != nil && run.prepared != nil && run.prepared.Receipt != nil {
		stage, _, _ = windowsReceiptAnchorPaths(layout, run.prepared.Receipt.ReceiptID)
	}
	if run == nil || run.anchorStage != stage || run.anchorPath != installedPath || run.driver.AnchorsPath != stage {
		var got [3]string
		if run != nil {
			got = [3]string{run.anchorStage, run.anchorPath, run.driver.AnchorsPath}
		}
		t.Fatalf("anchors not staged for Finish: stage/commit/verify paths %q, want %q", got, [3]string{stage, installedPath, stage})
	}
	want, err := os.ReadFile(delivered)
	if err != nil {
		t.Fatal(err)
	}
	if staged := readWindowsBundleAnchors(t, stage); !bytes.Equal(staged, want) {
		t.Fatalf("staged anchors (%d bytes) differ from TRUSTANCHORS= (%d bytes)", len(staged), len(want))
	}
	assertWindowsBundleInstalledAnchors(t, layout, installed, "while the run is prepared")
}

func TestWindowsBundleStandardUserRefusedBeforeManagedLookup(t *testing.T) {
	newBundleCLIEnv(t)
	savedElevated, savedManaged := windowsEnterpriseIsElevated, bundleManagedDevice
	t.Cleanup(func() {
		windowsEnterpriseIsElevated, bundleManagedDevice = savedElevated, savedManaged
	})
	windowsEnterpriseIsElevated = func() bool { return false }
	bundleManagedDevice = func() bool { t.Fatal("read protected deployment metadata as a standard user"); return false }
	for _, args := range [][]string{{"status", "--json"}, {"apply", "--bundle", "C:\\unreadable.dcbundle", "--json"}} {
		out, code := runBundle(t, args...)
		if code != enterprisestatus.WindowsExitFailure {
			t.Fatalf("%v exit %d, want 1603: %s", args, code, out)
		}
		var result struct {
			Errors []bundleError `json:"errors"`
		}
		if err := json.Unmarshal([]byte(out), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Errors) != 1 || result.Errors[0].Code != "not_admin" {
			t.Fatalf("%v answered %+v", args, result.Errors)
		}
		if strings.Contains(out, `"bundle_mode"`) || strings.Contains(out, `"current"`) {
			t.Fatalf("%v presented unreadable state as device facts: %s", args, out)
		}
	}
}

// An interrupted BUNDLE= TRUSTANCHORS= run leaves device trust as it was:
// it only staged the anchors (GAP-0106), so a first delivery still has no
// installed anchor file. The MDM re-runs the same command line; the retry
// stages the delivered anchors again, also over a stage that a killed run
// left behind, and records the interrupted receipt as failed instead of
// reusing it.
func TestWindowsBundleRetryKeepsInterruptedReceipt(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, _ := windowsBundleCommand()
	first := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", first); done || err != nil {
		t.Fatalf("first prepare ended: %v", err)
	}
	cleanupPreparedWindowsBundle(t, first)
	assertWindowsBundleAnchorsStaged(t, layout, first.bundle, e.anchors, nil)
	firstID := first.bundle.prepared.Receipt.ReceiptID
	stage := first.bundle.anchorStage
	first.bundle.release() // The lifecycle process stopped after staging.
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after the interrupted run")

	// A killed run never reaches release and leaves its stage. Make that
	// stage one whose only key is revoked: the retry must replace it with
	// the delivered anchors, not verify the bundle against it.
	delivered, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	stale := bytes.Replace(delivered, []byte(`"status":"active"`), []byte(`"status":"revoked"`), 1)
	if bytes.Equal(stale, delivered) {
		t.Fatal("stale stage equals the delivered anchors")
	}
	writeBundleTestFile(t, stage, stale)

	cmd, _ = windowsBundleCommand()
	retry := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", retry); done || err != nil {
		t.Fatalf("retry prepare ended: %v", err)
	}
	cleanupPreparedWindowsBundle(t, retry)
	defer retry.bundle.release()
	assertWindowsBundleAnchorsStaged(t, layout, retry.bundle, e.anchors, nil)
	if retry.bundle.prepared.Receipt.ReceiptID == firstID {
		t.Fatalf("retry reused the interrupted receipt %s", firstID)
	}
	receipts, err := newWindowsBundleDriver(layout).Store.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	var failed bool
	for _, rc := range receipts {
		if rc.ReceiptID == firstID {
			failed = rc.State == enterprisebundle.StateFailed && rc.ErrorCode == enterprisebundle.CodeInterrupted
		}
	}
	if !failed {
		t.Fatalf("interrupted receipt missing after retry: %+v", receipts)
	}
}

// A run killed after the ensure transaction installed the bundle config,
// but before Finish confirmed the bundle, never committed its TRUSTANCHORS=
// (GAP-0106): the device keeps the anchor file it had, byte for byte. The
// retry, verified against those installed anchors, receives the bundle into
// a fresh version directory and leaves the installed unconfirmed version
// alone.
func TestWindowsBundleRetryProtectsInstalledUnconfirmedVersion(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	if _, _, err := installWindowsBundleAnchors(e.anchors, newWindowsBundleDriver(layout).AnchorsPath); err != nil {
		t.Fatal(err)
	}
	anchorsBefore := readWindowsBundleAnchors(t, newWindowsBundleDriver(layout).AnchorsPath)
	candidate := windowsBundleCandidateAnchors(t, e)
	cmd, _ := windowsBundleCommand()
	first := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: candidate,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", first); done || err != nil {
		t.Fatalf("first prepare ended: %v", err)
	}
	cleanupPreparedWindowsBundle(t, first)
	assertWindowsBundleAnchorsStaged(t, layout, first.bundle, candidate, anchorsBefore)
	rendered := first.bundle.prepared.Config
	versionDir := first.bundle.driver.Store.VersionDir(first.bundle.prepared.Receipt.Dir)
	manifest := filepath.Join(versionDir, enterprisebundle.ManifestName)
	before, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	first.bundle.release() // Installed, then killed before confirmation.
	assertWindowsBundleInstalledAnchors(t, layout, anchorsBefore, "after the run was killed before confirmation")
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }

	cmd, _ = windowsBundleCommand()
	retry := &windowsEnterpriseLifecycleOptions{bundlePath: signed,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", retry); done || err != nil {
		t.Fatalf("retry prepare ended: done=%v err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, retry)
	if retry.bundle.prepared.Receipt.Dir == first.bundle.prepared.Receipt.Dir {
		t.Fatal("retry reused the installed receipt's version directory")
	}
	if _, err := os.Stat(retry.bundle.driver.Store.VersionDir(retry.bundle.prepared.Receipt.Dir)); err != nil {
		t.Fatalf("retry version directory missing: %v", err)
	}
	after, err := os.ReadFile(manifest)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("installed version changed: %v", err)
	}
	assertWindowsBundleInstalledAnchors(t, layout, anchorsBefore, "after the retry was prepared")
	// The retry owns the store lock until its ensure finishes.
	retry.bundle.release()
	assertWindowsBundleLockRemoved(t, layout)
}

// Setup /ensure BUNDLE= TRUSTANCHORS= on an installed device verifies the
// bundle against the delivered anchors from a private stage, hands the
// rendered bundle config to the ensure transaction, and confirms the bundle
// once the gateway enforces it. Only that successful Finish commits the
// anchors to <state root>\etc\trust, once, as a complete file (GAP-0106).
// Then the device is in bundle mode, so a CONFIG= that is not the bundle
// config is refused, and BUNDLE= with CONFIG= is invalid arguments (1639).
func TestWindowsEnsureBundleConfirmsThenRequiresBundles(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	ctx := context.Background()
	installedAnchors := newWindowsBundleDriver(layout).AnchorsPath
	delivered, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	// Every write of the installed anchor file is sealed through this seam
	// right after its rename into place: it counts the commits and checks
	// that each one published the complete delivered file.
	var anchorCommits int
	windowsBundlePublishPrivateFile = func(path string) error {
		if path == installedAnchors {
			anchorCommits++
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, delivered) {
				t.Errorf("anchor commit %d published other bytes than TRUSTANCHORS=: read %v", anchorCommits, err)
			}
		}
		return nil
	}

	cmd, out := windowsBundleCommand()
	both := &windowsEnterpriseLifecycleOptions{bundlePath: signed, configPath: filepath.Join(e.dir, "config.yaml"),
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", both)
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || !strings.Contains(out.String(), "invalid_arguments") {
		t.Fatalf("BUNDLE= with CONFIG=: done=%v exit=%d\n%s", done, commandExitCode(err), out.String())
	}
	cmd, out = windowsBundleCommand()
	anchored := &windowsEnterpriseLifecycleOptions{trustAnchors: e.anchors, configPath: filepath.Join(e.dir, "config.yaml"),
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	done, err = prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", anchored)
	// #1288: the code is bundle_required (not invalid_arguments), the exit 1639.
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || !strings.Contains(out.String(), string(enterprisebundle.CodeBundleRequired)) ||
		strings.Contains(out.String(), "invalid_arguments") {
		t.Fatalf("TRUSTANCHORS= with CONFIG=: done=%v exit=%d\n%s", done, commandExitCode(err), out.String())
	}
	if _, err := os.Stat(filepath.Join(layout.ConfigDir, "trust", enterprisebundle.AnchorsName)); err == nil {
		t.Fatal("TRUSTANCHORS= with CONFIG= installed the anchors")
	}

	cmd, out = windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", opts); done {
		t.Fatalf("prepare ended the run: %v\n%s", err, out.String())
	}
	cleanupPreparedWindowsBundle(t, opts)
	if opts.configPath != filepath.Join(layout.LifecycleDir, windowsBundleConfigName) {
		t.Fatalf("the ensure config is %q", opts.configPath)
	}
	assertWindowsBundleAnchorsStaged(t, layout, opts.bundle, e.anchors, nil)
	stage := opts.bundle.anchorStage
	// The ensure transaction installs the rendered config.
	rendered, err := os.ReadFile(opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(ctx, layout.ConfigPath); err != nil {
		t.Fatalf("record installed bundle config: %v", err)
	}
	attribution, ok := observabilityruntime.ReadBundleAttribution(layout.ConfigPath)
	if !ok || attribution.ID != opts.bundle.prepared.Receipt.BundleID ||
		attribution.Version != opts.bundle.prepared.Receipt.Version ||
		attribution.Principal != opts.bundle.prepared.Receipt.Principal ||
		attribution.SignerKeyID != opts.bundle.prepared.Receipt.SignerKeyID {
		t.Fatalf("restart config.change.applied attribution = %+v, ok=%v", attribution, ok)
	}
	if anchorCommits != 0 {
		t.Fatalf("the anchors were committed %d time(s) before Finish", anchorCommits)
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after the transaction installed the bundle config")
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	expected := opts.bundle.prepared.Receipt.ExpectedDigest
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if len(result.Errors) != 0 || result.Bundle == nil || result.Bundle.State != enterprisebundle.StateConfirmed || result.Bundle.Version != 5 {
		t.Fatalf("bundle not confirmed: errors %+v bundle %+v", result.Errors, result.Bundle)
	}
	if anchorCommits != 1 {
		t.Fatalf("Finish committed the anchors %d time(s), want once", anchorCommits)
	}
	assertWindowsBundleInstalledAnchors(t, layout, delivered, "after Finish confirmed the bundle")
	if _, err := os.Lstat(stage); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("anchor stage left after Finish: %v", err)
	}
	trust, err := os.ReadDir(filepath.Dir(installedAnchors))
	if err != nil {
		t.Fatal(err)
	}
	var trustNames []string
	for _, entry := range trust {
		trustNames = append(trustNames, entry.Name())
	}
	if len(trustNames) != 1 || trustNames[0] != enterprisebundle.AnchorsName {
		t.Fatalf("trust directory after the commit holds %q, want only %s", trustNames, enterprisebundle.AnchorsName)
	}
	// A repeated confirmed delivery is a no-op, but still owns the lock
	// during prepare and finish.
	cmd, _ = windowsBundleCommand()
	again := &windowsEnterpriseLifecycleOptions{bundlePath: signed,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", again); done || err != nil {
		t.Fatalf("already-applied prepare: done=%v err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, again)
	if again.bundle.prepared == nil || !again.bundle.prepared.AlreadyApplied {
		t.Fatalf("repeat delivery was not already applied: %+v", again.bundle.prepared)
	}
	noOp := newWindowsEnterpriseStandaloneResult("ensure", again)
	noOp.Noop = true
	finishWindowsEnterpriseBundle(cmd, again, noOp)
	if len(noOp.Errors) != 0 || noOp.NoopReason != "already_applied" {
		t.Fatalf("already-applied result: %+v", noOp)
	}
	if anchorCommits != 1 {
		t.Fatalf("a repeat delivery without TRUSTANCHORS= rewrote the anchors (%d commits)", anchorCommits)
	}
	assertWindowsBundleInstalledAnchors(t, layout, delivered, "after the repeat delivery")
	assertWindowsBundleLockRemoved(t, layout)
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		t.Fatalf("the run kept the bundle store lock: %v", err)
	}
	unlock()

	// GAP-0034: a repeat of the confirmed bundle with TRUSTANCHORS= that
	// adds a key (A -> A and B) commits the new anchors, so the run is not
	// an already_applied no-op and says what it replaced. The same anchors
	// again are a no-op.
	keyAOnly := e.anchors
	e.anchors = filepath.Join(e.dir, "anchors-ab.json")
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public(), "k2": ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)).Public()})
	rotatedPath := e.anchors
	e.anchors = keyAOnly
	rotated, err := os.ReadFile(rotatedPath)
	if err != nil {
		t.Fatal(err)
	}
	windowsBundlePublishPrivateFile = func(path string) error {
		if path == installedAnchors {
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, rotated) {
				t.Errorf("rotation commit published other bytes than TRUSTANCHORS=: read %v", err)
			}
		}
		return nil
	}
	for _, tc := range []struct {
		name   string
		noop   bool
		reason string
		change []string
	}{
		{"new anchors", false, "", []string{"replaced the trust anchors in " + installedAnchors}},
		{"same anchors again", true, "already_applied", nil},
	} {
		cmd, _ = windowsBundleCommand()
		repeat := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: rotatedPath,
			profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
		if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", repeat); done || err != nil {
			t.Fatalf("%s: prepare: done=%v err=%v", tc.name, done, err)
		}
		cleanupPreparedWindowsBundle(t, repeat)
		if repeat.bundle.prepared == nil || !repeat.bundle.prepared.AlreadyApplied {
			t.Fatalf("%s: repeat delivery was not already applied: %+v", tc.name, repeat.bundle.prepared)
		}
		got := newWindowsEnterpriseStandaloneResult("ensure", repeat)
		got.Noop = true
		finishWindowsEnterpriseBundle(cmd, repeat, got)
		if len(got.Errors) != 0 || got.Noop != tc.noop || got.NoopReason != tc.reason || !slices.Equal(got.Changes, tc.change) {
			t.Fatalf("%s: errors %+v noop=%v reason=%q changes=%q", tc.name, got.Errors, got.Noop, got.NoopReason, got.Changes)
		}
		assertWindowsBundleInstalledAnchors(t, layout, rotated, "after the repeat delivery with "+tc.name)
	}

	other := filepath.Join(e.dir, "other.yaml")
	writeBundleTestFile(t, other, []byte("config_version: 9\n"))
	cmd, out = windowsBundleCommand()
	edit := &windowsEnterpriseLifecycleOptions{configPath: other, profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, _ := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", edit); !done || !strings.Contains(out.String(), string(enterprisebundle.CodeBundleRequired)) {
		t.Fatalf("CONFIG= in bundle mode: done=%v\n%s", done, out.String())
	}
	if done, _ := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", &windowsEnterpriseLifecycleOptions{configPath: layout.ConfigPath,
		profile: managed.ProfileStandalone, installedBeforeRun: true}); done {
		t.Fatal("the current bundle config was refused in bundle mode")
	}

	// TRUSTANCHORS= alone that revokes the confirmed signer replaces the
	// anchor file: the run changed the device, so it is not a compliant
	// no-op, and the warning names the revoked signer (live1 P-3).
	windowsBundlePublishPrivateFile = func(string) error { return nil }
	revoked := filepath.Join(e.dir, "revoked-anchors.json")
	writeBundleTestFile(t, revoked, bytes.Replace(delivered, []byte(`"status":"active"`), []byte(`"status":"revoked"`), 1))
	cmd, _ = windowsBundleCommand()
	alone := &windowsEnterpriseLifecycleOptions{trustAnchors: revoked, profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", alone); done || err != nil {
		t.Fatalf("anchor-only prepare: done=%v err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, alone)
	compliant := newWindowsEnterpriseStandaloneResult("ensure", alone)
	compliant.Noop, compliant.NoopReason = true, "compliant"
	finishWindowsEnterpriseBundle(cmd, alone, compliant)
	named := false
	for _, w := range compliant.Warnings {
		named = named || (w.Code == string(enterprisebundle.CodeKeyRevoked) && strings.Contains(w.Message, "signer k1 is revoked"))
	}
	if compliant.Noop || compliant.NoopReason != "" || len(compliant.Changes) != 1 ||
		compliant.Changes[0] != "replaced the trust anchors in "+installedAnchors+anchorOnlyConfirmedClause || !named {
		t.Fatalf("anchor-only revocation result: noop=%v reason=%q changes=%q warnings=%+v",
			compliant.Noop, compliant.NoopReason, compliant.Changes, compliant.Warnings)
	}
}

func TestWindowsBundleGatewayRestartReachesEveryReceiptSurface(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "restart.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, _ := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, opts)
	run := opts.bundle
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, run.prepared.Config, 0o600); err != nil {
		t.Fatal(err)
	}
	// This host uses a temporary managed layout, so derive the gateway's
	// enforcing digest from that layout and the promoted bundle assets.
	versionDir := run.driver.Store.VersionDir(run.prepared.Receipt.Dir)
	installedBundle, err := enterprisebundle.ReadDir(versionDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, rendered, err := enterprisebundle.LoadConfigForDeviceLayout(installedBundle, versionDir,
		enterprisebundle.PlatformWindows, enterprisebundle.DeviceLayoutFromManaged(layout))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := bundleDigester(context.Background(), cfg, rendered, enterprisebundle.PlatformWindows, versionDir)
	if err != nil {
		t.Fatal(err)
	}
	recordWindowsBundleTestCommit(t, layout, run.prepared.Receipt, run.prepared.Config)
	policy := *windowsBundlePolicy(t.Context())
	policy.EffectiveDigest, policy.Digest = digest, digest
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return &policy }
	run.gatewayRestarted = true
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: digest,
		GatewayReportedDigest: digest, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if len(result.Errors) != 0 {
		t.Fatalf("finish errors: %+v", result.Errors)
	}
	private, err := run.driver.Store.Receipts()
	if err != nil || len(private) != 1 || !private[0].Restart || !private[0].RestartRequired {
		t.Fatalf("private receipts = %+v err=%v", private, err)
	}
	public, err := enterprisestatus.ReadPublicReceipt(run.driver.Store.PublicReceiptPath())
	if err != nil || !public.Restart || !public.RestartRequired {
		t.Fatalf("public receipt = %+v err=%v", public, err)
	}
	state, err := run.driver.Store.LoadState()
	if err != nil || state.Current == nil || !state.Current.RestartRequired {
		t.Fatalf("bundle state = %+v err=%v", state, err)
	}
}

func TestWindowsCommittedBundleGatewayOutageReportsPendingReceipt(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "outage.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, _ := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, opts)
	run := opts.bundle
	id := run.prepared.Receipt.ReceiptID
	_ = recordWindowsBundleTestCommit(t, layout, run.prepared.Receipt, run.prepared.Config)
	confirmedPolicy := windowsBundlePolicy(t.Context())
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	cmd.SetOut(io.Discard)
	finishErr := finishWindowsEnterpriseStandalone(cmd, opts, result, 0)
	if rc := windowsBundleReceiptState(t, layout, id); rc.State != enterprisebundle.StateApplied || rc.ErrorCode != "" ||
		result.Bundle == nil || result.Bundle.State != enterprisebundle.StateApplied ||
		!windowsBundleHasCode(result.Errors, string(enterprisebundle.CodeNotConfirmed)) ||
		!windowsBundleHasCode(result.Warnings, enterprisebundle.WarnBundlePending) ||
		commandExitCode(finishErr) != enterprisestatus.WindowsExitBusy {
		t.Fatalf("gateway outage: receipt=%+v bundle=%+v errors=%+v warnings=%+v exit=%d",
			rc, result.Bundle, result.Errors, result.Warnings, commandExitCode(finishErr))
	}
	if _, err := os.Stat(run.driver.Store.PublicReceiptPath()); !os.IsNotExist(err) {
		t.Fatalf("pending receipt published as terminal: %v", err)
	}
	state, err := run.driver.Store.LoadState()
	if err != nil || state.Current != nil {
		t.Fatalf("outage confirmed an unproven bundle: state=%+v error=%v", state, err)
	}
	report, rollback, err := run.driver.SettleRun(run.prepared.Config, nil)
	if err != nil || len(report.Pending) != 1 || len(rollback) != 0 {
		t.Fatalf("outage settle: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
	report, rollback, err = run.driver.SettleRun(run.prepared.Config, confirmedPolicy)
	if err != nil || len(report.Completed) != 1 || len(rollback) != 0 ||
		windowsBundleReceiptState(t, layout, id).State != enterprisebundle.StateConfirmed {
		t.Fatalf("recovered settle: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
	public, err := enterprisestatus.ReadPublicReceipt(run.driver.Store.PublicReceiptPath())
	if err != nil || public.State != enterprisebundle.StateConfirmed || public.ErrorCode != "" {
		t.Fatalf("public confirmed receipt=%+v error=%v", public, err)
	}
}

// A first delivery can commit config while the gateway is down. Its trust
// anchors must survive the pending receipt and be installed before recovery
// confirms it. Neither the missing installed file nor a later plain ensure
// may admit an unsigned CONFIG= in that interval.
func TestWindowsPendingFirstBundleKeepsTrustAnchors(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "pending-first.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	stubWindowsBundleMarker(t)
	cmd, _ := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, opts)
	run := opts.bundle
	id := run.prepared.Receipt.ReceiptID
	want, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	stage := run.anchorStage
	_ = recordWindowsBundleTestCommit(t, layout, run.prepared.Receipt, run.prepared.Config)
	recoveredPolicy := windowsBundlePolicy(t.Context())
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if rc := windowsBundleReceiptState(t, layout, id); rc.State != enterprisebundle.StateApplied ||
		result.Bundle == nil || result.Bundle.State != enterprisebundle.StateApplied {
		t.Fatalf("gateway outage: receipt=%+v result=%+v", rc, result.Bundle)
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "while the receipt is applied")
	if got := readWindowsBundleAnchors(t, stage); !bytes.Equal(got, want) {
		t.Fatalf("pending receipt lost its staged anchors: %d bytes, want %d", len(got), len(want))
	}
	// Another delivery can stage different anchors without replacing those
	// retained for the receipt whose config is already installed.
	otherAnchors := filepath.Join(e.dir, "other-anchors.json")
	other := bytes.Replace(want, []byte(`"min_version":0`), []byte(`"min_version":1`), 1)
	writeBundleTestFile(t, otherAnchors, other)
	cmd, _ = windowsBundleCommand()
	second := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: otherAnchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", second); done || err != nil {
		t.Fatalf("stage second delivery: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, second)
	if got := readWindowsBundleAnchors(t, stage); !bytes.Equal(got, want) || second.bundle.anchorStage == stage {
		t.Fatalf("second delivery replaced the pending receipt's trust anchors: %d bytes", len(got))
	}
	second.bundle.release()
	unsigned := filepath.Join(e.dir, "unsigned.yaml")
	writeBundleTestFile(t, unsigned, []byte("config_version: 9\n"))
	cmd, out := windowsBundleCommand()
	plain := &windowsEnterpriseLifecycleOptions{configPath: unsigned, profile: managed.ProfileStandalone,
		jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", plain); !done ||
		!strings.Contains(out.String(), string(enterprisebundle.CodeBundleRequired)) {
		t.Fatalf("unsigned CONFIG= was accepted during pending bundle: done=%t err=%v output=%s", done, err, out.String())
	}
	if rc := windowsBundleReceiptState(t, layout, id); rc.State != enterprisebundle.StateApplied {
		t.Fatalf("CONFIG= changed the pending receipt: %+v", rc)
	}
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return recoveredPolicy }
	installedPath := newWindowsBundleDriver(layout).AnchorsPath
	windowsBundlePublishPrivateFile = func(path string) error {
		if path == installedPath {
			return errors.New("test anchor publication failed")
		}
		return nil
	}
	failedCommit := &windowsBundleSettle{ctx: t.Context()}
	settleWindowsInterruptedBundles(failedCommit, layout, newWindowsBundleDriver(layout), 0, false)
	if rc := windowsBundleReceiptState(t, layout, id); rc.State != enterprisebundle.StateApplied ||
		!slices.ContainsFunc(failedCommit.warnings, func(w enterprisebundle.Warning) bool { return w.Code == windowsBundleStateUnreadableWarning }) {
		t.Fatalf("failed anchor publication confirmed a receipt: receipt=%+v warnings=%+v", rc, failedCommit.warnings)
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after failed anchor publication")
	windowsBundlePublishPrivateFile = func(string) error { return nil }
	settled := &windowsBundleSettle{ctx: t.Context()}
	settleWindowsInterruptedBundles(settled, layout, newWindowsBundleDriver(layout), 0, false)
	if !slices.ContainsFunc(settled.warnings, func(w enterprisebundle.Warning) bool {
		return w.Code == enterprisebundle.WarnConfirmedAfterInterrupt
	}) {
		t.Fatalf("recovery did not report confirmation: %+v", settled.warnings)
	}
	if rc := windowsBundleReceiptState(t, layout, id); rc.State != enterprisebundle.StateConfirmed {
		t.Fatalf("recovery receipt = %+v", rc)
	}
	assertWindowsBundleInstalledAnchors(t, layout, want, "after confirmation")
	if _, err := os.Lstat(stage); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("confirmed anchor stage remains: %v", err)
	}
	if err := os.Remove(newWindowsBundleDriver(layout).AnchorsPath); err != nil {
		t.Fatal(err)
	}
	cmd, out = windowsBundleCommand()
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", plain); !done ||
		!strings.Contains(out.String(), string(enterprisebundle.CodeBundleRequired)) {
		t.Fatalf("unsigned CONFIG= was accepted with confirmed bundle and missing anchors: done=%t err=%v output=%s", done, err, out.String())
	}
	before, err := newWindowsBundleDriver(layout).Store.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	cmd, _ = windowsBundleCommand()
	repeat := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", repeat); done || err != nil {
		t.Fatalf("repeat signed bundle: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, repeat)
	if !repeat.bundle.prepared.AlreadyApplied {
		t.Fatal("same signed bundle was not recognized as already applied")
	}
	noOp := newWindowsEnterpriseStandaloneResult("ensure", repeat)
	noOp.Noop = true
	finishWindowsEnterpriseBundle(cmd, repeat, noOp)
	after, err := newWindowsBundleDriver(layout).Store.Receipts()
	if err != nil || len(after) != len(before) || noOp.Bundle == nil || noOp.Bundle.State != enterprisebundle.StateConfirmed {
		t.Fatalf("repeat created another receipt or lost confirmation: before=%d after=%d bundle=%+v error=%v", len(before), len(after), noOp.Bundle, err)
	}
	assertWindowsBundleInstalledAnchors(t, layout, want, "after repeating the confirmed bundle")
}

func TestWindowsRetryConfirmationKeepsAnchorsWhenEarlierReceiptFails(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		name := "first anchors"
		if rotated {
			name = "rotation"
		}
		t.Run(name, func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			signed := filepath.Join(e.dir, "retry.dcbundle")
			if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
				t.Fatalf("sign exit %d: %s", code, out)
			}
			layout := stubWindowsBundleHost(t)
			stubWindowsBundleMarker(t)
			anchors := e.anchors
			var previous []byte
			if rotated {
				previous = readWindowsBundleAnchors(t, e.anchors)
				if _, _, err := installWindowsBundleAnchors(e.anchors, newWindowsBundleDriver(layout).AnchorsPath); err != nil {
					t.Fatal(err)
				}
				anchors = windowsBundleCandidateAnchors(t, e)
			}
			want := readWindowsBundleAnchors(t, anchors)
			recoveredPolicy := windowsBundlePolicy
			windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
			prepare := func() (*windowsEnterpriseLifecycleOptions, *cobra.Command) {
				cmd, _ := windowsBundleCommand()
				opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: anchors,
					profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
				if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
					t.Fatalf("prepare retry: done=%t err=%v", done, err)
				}
				cleanupPreparedWindowsBundle(t, opts)
				return opts, cmd
			}
			first, cmd := prepare()
			firstID := first.bundle.prepared.Receipt.ReceiptID
			g1 := recordWindowsBundleTestCommit(t, layout, first.bundle.prepared.Receipt, first.bundle.prepared.Config)
			finishWindowsEnterpriseBundle(cmd, first, newWindowsEnterpriseStandaloneResult("ensure", first))
			if rc := windowsBundleReceiptState(t, layout, firstID); rc.State != enterprisebundle.StateApplied {
				t.Fatalf("first receipt = %+v", rc)
			}
			second, cmd := prepare()
			secondID := second.bundle.prepared.Receipt.ReceiptID
			if firstID == secondID {
				t.Fatal("retry reused the pending receipt")
			}
			g2 := recordWindowsBundleTestCommit(t, layout, second.bundle.prepared.Receipt, second.bundle.prepared.Config)
			if g2 <= g1 {
				t.Fatalf("retry did not advance generation: first=%d second=%d", g1, g2)
			}
			windowsBundlePolicy = recoveredPolicy
			finishWindowsEnterpriseBundle(cmd, second, newWindowsEnterpriseStandaloneResult("ensure", second))
			if rc := windowsBundleReceiptState(t, layout, secondID); rc.State != enterprisebundle.StateConfirmed {
				t.Fatalf("retry receipt = %+v", rc)
			}
			assertWindowsBundleInstalledAnchors(t, layout, want, "after retry confirmation")
			plain := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, installedBeforeRun: true}
			cmd, _ = windowsBundleCommand()
			if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", plain); done || err != nil {
				t.Fatalf("plain ensure: done=%t err=%v", done, err)
			}
			if rc := windowsBundleReceiptState(t, layout, firstID); rc.State != enterprisebundle.StateFailed {
				t.Fatalf("earlier receipt = %+v", rc)
			}
			assertWindowsBundleInstalledAnchors(t, layout, want, "after earlier receipt failed")
			if rotated && bytes.Equal(previous, want) {
				t.Fatal("rotation did not change anchors")
			}
		})
	}
}

func TestWindowsRetryWithAnchorsRecoversLegacyAppliedReceiptWithoutAnchors(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "legacy-retry.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	stubWindowsBundleMarker(t)
	cmd, _ := windowsBundleCommand()
	first := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", first); done || err != nil {
		t.Fatalf("prepare first delivery: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, first)
	firstID := first.bundle.prepared.Receipt.ReceiptID
	recordWindowsBundleTestCommit(t, layout, first.bundle.prepared.Receipt, first.bundle.prepared.Config)
	recoveredPolicy := windowsBundlePolicy
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
	finishWindowsEnterpriseBundle(cmd, first, newWindowsEnterpriseStandaloneResult("ensure", first))
	stage, previous, err := windowsReceiptAnchorPaths(layout, firstID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stage, previous} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after legacy stage loss")
	windowsBundlePolicy = recoveredPolicy
	cmd, _ = windowsBundleCommand()
	retry := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", retry); done || err != nil {
		t.Fatalf("retry did not reach the new bundle: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, retry)
	if retry.bundle.prepared == nil || retry.bundle.prepared.Receipt == nil ||
		retry.bundle.prepared.Receipt.ReceiptID == firstID {
		t.Fatalf("retry did not stage a new receipt: %+v", retry.bundle.prepared)
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "while retry is staged")
	retryID := retry.bundle.prepared.Receipt.ReceiptID
	recordWindowsBundleTestCommit(t, layout, retry.bundle.prepared.Receipt, retry.bundle.prepared.Config)
	finishWindowsEnterpriseBundle(cmd, retry, newWindowsEnterpriseStandaloneResult("ensure", retry))
	if rc := windowsBundleReceiptState(t, layout, retryID); rc.State != enterprisebundle.StateConfirmed {
		t.Fatalf("replacement receipt = %+v", rc)
	}
	assertWindowsBundleInstalledAnchors(t, layout, readWindowsBundleAnchors(t, e.anchors), "after retry confirmation")
	plain := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, installedBeforeRun: true}
	cmd, _ = windowsBundleCommand()
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", plain); done || err != nil {
		t.Fatalf("plain ensure: done=%t err=%v", done, err)
	}
	if rc := windowsBundleReceiptState(t, layout, firstID); rc.State != enterprisebundle.StateFailed {
		t.Fatalf("legacy receipt after replacement = %+v", rc)
	}
	assertWindowsBundleInstalledAnchors(t, layout, readWindowsBundleAnchors(t, e.anchors), "after legacy receipt failed")
}

func TestWindowsStatusKeepsLegacyAppliedReceiptPendingWithoutAnchors(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "legacy-status.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, _ := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare legacy delivery: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, opts)
	rc := opts.bundle.prepared.Receipt
	recordWindowsBundleTestCommit(t, layout, rc, opts.bundle.prepared.Config)
	policy := windowsBundlePolicy
	windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
	finishWindowsEnterpriseBundle(cmd, opts, newWindowsEnterpriseStandaloneResult("ensure", opts))
	if got := windowsBundleReceiptState(t, layout, rc.ReceiptID); got.State != enterprisebundle.StateApplied {
		t.Fatalf("legacy receipt = %+v", got)
	}
	stage, previous, err := windowsReceiptAnchorPaths(layout, rc.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{stage, previous} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "after legacy anchor loss")
	windowsBundlePolicy = policy // The gateway proves the signed config is enforced.
	for range 2 {
		pending, err := settleWindowsBundleStatusReport(t.Context())
		if err != nil {
			t.Fatalf("status could not report the pending receipt: %v", err)
		}
		if len(pending) != 1 || pending[0].ReceiptID != rc.ReceiptID || pending[0].State != enterprisebundle.StateApplied {
			t.Fatalf("status pending receipts = %+v", pending)
		}
		if got := windowsBundleReceiptState(t, layout, rc.ReceiptID); got.State != enterprisebundle.StateApplied {
			t.Fatalf("status changed legacy receipt = %+v", got)
		}
	}
}

func TestWindowsPendingReceiptCannotBorrowEarlierTrustAnchors(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	layout := stubWindowsBundleHost(t)
	driver := newWindowsBundleDriver(layout)
	if _, _, err := installWindowsBundleAnchors(e.anchors, driver.AnchorsPath); err != nil {
		t.Fatal(err)
	}
	rc, err := driver.Store.Receive("b-01JA00000000000000000000D1", 2, "")
	if err != nil {
		t.Fatal(err)
	}
	_, previous, err := windowsReceiptAnchorPaths(layout, rc.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWindowsBundleAdminFile(previous, old); err != nil {
		t.Fatal(err)
	}
	// A pending receipt's stage was lost, but the old installed anchors are
	// still valid. They did not verify the new delivery.
	if _, err := commitWindowsReceiptAnchors(layout, rc, nil); err == nil {
		t.Fatal("pending receipt borrowed the earlier valid trust anchors")
	}
}

func TestWindowsCommittedStagedBundleKeepsAnchorsAfterRelease(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "staged-commit.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, _ := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(t.Context(), cmd, "ensure", opts); done || err != nil {
		t.Fatalf("prepare: done=%t err=%v", done, err)
	}
	cleanupPreparedWindowsBundle(t, opts)
	run := opts.bundle
	id := run.prepared.Receipt.ReceiptID
	stage := run.anchorStage
	want, err := os.ReadFile(e.anchors)
	if err != nil {
		t.Fatal(err)
	}
	_ = recordWindowsBundleTestCommit(t, layout, run.prepared.Receipt, run.prepared.Config)
	policy := windowsBundlePolicy(t.Context())
	run.release() // The transaction committed, but Finish did not run.
	if rc := windowsBundleReceiptState(t, layout, id); rc.State != enterprisebundle.StateStaged {
		t.Fatalf("committed receipt state = %s, want staged", rc.State)
	}
	if got := readWindowsBundleAnchors(t, stage); !bytes.Equal(got, want) {
		t.Fatalf("committed staged receipt lost its anchors: %d bytes, want %d", len(got), len(want))
	}
	assertWindowsBundleInstalledAnchors(t, layout, nil, "while the committed receipt is staged")
	driver := newWindowsBundleDriver(layout)
	report, rollback, err := driver.SettleRun(run.prepared.Config, nil)
	if err != nil || len(rollback) != 0 || !slices.Contains(report.Pending, id) {
		t.Fatalf("outage settle: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
	report, rollback, err = driver.SettleRun(run.prepared.Config, policy)
	if err != nil || len(rollback) != 0 || !slices.Contains(report.Completed, id) ||
		windowsBundleReceiptState(t, layout, id).State != enterprisebundle.StateConfirmed {
		t.Fatalf("recovered settle: report=%+v rollback=%+v error=%v", report, rollback, err)
	}
	assertWindowsBundleInstalledAnchors(t, layout, want, "after confirming a committed staged receipt")
}

func TestWindowsBundleWarningOnlyVerifyIsNoopEligible(t *testing.T) {
	report := &windowsEnterpriseInstallerReport{Installed: true, GatewayReady: true}
	if !windowsEnterpriseVerifyAcceptable(report) {
		t.Fatal("a warning-only verify caused an ensure repair")
	}
	report.Errors = []string{"managed ACL is still invalid"}
	if windowsEnterpriseVerifyAcceptable(report) {
		t.Fatal("a genuine verify error was treated as compliant")
	}
}

func TestWindowsBundleApplyRejectsDifferentEnforcingDigest(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	cmd, out := windowsBundleCommand()
	opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); done {
		t.Fatalf("prepare ended the run: %v\n%s", err, out.String())
	}
	cleanupPreparedWindowsBundle(t, opts)
	if opts.bundle == nil || opts.bundle.prepared == nil || opts.bundle.prepared.Receipt == nil ||
		!opts.bundle.prepared.Receipt.DigestComparable {
		t.Fatalf("Windows-target bundle was not comparable: %+v", opts.bundle)
	}
	rendered, err := os.ReadFile(opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.ConfigPath, rendered, 0o600); err != nil {
		t.Fatal(err)
	}
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: windowsBundleTestDigest,
		GatewayReportedDigest: windowsBundleTestDigest, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if result.Bundle == nil || result.Bundle.State != enterprisebundle.StateFailed ||
		!windowsBundleHasCode(result.Errors, string(enterprisebundle.CodeDigestMismatch)) ||
		result.Bundle.ErrorCode != string(enterprisebundle.CodeDigestMismatch) {
		t.Fatalf("Windows confirmed a different digest: errors=%+v bundle=%+v", result.Errors, result.Bundle)
	}
	assertWindowsBundleLockRemoved(t, layout)
}

// GAP-0113: Setup /ensure BUNDLE= refuses a validly signed bundle whose
// signed Windows digest this device disproves, also when the manifest says a
// Linux host computed it: digest_mismatch, a failure exit and the installed
// anchors unchanged. The same bundle with its true digest, signed on Linux,
// is compared and verified, with no digest_unverifiable.
func TestWindowsEnsureRefusesCrossHostDigestMismatch(t *testing.T) {
	for _, tampered := range []bool{false, true} {
		t.Run(fmt.Sprintf("tampered=%t", tampered), func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			signed := filepath.Join(e.dir, "v5.dcbundle")
			if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
				t.Fatalf("sign exit %d: %s", code, out)
			}
			resignBundleManifest(t, e, signed, func(m *enterprisebundle.Manifest) {
				m.EffectivePolicy.ComputedOn = enterprisebundle.PlatformLinux
				if tampered {
					// make-p4-digest-mismatch.py: change the first hex digit.
					d := m.EffectivePolicy.Digests[enterprisebundle.PlatformWindows]
					flip := "0"
					if d[7] == '0' {
						flip = "1"
					}
					m.EffectivePolicy.Digests[enterprisebundle.PlatformWindows] = d[:7] + flip + d[8:]
				}
			})
			layout := stubWindowsBundleHost(t)
			installed := newWindowsBundleDriver(layout).AnchorsPath
			if _, _, err := installWindowsBundleAnchors(e.anchors, installed); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(installed)
			if err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(e.dir, "candidate-anchors.json")
			writeBundleTestFile(t, candidate, bytes.Replace(before, []byte(`"min_version":0`), []byte(`"min_version":1`), 1))
			cmd, out := windowsBundleCommand()
			opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: candidate,
				profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
			done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
			if !tampered {
				if done || err != nil {
					t.Fatalf("consistent cross-host bundle: done=%v err=%v output=%s", done, err, out.String())
				}
				cleanupPreparedWindowsBundle(t, opts)
				rc := opts.bundle.prepared.Receipt
				if !rc.DigestComparable || rc.ExpectedDigest != opts.bundle.prepared.Manifest.EffectivePolicy.Digests[enterprisebundle.PlatformWindows] ||
					slices.Contains(rc.WarningCodes, enterprisebundle.WarnDigestUnverifiable) {
					t.Fatalf("consistent cross-host bundle receipt = %+v", rc)
				}
				return
			}
			var refusal struct {
				ExitCode    int `json:"exit_code"`
				LastRefusal struct {
					ErrorCode string `json:"error_code"`
				} `json:"last_refusal"`
			}
			if decodeErr := json.Unmarshal(out.Bytes(), &refusal); decodeErr != nil {
				t.Fatalf("decode refusal: %v: %s", decodeErr, out.String())
			}
			if !done || commandExitCode(err) != enterprisestatus.WindowsExitFailure || refusal.ExitCode != enterprisestatus.WindowsExitFailure ||
				refusal.LastRefusal.ErrorCode != string(enterprisebundle.CodeDigestMismatch) ||
				!strings.Contains(out.String(), "the signer computed the digest on linux") {
				t.Fatalf("disproved cross-host digest: done=%v err=%v output=%s", done, err, out.String())
			}
			after, err := os.ReadFile(installed)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("the refusal changed the installed anchors: read=%v", err)
			}
			assertWindowsBundleLockRemoved(t, layout)
		})
	}
}

// resignBundleManifest edits the manifest of the signed bundle at path and
// re-signs it with the trusted test key, as a holder of that key would.
func resignBundleManifest(t *testing.T, e *bundleCLIEnv, path string, edit func(*enterprisebundle.Manifest)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := enterprisebundle.ReadArchive(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	m, err := enterprisebundle.DecodeManifest(b.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	edit(m)
	if b.Manifest, err = m.Marshal(); err != nil {
		t.Fatal(err)
	}
	sig, err := enterprisebundle.Sign(b.Manifest, e.edKey, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if b.Signature, err = sig.Marshal(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := enterprisebundle.WriteArchive(&out, b); err != nil {
		t.Fatal(err)
	}
	writeBundleTestFile(t, path, out.Bytes())
}

func TestWindowsBundleRefusalsReleaseLock(t *testing.T) {
	for _, kind := range []string{"version_not_newer", "apply_failure"} {
		t.Run(kind, func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			signed := filepath.Join(e.dir, "v5.dcbundle")
			if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
				t.Fatalf("sign exit %d: %s", code, out)
			}
			if kind == "version_not_newer" {
				raw, err := os.ReadFile(e.anchors)
				if err != nil {
					t.Fatal(err)
				}
				writeBundleTestFile(t, e.anchors, bytes.Replace(raw, []byte(`"min_version":0`), []byte(`"min_version":6`), 1))
			}
			layout := stubWindowsBundleHost(t)
			cmd, out := windowsBundleCommand()
			opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
				profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
			done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
			if kind == "version_not_newer" {
				var refusal struct {
					FloorSource string `json:"floor_source"`
					ExitCode    int    `json:"exit_code"`
					LastRefusal struct {
						ErrorCode string `json:"error_code"`
					} `json:"last_refusal"`
				}
				if decodeErr := json.Unmarshal(out.Bytes(), &refusal); decodeErr != nil {
					t.Fatalf("decode version floor refusal: %v: %s", decodeErr, out.String())
				}
				if !done || commandExitCode(err) != enterprisestatus.WindowsExitFailure ||
					refusal.ExitCode != enterprisestatus.WindowsExitFailure || refusal.LastRefusal.ErrorCode != kind ||
					refusal.FloorSource != "trust_anchor_min_version" ||
					!strings.Contains(out.String(), "set by trust anchor min_version") {
					t.Fatalf("version floor refusal: done=%v err=%v output=%s", done, err, out.String())
				}
				assertWindowsBundleLockRemoved(t, layout)
				return
			}
			if done || err != nil {
				t.Fatalf("prepare: done=%v err=%v output=%s", done, err, out.String())
			}
			cleanupPreparedWindowsBundle(t, opts)
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			result.AddError("installer_failed", "test ensure transaction failed")
			finishWindowsEnterpriseBundle(cmd, opts, result)
			if !windowsBundleHasCode(result.Errors, string(enterprisebundle.CodeApplyFailed)) {
				t.Fatalf("apply failure was not recorded: %+v", result.Errors)
			}
			assertWindowsBundleLockRemoved(t, layout)
		})
	}
}

func TestWindowsRefusedBundleKeepsInstalledAnchors(t *testing.T) {
	for _, kind := range []string{"key_revoked", "archive_invalid", "version_not_newer", "apply_failed"} {
		t.Run(kind, func(t *testing.T) {
			e := newBundleCLIEnv(t)
			e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
			signed := filepath.Join(e.dir, "v5.dcbundle")
			if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
				t.Fatalf("sign exit %d: %s", code, out)
			}
			layout := stubWindowsBundleHost(t)
			installed := newWindowsBundleDriver(layout).AnchorsPath
			if _, _, err := installWindowsBundleAnchors(e.anchors, installed); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(installed)
			if err != nil {
				t.Fatal(err)
			}
			candidate := filepath.Join(e.dir, "candidate-anchors.json")
			replacement := bytes.Replace(before, []byte(`"min_version":0`), []byte(`"min_version":1`), 1)
			switch kind {
			case "key_revoked":
				replacement = bytes.Replace(replacement, []byte(`"status":"active"`), []byte(`"status":"revoked"`), 1)
			case "version_not_newer":
				replacement = bytes.Replace(replacement, []byte(`"min_version":1`), []byte(`"min_version":6`), 1)
			}
			writeBundleTestFile(t, candidate, replacement)
			if kind == "archive_invalid" {
				signed = filepath.Join(e.dir, "absent.dcbundle")
			}
			cmd, _ := windowsBundleCommand()
			opts := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: candidate,
				profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
			done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts)
			if kind == "apply_failed" {
				if done || err != nil {
					t.Fatalf("prepare: done=%v err=%v", done, err)
				}
				cleanupPreparedWindowsBundle(t, opts)
				result := newWindowsEnterpriseStandaloneResult("ensure", opts)
				result.AddError("bundle_apply_failed", "test apply failure")
				finishWindowsEnterpriseBundle(cmd, opts, result)
			} else if !done || err == nil {
				t.Fatalf("wanted %s refusal: done=%v err=%v", kind, done, err)
			}
			after, err := os.ReadFile(installed)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("%s changed installed anchors: read=%v", kind, err)
			}
		})
	}
}

// windowsKilledApplyReceipt leaves a receipt as a bundle run killed at
// state until does: received (staging copy written), verified, staged
// (promoted), applied (its config installed, gateway confirmation never
// recorded) or confirmed.
func windowsKilledApplyReceipt(t *testing.T, driver *enterprisebundle.Driver, bundleID string, version uint64, config []byte, until string) *enterprisebundle.Receipt {
	t.Helper()
	rc, err := driver.Store.Receive(bundleID, version, "d-gap1302")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Store.Stage(rc, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": config}}); err != nil {
		t.Fatal(err)
	}
	if until == enterprisebundle.StateReceived {
		return rc
	}
	if err := driver.Store.Advance(rc, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
		r.ManifestSHA256 = strings.Repeat("a", 64)
		r.Principal, r.SignerKeyID = "operator:alice", "k1"
		r.ExpectedDigest = windowsBundleTestDigest
		r.SetDigestComparison(true, false, false)
	}); err != nil {
		t.Fatal(err)
	}
	if until == enterprisebundle.StateVerified {
		return rc
	}
	// Prepare records the rendered config hash before promoting a receipt,
	// so a killed run can leave a staged receipt with a committed config.
	rc.ConfigSHA256 = configwrite.SHA256Hex(config)
	if _, err := driver.Store.Promote(rc); err != nil {
		t.Fatal(err)
	}
	if until == enterprisebundle.StateStaged {
		return rc
	}
	layout, err := windowsBundleLayout()
	if err != nil {
		t.Fatal(err)
	}
	generation := recordWindowsBundleTestCommit(t, layout, rc, config)
	if err := driver.Store.Advance(rc, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) {
		r.ConfigSHA256 = configwrite.SHA256Hex(config)
		r.EffectivePolicyDigest = windowsBundleTestDigest
		r.ConfigGeneration = generation
	}); err != nil {
		t.Fatal(err)
	}
	if until == enterprisebundle.StateApplied {
		return rc
	}
	if _, err := driver.Store.Confirm(rc); err != nil {
		t.Fatal(err)
	}
	return rc
}

func windowsBundleReceiptState(t *testing.T, layout managed.StandaloneLayout, id string) *enterprisebundle.Receipt {
	t.Helper()
	receipts, err := newWindowsBundleDriver(layout).Store.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	for _, rc := range receipts {
		if rc.ReceiptID == id {
			return rc
		}
	}
	t.Fatalf("receipt %s missing: %+v", id, receipts)
	return nil
}

func stubWindowsBundleMarker(t *testing.T) *int {
	t.Helper()
	saved := windowsBundleSyncMarker
	t.Cleanup(func() { windowsBundleSyncMarker = saved })
	calls := new(int)
	windowsBundleSyncMarker = func(*enterprisebundle.Store) error { *calls++; return nil }
	return calls
}

// A SYSTEM `enterprise bundle apply` killed after it staged its receipt
// left the receipt staged, and two plain `enterprise windows ensure` runs
// returned ok with the receipt still staged while status and bundle status
// warned bundle_pending (GAP-1302). The ensure the contract (4.6) and that
// warning name now settles it: the receipt fails as interrupted, the result
// warns bundle_interrupted, no unfinished receipt is left and the run does not
// keep bundle.lock (its bundle restore takes it again).
func TestWindowsPlainEnsureSettlesKilledApplyReceipt(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d: %s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	markers := stubWindowsBundleMarker(t)
	ctx := context.Background()
	cmd, _ := windowsBundleCommand()
	killed := &windowsEnterpriseLifecycleOptions{bundlePath: signed, trustAnchors: e.anchors,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, "ensure", killed); done || err != nil {
		t.Fatalf("apply prepare ended: %v", err)
	}
	cleanupPreparedWindowsBundle(t, killed)
	id := killed.bundle.prepared.Receipt.ReceiptID
	if state := killed.bundle.prepared.Receipt.State; state != enterprisebundle.StateStaged {
		t.Fatalf("apply receipt state = %s, want staged", state)
	}
	killed.bundle.release() // Stop-Process -Force: finish never ran.

	for i := range 2 {
		action := "ensure"
		cmd, _ = windowsBundleCommand()
		plain := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
		if done, err := prepareWindowsEnterpriseBundle(ctx, cmd, action, plain); done || err != nil {
			t.Fatalf("plain ensure prepare ended: done=%v err=%v", done, err)
		}
		if plain.bundle != nil {
			plain.bundle.release()
			t.Fatal("a plain ensure kept a bundle run, which disables its bundle restore")
		}
		// The run does not keep bundle.lock: its bundle restore takes it again.
		unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
		if err != nil {
			t.Fatalf("bundle.lock still held after a plain ensure prepared: %v", err)
		}
		unlock()
		result := newWindowsEnterpriseStandaloneResult(action, plain)
		finishWindowsEnterpriseBundle(cmd, plain, result)
		rc := windowsBundleReceiptState(t, layout, id)
		if rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeInterrupted {
			t.Fatalf("killed apply receipt = %s/%s, want failed/interrupted", rc.State, rc.ErrorCode)
		}
		if unsettled, err := newWindowsBundleDriver(layout).Store.Unsettled(); err != nil || len(unsettled) != 0 {
			t.Fatalf("unsettled after ensure = %+v, %v", unsettled, err)
		}
		// The first ensure settles and warns; a repeat is quiet.
		if got := windowsBundleHasCode(result.Warnings, windowsBundleInterruptedWarning); got != (i == 0) {
			t.Fatalf("ensure %d: bundle_interrupted warning = %v: %+v", i+1, got, result.Warnings)
		}
	}
	if *markers != 1 {
		t.Fatalf("marker synced %d times, want once (only the run that settled)", *markers)
	}
}

// Every receipt state a killed bundle run can leave is settled by a plain
// ensure (GAP-1302), as `ensure --bundle` settles them before its own bundle:
// received, verified and staged fail as interrupted; an applied one whose
// config is installed and enforced is confirmed; an applied one whose
// gateway is unavailable stays pending until a later run can confirm it.
// A pending install transaction defers the settle until the
// ensure recovered it, and a live bundle run's lock leaves its receipt alone.
func TestWindowsPlainEnsureSettlesEveryKilledApplyState(t *testing.T) {
	const lastGood, killedID = "b-01JA00000000000000000000C1", "b-01JA00000000000000000000C2"
	goodConfig, killedConfig := []byte("config_version: 9\n# last good\n"), []byte("config_version: 9\n# killed\n")
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	for _, tc := range []struct {
		name      string
		until     string
		installed []byte
		gateway   bool
		pending   string // "": none, "recovered": cleared before finish, "stuck": still there at finish
		busy      bool
		wantState string
		wantCode  enterprisebundle.Code
		wantWarn  string
		replacing bool
	}{
		{name: "received", until: enterprisebundle.StateReceived, installed: goodConfig, gateway: true,
			wantState: enterprisebundle.StateFailed, wantCode: enterprisebundle.CodeInterrupted, wantWarn: windowsBundleInterruptedWarning},
		{name: "verified", until: enterprisebundle.StateVerified, installed: goodConfig, gateway: true,
			wantState: enterprisebundle.StateFailed, wantCode: enterprisebundle.CodeInterrupted, wantWarn: windowsBundleInterruptedWarning},
		{name: "staged", until: enterprisebundle.StateStaged, installed: goodConfig, gateway: true,
			wantState: enterprisebundle.StateFailed, wantCode: enterprisebundle.CodeInterrupted, wantWarn: windowsBundleInterruptedWarning},
		{name: "applied and enforced", until: enterprisebundle.StateApplied, installed: killedConfig, gateway: true,
			wantState: enterprisebundle.StateConfirmed, wantWarn: enterprisebundle.WarnConfirmedAfterInterrupt},
		{name: "applied, gateway silent", until: enterprisebundle.StateApplied, installed: killedConfig,
			wantState: enterprisebundle.StateApplied, wantWarn: enterprisebundle.WarnBundlePending},
		{name: "pending transaction recovered", until: enterprisebundle.StateStaged, installed: goodConfig, gateway: true, pending: "recovered",
			wantState: enterprisebundle.StateFailed, wantCode: enterprisebundle.CodeInterrupted, wantWarn: windowsBundleInterruptedWarning},
		{name: "pending transaction stuck", until: enterprisebundle.StateStaged, installed: goodConfig, gateway: true, pending: "stuck",
			wantState: enterprisebundle.StateStaged, wantWarn: windowsBundleSettleDeferredWarning},
		{name: "live bundle run", until: enterprisebundle.StateStaged, installed: goodConfig, gateway: true, busy: true,
			wantState: enterprisebundle.StateStaged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := stubWindowsBundleHost(t)
			stubWindowsBundleMarker(t)
			driver := newWindowsBundleDriver(layout)
			if _, _, err := installWindowsBundleAnchors(e.anchors, driver.AnchorsPath); err != nil {
				t.Fatal(err)
			}
			windowsKilledApplyReceipt(t, driver, lastGood, 1, goodConfig, enterprisebundle.StateConfirmed)
			rc := windowsKilledApplyReceipt(t, driver, killedID, 2, killedConfig, tc.until)
			if err := os.MkdirAll(filepath.Dir(layout.ConfigPath), 0o700); err != nil {
				t.Fatal(err)
			}
			writeBundleTestFile(t, layout.ConfigPath, tc.installed)
			if !tc.gateway {
				windowsBundlePolicy = func(context.Context) *enterprisebundle.GatewayPolicy { return nil }
			}
			pending := filepath.Join(filepath.Dir(layout.ConfigDir), "install", "pending.json")
			if tc.pending != "" {
				if err := os.MkdirAll(filepath.Dir(pending), 0o700); err != nil {
					t.Fatal(err)
				}
				writeBundleTestFile(t, pending, []byte("{}"))
			}
			if tc.busy {
				unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(unlock)
			}
			cmd, _ := windowsBundleCommand()
			opts := &windowsEnterpriseLifecycleOptions{profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
			if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", opts); done || err != nil {
				t.Fatalf("plain ensure prepare ended: done=%v err=%v", done, err)
			}
			if opts.bundle != nil {
				opts.bundle.release()
				t.Fatal("a plain ensure kept a bundle run")
			}
			if tc.pending != "" {
				if got := windowsBundleReceiptState(t, layout, rc.ReceiptID).State; got != tc.until {
					t.Fatalf("receipt settled to %s while the install transaction was pending", got)
				}
			}
			if got := windowsBundleSettleReplacing(opts); (got != "") != tc.replacing || (tc.replacing && !strings.Contains(got, killedID)) {
				t.Fatalf("bundle restore replaces %q, want the killed bundle: %v", got, tc.replacing)
			}
			if tc.pending == "recovered" {
				if err := os.Remove(pending); err != nil {
					t.Fatal(err)
				}
			}
			result := newWindowsEnterpriseStandaloneResult("ensure", opts)
			finishWindowsEnterpriseBundle(cmd, opts, result)
			got := windowsBundleReceiptState(t, layout, rc.ReceiptID)
			if got.State != tc.wantState || got.ErrorCode != tc.wantCode {
				t.Fatalf("receipt = %s/%s, want %s/%s", got.State, got.ErrorCode, tc.wantState, tc.wantCode)
			}
			if tc.wantWarn == "" {
				if len(result.Warnings) != 0 && windowsBundleHasCode(result.Warnings, windowsBundleInterruptedWarning) {
					t.Fatalf("a live bundle run's receipt was settled: %+v", result.Warnings)
				}
			} else if !windowsBundleHasCode(result.Warnings, tc.wantWarn) {
				t.Fatalf("warnings = %+v, want %s", result.Warnings, tc.wantWarn)
			}
			st, err := driver.Store.LoadState()
			if err != nil {
				t.Fatal(err)
			}
			wantCurrent := lastGood
			if tc.wantState == enterprisebundle.StateConfirmed {
				wantCurrent = killedID
			}
			if st.Current == nil || st.Current.BundleID != wantCurrent {
				t.Fatalf("current = %+v, want %s", st.Current, wantCurrent)
			}
		})
	}
}
