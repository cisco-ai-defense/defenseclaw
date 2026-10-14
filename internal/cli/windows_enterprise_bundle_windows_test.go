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
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

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
	got := windowsHotConfigWriteOptions(opts, "abc")
	if got.Actor != "control-plane:acme/alice" || got.LocalActor != configwrite.CurrentOSActor() || got.Bundle.ID != id || got.Bundle.Version != 3 ||
		got.Bundle.SignerKeyID != "k1" || got.Reason != configwrite.BundleReason(id, 3, "guardrail pack update") ||
		!got.Lifecycle || got.ExpectSHA256 != "abc" {
		t.Fatalf("Windows bundle hot write = %+v", got)
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
	_, err := configwrite.Locked(context.Background(), layout.ConfigPath,
		windowsHotConfigWriteOptions(opts, configwrite.SHA256Hex(previous)), func() (bool, error) {
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
		{"enforced", 7, windowsBundleTestDigest, true},
		{"wrong generation", 6, windowsBundleTestDigest, false},
		{"wrong digest", 7, "sha256:" + strings.Repeat("2", 64), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout := stubWindowsBundleHost(t)
			driver := newWindowsBundleDriver(layout)
			rc, err := driver.Store.Receive("b-01JA0000000000000000000033", 13)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := driver.Store.Stage(rc, &enterprisebundle.Bundle{Files: map[string][]byte{"config.yaml": []byte("config_version: 9\n")}}); err != nil {
				t.Fatal(err)
			}
			if err := driver.Store.Advance(rc, enterprisebundle.StateVerified, func(r *enterprisebundle.Receipt) {
				r.ManifestSHA256 = strings.Repeat("a", 64)
				r.ExpectedDigest = windowsBundleTestDigest
				r.SetDigestComparison(true, false, false)
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := driver.Store.Promote(rc); err != nil {
				t.Fatal(err)
			}
			installed := []byte("config_version: 9\n")
			if err := driver.Store.Advance(rc, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) {
				r.ConfigSHA256 = configwrite.SHA256Hex(installed)
				r.EffectivePolicyDigest = windowsBundleTestDigest
				r.ConfigGeneration = 7
			}); err != nil {
				t.Fatal(err)
			}
			policy := &enterprisebundle.GatewayPolicy{EffectiveDigest: tc.digest, Digest: tc.digest, Generation: tc.generation, Applied: true}
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
			receipt, err := store.Receive("b-01JA0000000000000000000033", 1)
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
		return &enterprisebundle.GatewayPolicy{EffectiveDigest: windowsBundleTestDigest, Digest: windowsBundleTestDigest, Generation: 3, Applied: true}
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
	firstID := first.bundle.prepared.Receipt.ReceiptID
	first.bundle.release() // The lifecycle process stopped after staging.

	cmd, _ = windowsBundleCommand()
	retry := &windowsEnterpriseLifecycleOptions{bundlePath: signed,
		profile: managed.ProfileStandalone, jsonOutput: true, installedBeforeRun: true}
	if done, err := prepareWindowsEnterpriseBundle(context.Background(), cmd, "ensure", retry); done || err != nil {
		t.Fatalf("retry prepare ended: %v", err)
	}
	cleanupPreparedWindowsBundle(t, retry)
	defer retry.bundle.release()
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

func TestWindowsBundleRetryProtectsInstalledUnconfirmedVersion(t *testing.T) {
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
	// The retry owns the store lock until its ensure finishes.
	retry.bundle.release()
	assertWindowsBundleLockRemoved(t, layout)
}

// Setup /ensure BUNDLE= on an installed device installs the trust anchors,
// hands the rendered bundle config to the ensure transaction, and confirms
// the bundle once the gateway enforces it; then the device is in bundle
// mode, so a CONFIG= that is not the bundle config is refused, and BUNDLE=
// with CONFIG= is invalid arguments (1639).
func TestWindowsEnsureBundleConfirmsThenRequiresBundles(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	layout := stubWindowsBundleHost(t)
	ctx := context.Background()

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
	if !done || commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || !strings.Contains(out.String(), "invalid_arguments") {
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
	if _, err := os.Stat(filepath.Join(layout.ConfigDir, "trust", enterprisebundle.AnchorsName)); err != nil {
		t.Fatalf("anchors not installed: %v", err)
	}
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
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	expected := opts.bundle.prepared.Receipt.ExpectedDigest
	result.Policy = &enterprisestatus.PolicyState{EffectiveDigest: expected, GatewayReportedDigest: expected, ConfigGeneration: 3, Applied: true}
	finishWindowsEnterpriseBundle(cmd, opts, result)
	if len(result.Errors) != 0 || result.Bundle == nil || result.Bundle.State != enterprisebundle.StateConfirmed || result.Bundle.Version != 5 {
		t.Fatalf("bundle not confirmed: errors %+v bundle %+v", result.Errors, result.Bundle)
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
	assertWindowsBundleLockRemoved(t, layout)
	unlock, err := lockWindowsBundleStore(layout.LifecycleDir)
	if err != nil {
		t.Fatalf("the run kept the bundle store lock: %v", err)
	}
	unlock()

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
