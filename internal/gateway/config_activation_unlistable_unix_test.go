//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// unlistableStore makes the bundle store of dir searchable but not readable
// for the test account, as the 0711 root:root store is for the gateway's
// service account on Linux and macOS (rel-1-0-6:GAP-0038). It skips when the
// account lists the directory anyway (root).
func unlistableStore(t *testing.T, dir string) string {
	t.Helper()
	bundles := filepath.Join(dir, enterprisebundle.BundlesDirName)
	if err := os.Chmod(bundles, 0o311); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bundles, 0o755) })
	if _, err := os.ReadDir(bundles); err == nil {
		t.Skip("this account lists a directory without read permission (root)")
	}
	return bundles
}

func bundleWriteAt(id string, version uint64, dir string) configwrite.Options {
	opt := bundleWrite(id, version)
	opt.Bundle.Dir = dir
	return opt
}

// rel-1-0-6:GAP-0102: the gateway's service account cannot list the bundle
// store, and the private #7 activation check listed it, so every signed
// bundle apply on managed Linux failed not_confirmed and rolled back. The
// check now opens the version directory the generation record names
// (bundle_dir). A retry of a bundle (fresh r- receipt id, a settings-only
// config that names no bundle file) confirms; a record that names no
// directory the gateway can find, an unknown bundle, an unreadable
// directory, bytes the bundle does not render, a changed shipped file and a
// bundle no anchor key signed are still refused.
func TestSignedApplyConfirmsInAnUnlistableStore(t *testing.T) {
	mgr, store, path, source, applied := managedSignedManager(t)
	if mgr.rejected {
		t.Fatal("startup on the signed bundle was refused")
	}
	const v1ID, v2ID = "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", "b-01J9ZZZZZZZZZZZZZZZZZZZZZ2"
	const retry = "r-01M67Q3D91SE476NFVDCN0BDQZ"
	actionSource := bytes.Replace(source, []byte("mode: observe"), []byte("mode: action"), 1)
	unlistableStore(t, store.dir)
	v2, v2Dir := store.storeFor(t, v2ID, 2, retry, actionSource)
	if strings.Contains(string(v2), v2Dir) {
		t.Fatal("the test bundle must be settings-only: its config names its version directory")
	}

	refusedBy := func(name, wantCause string) {
		t.Helper()
		before := *applied
		err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload")
		if err == nil || !strings.Contains(err.Error(), "activation_not_signed ("+wantCause+")") {
			t.Fatalf("%s: err=%v, want activation_not_signed (%s)", name, err, wantCause)
		}
		if *applied != before || mgr.Current().Guardrail.Mode != "observe" {
			t.Fatalf("%s: applied=%d mode=%q, live policy changed", name, *applied, mgr.Current().Guardrail.Mode)
		}
	}
	// A record an earlier build wrote names no directory, and the retry's
	// directory name cannot be guessed: not signed (fail closed).
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v2, bundleWrite(v2ID, 2)); err != nil {
		t.Fatal(err)
	}
	refusedBy("record without bundle_dir", enterprisebundle.ActivationNotStored)

	// The record names the directory: the apply confirms.
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v2, bundleWriteAt(v2ID, 2, v2Dir)); err != nil {
		t.Fatal(err)
	}
	if state, err := configwrite.ReadGenerationState(path); err != nil || state.BundleDir != v2Dir {
		t.Fatalf("record bundle_dir = %q (%v), want %q", state.BundleDir, err, v2Dir)
	}
	if err := mgr.Reload(t.Context(), "watch"); err != nil || mgr.Current().Guardrail.Mode != "action" {
		t.Fatalf("signed apply in an unlistable store: err=%v mode=%q", err, mgr.Current().Guardrail.Mode)
	}
	// The apply rollback to the last good bundle (first delivery): admitted.
	v1Dir := enterprisebundle.VersionDirNameForReceipt(1, v1ID, v1ID)
	v1, err := enterprisebundle.RenderConfig(mustReadDir(t, store, v1ID, 1), versionDirOf(store, v1ID, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v1, bundleWriteAt(v1ID, 1, v1Dir)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "watch"); err != nil || mgr.Current().Guardrail.Mode != "observe" {
		t.Fatalf("apply rollback in an unlistable store: err=%v mode=%q", err, mgr.Current().Guardrail.Mode)
	}

	// An unknown bundle whose record points at a stored directory of another bundle.
	if _, err := configwrite.ReplaceDocument(t.Context(), path, actionSource, bundleWriteAt("b-01J9ZZZZZZZZZZZZZZZZZZZZZ9", 9, v2Dir)); err != nil {
		t.Fatal(err)
	}
	refusedBy("unknown bundle", enterprisebundle.ActivationNotStored)
	// The stored v2 over other bytes.
	if _, err := configwrite.ReplaceDocument(t.Context(), path, append([]byte("# edited\n"), v2...), bundleWriteAt(v2ID, 2, v2Dir)); err != nil {
		t.Fatal(err)
	}
	refusedBy("stored bundle over other bytes", enterprisebundle.ActivationConfig)
	// A version directory the gateway cannot read is not signed.
	versionPath := filepath.Join(store.dir, enterprisebundle.BundlesDirName, v2Dir)
	if err := os.Chmod(versionPath, 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v2, bundleWriteAt(v2ID, 2, v2Dir)); err != nil {
		_ = os.Chmod(versionPath, 0o700)
		t.Fatal(err)
	}
	refusedBy("unreadable version directory", enterprisebundle.ActivationNotStored)
	if err := os.Chmod(versionPath, 0o700); err != nil {
		t.Fatal(err)
	}
	// A shipped file of v2 changed after it was stored.
	pack := filepath.Join(versionPath, "policies", "guardrail", "custom", "rules.yaml")
	if err := os.WriteFile(pack, []byte("name: changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(t.Context(), path, append(append([]byte(nil), v2...), "# again\n"...), bundleWriteAt(v2ID, 2, v2Dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v2, bundleWriteAt(v2ID, 2, v2Dir)); err != nil {
		t.Fatal(err)
	}
	refusedBy("tampered shipped file", enterprisebundle.ActivationDigest)
	// A bundle signed by a key that is not a trust anchor.
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rogue := &signedStore{dir: store.dir, key: otherPrivate}
	v3, v3Dir := rogue.storeFor(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ3", 3, retry, actionSource)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v3, bundleWriteAt("b-01J9ZZZZZZZZZZZZZZZZZZZZZ3", 3, v3Dir)); err != nil {
		t.Fatal(err)
	}
	refusedBy("unsigned by an anchor key", enterprisebundle.ActivationSignature)
}

// The start fallback (SignedVersions) cannot list an unlistable store
// either: it opens the directories the generation record points at and the
// ones the public receipt events name.
func TestSignedVersionsInAnUnlistableStore(t *testing.T) {
	dir := t.TempDir()
	s := newSignedStore(t, dir)
	const first, second = "b-01M67Q3D91SE476NFVDCN0BDQZ", "b-01M67QDN97GZ201W27K06BENYS"
	const retry = "r-01M67QDN97GZ201W27K06BENYT"
	source := []byte("config_version: 9\n")
	s.store(t, first, 1, source)
	_, secondDir := s.storeFor(t, second, 2, retry, source)
	bundles := filepath.Join(dir, enterprisebundle.BundlesDirName)
	events := filepath.Join(bundles, "receipt-events")
	if err := os.MkdirAll(events, 0o755); err != nil {
		t.Fatal(err)
	}
	unlistableStore(t, dir)
	anchors, raw, err := enterprisebundle.ReadAnchorsFile(filepath.Join(dir, "trust", enterprisebundle.AnchorsName), nil)
	if err != nil {
		t.Fatal(err)
	}
	in := enterprisebundle.ActivationInput{BundlesDir: bundles, Platform: runtime.GOOS, Anchors: anchors, AnchorsRaw: raw}
	if versions := enterprisebundle.SignedVersions(in); len(versions) != 0 {
		t.Fatalf("no hint and no receipt: %d versions, want none", len(versions))
	}
	if versions := enterprisebundle.SignedVersions(in, enterprisebundle.RecordVersionDirs(first, 1, "")...); len(versions) != 1 || versions[0].Manifest.BundleID != first {
		t.Fatalf("record of an earlier build: %d versions", len(versions))
	}
	event := fmt.Sprintf(`{"schema_version":1,"receipt_id":%q,"bundle_id":%q,"version":2,"state":"confirmed"}`, retry, second)
	if err := os.WriteFile(filepath.Join(events, retry+".json"), []byte(event), 0o644); err != nil {
		t.Fatal(err)
	}
	versions := enterprisebundle.SignedVersions(in, enterprisebundle.RecordVersionDirs(first, 1, "")...)
	if len(versions) != 2 || versions[0].Dir != secondDir {
		t.Fatalf("with the public receipt event: %d versions", len(versions))
	}
}

// The lifecycle records the version directory of the receipt it applies.
func TestGenerationOptionsRecordsTheVersionDirectory(t *testing.T) {
	const id, receipt = "b-01M67Q3D91SE476NFVDCN0BDQZ", "r-01M67QDN97GZ201W27K06BENYT"
	opt, ok := enterprisebundle.GenerationOptions(&enterprisebundle.Receipt{ReceiptID: receipt, BundleID: id, Version: 4,
		Principal: "control-plane:acme/alice", SignerKeyID: "k1"})
	if !ok || opt.Bundle.Dir != enterprisebundle.VersionDirNameForReceipt(4, id, receipt) {
		t.Fatalf("bundle dir = %q (ok %t)", opt.Bundle.Dir, ok)
	}
}

// rel-1-0-6:GAP-0051 (managed macOS, the same lookup as GAP-0102): a
// gateway that starts on an edited config.yaml runs the stored signed
// bundle in memory even though its service account cannot list the store.
// The record names the version directory (bundle_dir), or, written by an
// earlier build, only the bundle (its first delivery's directory); a retry
// directory an old record cannot name is found through the public receipt
// event. With none of these the edited config is kept and reported, as
// when no signed bundle passes.
func TestManagedStartupRunsTheSignedBundleInAnUnlistableStore(t *testing.T) {
	const id = "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1"
	const retry = "r-01M67QDN97GZ201W27K06BENYT"
	for _, tc := range []struct {
		name, receipt string
		recordDir     bool
		event         bool
		runsSigned    bool
	}{
		{name: "record_names_the_directory", receipt: retry, recordDir: true, runsSigned: true},
		{name: "earlier_record_first_delivery", receipt: id, runsSigned: true},
		{name: "earlier_record_retry_with_receipt_event", receipt: retry, event: true, runsSigned: true},
		{name: "earlier_record_retry_without_receipt", receipt: retry},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			store := newSignedStore(t, dir)
			rendered, versionDir := store.storeFor(t, id, 1, tc.receipt, source)
			opt := bundleWrite(id, 1)
			if tc.recordDir {
				opt.Bundle.Dir = versionDir
			}
			if _, err := configwrite.ReplaceDocument(t.Context(), path, rendered, opt); err != nil {
				t.Fatal(err)
			}
			if tc.event {
				events := filepath.Join(dir, enterprisebundle.BundlesDirName, "receipt-events")
				if err := os.MkdirAll(events, 0o755); err != nil {
					t.Fatal(err)
				}
				event := fmt.Sprintf(`{"schema_version":1,"receipt_id":%q,"bundle_id":%q,"version":1,"state":"confirmed"}`, tc.receipt, id)
				if err := os.WriteFile(filepath.Join(events, tc.receipt+".json"), []byte(event), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// Edited while the gateway was stopped (no record binds it).
			edited := bytes.Replace(rendered, []byte("mode: observe"), []byte("mode: action"), 1)
			if err := os.WriteFile(path, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			unlistableStore(t, dir)
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
			var appliedRaw []byte
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, _ ConfigDiff, s configReloadSource) error {
				if s.proveUnchanged {
					return errGenerationUnchanged
				}
				appliedRaw = s.raw
				return nil
			})
			mgr.assetDirs = func() []string { return nil }
			loader := mgr.loadSnapshot
			mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
				candidate, err := loader(source, raw)
				if err == nil {
					candidate.DeploymentMode, candidate.Enterprise.Profile = "managed_enterprise", "standalone"
				}
				return candidate, err
			}
			mgr.setStartupSource(path, edited)
			clearGenerationBuildError()
			t.Cleanup(clearGenerationBuildError)
			if err := mgr.ReloadAssets(t.Context(), "startup_reconcile"); err != nil {
				t.Fatalf("startup: %v", err)
			}
			if got := liveReloadErrorText(); !strings.Contains(got, "activation_not_signed") {
				t.Fatalf("startup refusal not reported: %q", got)
			}
			if !tc.runsSigned {
				if (appliedRaw != nil && !bytes.Equal(appliedRaw, edited)) || mgr.Current().Guardrail.Mode != "action" {
					t.Fatalf("no findable signed bundle: applied %q mode %q, want the boot config kept", appliedRaw, mgr.Current().Guardrail.Mode)
				}
				return
			}
			if !strings.Contains(liveReloadErrorText(), "activation_not_signed (config)") {
				t.Fatalf("the stored bundle was not found: %q", liveReloadErrorText())
			}
			if !bytes.Equal(appliedRaw, rendered) || mgr.Current().Guardrail.Mode != "observe" {
				t.Fatalf("start fallback in an unlistable store: applied %q mode %q, want the signed bundle", appliedRaw, mgr.Current().Guardrail.Mode)
			}
		})
	}
}
