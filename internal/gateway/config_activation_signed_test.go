// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
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

// signedStore is a device bundle store next to a test config.yaml: trust
// anchors with one key and signed bundle version directories.
type signedStore struct {
	dir string
	key ed25519.PrivateKey
}

func newSignedStore(t *testing.T, dir string) *signedStore {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &signedStore{dir: dir, key: private}
	s.writeAnchors(t, "k1", public)
	return s
}

func (s *signedStore) writeAnchors(t *testing.T, keyID string, public ed25519.PublicKey) {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	raw := fmt.Sprintf(`{"schema_version":1,"tenant_id":"acme","device_groups":["eng"],"min_version":0,"keys":[{"key_id":%q,"alg":"ed25519","public_key":%q,"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"active"}]}`,
		keyID, base64.StdEncoding.EncodeToString(spki))
	if err := os.MkdirAll(filepath.Join(s.dir, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.dir, "trust", enterprisebundle.AnchorsName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

// store signs source as config.yaml (plus a shipped rule pack) of bundle
// id at version, stores it under bundles/<version dir> and returns the
// bytes an apply installs (RenderConfig against that directory).
func (s *signedStore) store(t *testing.T, id string, version uint64, source []byte) []byte {
	t.Helper()
	b := &enterprisebundle.Bundle{Files: map[string][]byte{
		enterprisebundle.ConfigName:            source,
		"policies/guardrail/custom/rules.yaml": []byte("name: custom\n"),
	}}
	m := &enterprisebundle.Manifest{
		SchemaVersion: enterprisebundle.ManifestSchemaVersion,
		BundleID:      id, TenantID: "acme", Version: version,
		Target:    enterprisebundle.Target{DeviceGroup: "eng", Platforms: []string{runtime.GOOS}},
		CreatedAt: "2026-10-30T08:30:00Z", CreatedBy: "control-plane:acme/alice",
		Files:           enterprisebundle.FileEntries(b),
		SecretRefs:      []enterprisebundle.SecretRef{},
		EffectivePolicy: enterprisebundle.EffectivePolicy{ProductVersion: "1.0.6", ComputedOn: runtime.GOOS, Digests: map[string]string{runtime.GOOS: "sha256:" + strings.Repeat("a", 64)}},
	}
	manifest, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := enterprisebundle.Sign(manifest, s.key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	signature, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	versionDir := filepath.Join(s.dir, enterprisebundle.BundlesDirName, enterprisebundle.VersionDirNameForReceipt(version, id, id))
	files := map[string][]byte{enterprisebundle.ManifestName: manifest, enterprisebundle.SignatureName: signature}
	for name, data := range b.Files {
		files[name] = data
	}
	for name, data := range files {
		path := filepath.Join(versionDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rendered, err := enterprisebundle.RenderConfig(b, versionDir)
	if err != nil {
		t.Fatal(err)
	}
	return rendered
}

func bundleWrite(id string, version uint64) configwrite.Options {
	return configwrite.Options{Actor: "control-plane:acme/alice", Reason: "bundle", Lifecycle: true,
		Bundle: configwrite.BundleRef{ID: id, Version: version, SignerKeyID: "k1"}}
}

// managedSignedManager is a running standalone managed manager on a config
// whose first generation is the signed bundle v1 of a store.
func managedSignedManager(t *testing.T) (mgr *ConfigManager, store *signedStore, path string, source []byte, applied *int) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store = newSignedStore(t, dir)
	rendered := store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1, source)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, rendered, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1)); err != nil {
		t.Fatal(err)
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
	count := 0
	mgr = newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		count++
		return nil
	})
	loader := mgr.loadSnapshot
	mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
		candidate, err := loader(source, raw)
		if err == nil {
			candidate.DeploymentMode, candidate.Enterprise.Profile = "managed_enterprise", "standalone"
		}
		return candidate, err
	}
	mgr.setStartupSource(path, rendered)
	if err := mgr.Reload(t.Context(), "startup_reconcile"); err != nil {
		t.Fatalf("startup on the signed bundle: %v", err)
	}
	return mgr, store, path, source, &count
}

// private #7: with trust anchors installed, a generation record that names
// a bundle activates only the bytes a signed bundle in the store renders. A
// new signed apply and an apply rollback to the last good bundle pass; a
// hand edit, a forged record naming an unstored bundle, a record naming a
// stored bundle over other bytes, a tampered shipped file and a bundle
// signed by a key that is no anchor are refused, the live policy unchanged.
func TestManagedActivationRequiresASignedStoredBundle(t *testing.T) {
	mgr, store, path, source, applied := managedSignedManager(t)
	if mgr.rejected {
		t.Fatal("startup on the signed bundle was refused")
	}
	actionSource := bytes.Replace(source, []byte("mode: observe"), []byte("mode: action"), 1)

	// A new signed bundle (apply): admitted.
	v2 := store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ2", 2, actionSource)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v2, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ2", 2)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "watch"); err != nil || mgr.Current().Guardrail.Mode != "action" {
		t.Fatalf("signed apply: err=%v mode=%q", err, mgr.Current().Guardrail.Mode)
	}
	// The apply rollback puts the last good bundle back: admitted.
	v1, err := enterprisebundle.RenderConfig(mustReadDir(t, store, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1), versionDirOf(store, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v1, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1)); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(t.Context(), "watch"); err != nil || mgr.Current().Guardrail.Mode != "observe" {
		t.Fatalf("apply rollback: err=%v mode=%q", err, mgr.Current().Guardrail.Mode)
	}
	before := *applied
	refused := func(name string, wantCause string) {
		t.Helper()
		err := mgr.ReloadRecordedGeneration(t.Context(), "api:policy_reload")
		if err == nil || !strings.Contains(err.Error(), "activation_not_signed ("+wantCause+")") {
			t.Fatalf("%s: err=%v, want activation_not_signed (%s)", name, err, wantCause)
		}
		if *applied != before || mgr.Current().Guardrail.Mode != "observe" {
			t.Fatalf("%s: applied=%d mode=%q, live policy changed", name, *applied, mgr.Current().Guardrail.Mode)
		}
	}
	// A record naming a bundle the store does not hold.
	if _, err := configwrite.ReplaceDocument(t.Context(), path, actionSource, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ9", 9)); err != nil {
		t.Fatal(err)
	}
	refused("forged record", enterprisebundle.ActivationNotStored)
	// A record naming the stored v2 over hand-edited bytes.
	edited := append([]byte("# edited\n"), v2...)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, edited, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ2", 2)); err != nil {
		t.Fatal(err)
	}
	refused("stored bundle over other bytes", enterprisebundle.ActivationConfig)
	// A shipped file of v2 changed after it was stored.
	pack := filepath.Join(versionDirOf(store, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ2", 2), "policies", "guardrail", "custom", "rules.yaml")
	if err := os.WriteFile(pack, []byte("name: changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v2, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ2", 2)); err != nil {
		t.Fatal(err)
	}
	refused("tampered shipped file", enterprisebundle.ActivationDigest)
	// A bundle signed by a key that is not a trust anchor.
	_, otherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	rogue := &signedStore{dir: store.dir, key: otherPrivate}
	v3 := rogue.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ3", 3, actionSource)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, v3, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ3", 3)); err != nil {
		t.Fatal(err)
	}
	refused("unsigned by an anchor key", enterprisebundle.ActivationSignature)
}

func versionDirOf(s *signedStore, id string, version uint64) string {
	return filepath.Join(s.dir, enterprisebundle.BundlesDirName, enterprisebundle.VersionDirNameForReceipt(version, id, id))
}

func mustReadDir(t *testing.T, s *signedStore, id string, version uint64) *enterprisebundle.Bundle {
	t.Helper()
	b, err := enterprisebundle.ReadDir(versionDirOf(s, id, version))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// private #7, start: boot bytes that are not the signed bundle the record
// names run the stored signed bundle in memory (config.yaml untouched) and
// report the refusal; with no signed bundle that passes, the gateway keeps
// the boot config (hooks keep their fail-mode table) and reports not ok.
func TestManagedStartupRunsTheSignedBundleInMemory(t *testing.T) {
	for _, damaged := range []bool{false, true} {
		t.Run(fmt.Sprintf("store_damaged=%t", damaged), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			store := newSignedStore(t, dir)
			rendered := store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1, source)
			if _, err := configwrite.ReplaceDocument(t.Context(), path, rendered, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1)); err != nil {
				t.Fatal(err)
			}
			// Edited while the gateway was stopped (no record binds it).
			edited := bytes.Replace(rendered, []byte("mode: observe"), []byte("mode: action"), 1)
			if err := os.WriteFile(path, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			if damaged {
				// Replaced anchors: no stored bundle verifies.
				public, _, _ := ed25519.GenerateKey(rand.Reader)
				store.writeAnchors(t, "k9", public)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
			var appliedRaw []byte
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, _ ConfigDiff, s configReloadSource) error {
				appliedRaw = s.raw
				return nil
			})
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
			if err := mgr.Reload(t.Context(), "startup_reconcile"); err != nil {
				t.Fatalf("startup: %v", err)
			}
			if got := liveReloadError.Load(); got == nil || !strings.Contains(fmt.Sprint(got), "activation_not_signed") {
				t.Fatalf("startup refusal not reported: %v", got)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, edited) {
				t.Fatal("the start fallback rewrote config.yaml")
			}
			if damaged {
				if (appliedRaw != nil && !bytes.Equal(appliedRaw, edited)) || mgr.Current().Guardrail.Mode != "action" {
					t.Fatalf("no signed bundle passes: applied %q mode %q, want the boot config kept", appliedRaw, mgr.Current().Guardrail.Mode)
				}
				return
			}
			if !bytes.Equal(appliedRaw, rendered) || mgr.Current().Guardrail.Mode != "observe" {
				t.Fatalf("start fallback: applied %q mode %q, want the signed bundle", appliedRaw, mgr.Current().Guardrail.Mode)
			}
			// A later watcher event for the edited file stays refused.
			if err := mgr.Reload(t.Context(), "watch"); err == nil {
				t.Fatal("the edited config.yaml was activated after the start fallback")
			}
		})
	}
}

// An upgrade from 1.0.4 or 1.0.5 on a confirmed bundle starts with no
// refusal: the old build's record names the bundle and config.yaml is what
// the stored signed bundle renders. Without trust anchors (CONFIG= installs)
// nothing changes: a lifecycle record activates and a named bundle is not
// checked.
func TestManagedActivationUpgradeAndConfigInstallsUnchanged(t *testing.T) {
	mgr, _, _, _, _ := managedSignedManager(t)
	if mgr.rejected || liveReloadErrorText() != "" {
		t.Fatalf("upgrade start on a confirmed bundle refused: %q", liveReloadErrorText())
	}

	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	raw, _ := os.ReadFile(path)
	raw = append([]byte("# lifecycle\n"), raw...)
	mgr2 := &ConfigManager{path: path}
	mgr2.appliedGenerationKnown = true
	if _, err := configwrite.ReplaceDocument(t.Context(), path, raw, configwrite.Options{Actor: configwrite.ActorLifecycle, Lifecycle: true, Reason: "enterprise ensure"}); err != nil {
		t.Fatal(err)
	}
	if ok, refusal := mgr2.managedGenerationAdmission(raw); !ok || refusal != nil {
		state, err := configwrite.ReadGenerationState(path)
		t.Fatalf("CONFIG= lifecycle record without anchors: %t %v (record %+v, %v)", ok, refusal, state, err)
	}
	edited := append([]byte("# b\n"), raw...)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, edited, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ9", 9)); err != nil {
		t.Fatal(err)
	}
	if ok, refusal := mgr2.managedGenerationAdmission(edited); !ok || refusal != nil {
		t.Fatalf("bundle record without anchors: %t %v", ok, refusal)
	}
}

func liveReloadErrorText() string {
	if got := liveReloadError.Load(); got != nil {
		return fmt.Sprint(got)
	}
	return ""
}
