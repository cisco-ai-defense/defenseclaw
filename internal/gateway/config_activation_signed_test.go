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

	"github.com/defenseclaw/defenseclaw/internal/audit"
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
	rendered, _ := s.storeFor(t, id, version, id, source)
	return rendered
}

// storeFor is store for the delivery receipt receiptID: the version
// directory is the one Promote names for that receipt (a retry of a bundle
// has a fresh r- receipt id). It also returns that directory name.
func (s *signedStore) storeFor(t *testing.T, id string, version uint64, receiptID string, source []byte) ([]byte, string) {
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
	name := enterprisebundle.VersionDirNameForReceipt(version, id, receiptID)
	versionDir := filepath.Join(s.dir, enterprisebundle.BundlesDirName, name)
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
	return rendered, name
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

// Boot bytes that are not the signed bundle the record names run the stored
// signed bundle in memory (config.yaml untouched). Without one, startup
// refuses before serving the edited policy.
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
				if s.proveUnchanged {
					// The boot generation is the live one.
					return errGenerationUnchanged
				}
				appliedRaw = s.raw
				return nil
			})
			alertStore, logger := newNativeSkillRuntimeTestStore(t)
			mgr.logger = logger
			// A gateway with policy assets reconciles its start through
			// ReloadAssets, as production does (reconcileStartup).
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
			startupErr := mgr.ReloadAssets(t.Context(), "startup_reconcile")
			if damaged {
				if startupErr == nil || !strings.Contains(startupErr.Error(), "activation_not_signed") || appliedRaw != nil {
					t.Fatalf("damaged store startup = %v, applied=%q; want signed refusal before apply", startupErr, appliedRaw)
				}
			} else if startupErr != nil {
				t.Fatalf("startup: %v", startupErr)
			}
			if got := liveReloadError.Load(); got == nil || !strings.Contains(fmt.Sprint(got), "activation_not_signed") {
				t.Fatalf("startup refusal not reported: %v", got)
			}
			assertManagedStartupAlert(t, alertStore, !damaged)
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, edited) {
				t.Fatal("the start fallback rewrote config.yaml")
			}
			if damaged {
				return
			}
			if !bytes.Equal(appliedRaw, rendered) || mgr.Current().Guardrail.Mode != "observe" {
				t.Fatalf("start fallback: applied %q mode %q, want the signed bundle", appliedRaw, mgr.Current().Guardrail.Mode)
			}
			// A later watcher event for the edited file stays refused.
			if err := mgr.Reload(t.Context(), "watch"); err == nil {
				t.Fatal("the edited config.yaml was activated after the start fallback")
			}
			// The repair puts the signed config back: the refusal clears.
			if err := os.WriteFile(path, rendered, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := mgr.Reload(t.Context(), "watch"); err != nil || liveReloadErrorText() != "" {
				t.Fatalf("after the repair: err=%v last reload error %q", err, liveReloadErrorText())
			}
		})
	}
}

// A watcher event buffered during startup can cause a second reload after
// the signed fallback, and an external reload can arrive before startup
// reconciliation. Both orders must report the signed activation refusal.
func TestManagedStartupActivationRefusalWinsReloadOrders(t *testing.T) {
	for _, order := range [][]string{
		{"startup_reconcile", "watch"},
		{"watch", "startup_reconcile"},
		{"watch_assets", "startup_reconcile"},
	} {
		t.Run(strings.Join(order, "_then_"), func(t *testing.T) {
			_, _, path, _, _ := managedSignedManager(t)
			signed, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			edited := bytes.Replace(signed, []byte("mode: observe"), []byte("mode: action"), 1)
			if bytes.Equal(edited, signed) {
				t.Fatal("fixture did not change the signed config")
			}
			if err := os.WriteFile(path, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
			applied := 0
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
				applied++
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
			want := mgr.startupActivationRefusal(edited)
			if want == nil || want.Cause != enterprisebundle.ActivationConfig {
				t.Fatalf("fixture activation refusal = %v", want)
			}
			clearGenerationBuildError()
			t.Cleanup(clearGenerationBuildError)
			for _, step := range order {
				switch step {
				case "startup_reconcile":
					err = mgr.ReloadAssets(t.Context(), step)
					if err != nil {
						t.Fatalf("%s: %v", step, err)
					}
				case "watch":
					err = mgr.Reload(t.Context(), step)
					if err == nil {
						t.Fatal("unsigned edit was accepted")
					}
				case "watch_assets":
					err = mgr.ReloadAssets(t.Context(), step)
					if err == nil {
						t.Fatal("unsigned asset reload was accepted")
					}
				}
				if got := liveReloadErrorText(); got != want.Error() {
					t.Fatalf("after %s: last_reload_error = %q, want %q", step, got, want.Error())
				}
			}
			if mgr.Current().Guardrail.Mode != "observe" || applied != 1 {
				t.Fatalf("stored signed bundle not kept: mode=%q applies=%d", mgr.Current().Guardrail.Mode, applied)
			}
		})
	}
}

// A boot edit to a process-level setting must not survive the signed
// fallback. If that setting cannot be restored before serving, startup must
// fail closed. A watcher reload before reconciliation cannot change this.
func TestManagedStartupUnsignedRestartSettingNeverServes(t *testing.T) {
	for _, order := range [][]string{
		{"startup_reconcile", "watch"},
		{"watch", "startup_reconcile"},
		{"watch_assets", "startup_reconcile"},
	} {
		t.Run(strings.Join(order, "_then_"), func(t *testing.T) {
			clearGenerationBuildError()
			t.Cleanup(clearGenerationBuildError)
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			source = bytes.Replace(source, []byte("  mode: observe"), []byte("  enabled: true\n  mode: observe"), 1)
			store := newSignedStore(t, dir)
			signed := store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1, source)
			if _, err := configwrite.ReplaceDocument(t.Context(), path, signed, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1)); err != nil {
				t.Fatal(err)
			}
			edited := bytes.Replace(signed, []byte("enabled: true"), []byte("enabled: false"), 1)
			if bytes.Equal(edited, signed) {
				t.Fatal("fixture did not edit guardrail.enabled")
			}
			if err := os.WriteFile(path, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
			if initial.Guardrail.Enabled {
				t.Fatal("boot edit did not disable guardrail")
			}
			applied := 0
			var effectiveEnabled bool
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, next *config.Config, _ ConfigDiff, source configReloadSource) error {
				if source.proveUnchanged {
					return errGenerationUnchanged
				}
				applied++
				effectiveEnabled = next.Guardrail.Enabled
				return nil
			})
			alertStore, logger := newNativeSkillRuntimeTestStore(t)
			mgr.logger = logger
			loader := mgr.loadSnapshot
			mgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
				candidate, err := loader(source, raw)
				if err == nil {
					candidate.DeploymentMode, candidate.Enterprise.Profile = "managed_enterprise", "standalone"
				}
				return candidate, err
			}
			mgr.assetDirs = func() []string { return nil }
			mgr.setStartupSource(path, edited)
			for _, step := range order {
				if step != "startup_reconcile" {
					var err error
					if step == "watch_assets" {
						err = mgr.ReloadAssets(t.Context(), step)
					} else {
						err = mgr.Reload(t.Context(), step)
					}
					if err == nil {
						t.Fatalf("%s accepted unsigned boot edit", step)
					}
					continue
				}
				err := mgr.ReloadAssets(t.Context(), step)
				if err != nil {
					if !strings.Contains(err.Error(), "activation_not_signed") || applied != 0 ||
						!strings.Contains(liveReloadErrorText(), "activation_not_signed") {
						t.Fatalf("startup refusal = %v, applied=%d, status=%q; want signed refusal before apply", err, applied, liveReloadErrorText())
					}
					assertManagedStartupAlert(t, alertStore, false)
					return
				}
				if applied != 1 || !effectiveEnabled || !mgr.Current().Guardrail.Enabled || !bytes.Equal(mgr.appliedRaw, signed) {
					t.Fatalf("startup applied unsigned setting: applied=%d callback_enabled=%t current_enabled=%t raw_signed=%t",
						applied, effectiveEnabled, mgr.Current().Guardrail.Enabled, bytes.Equal(mgr.appliedRaw, signed))
				}
			}
		})
	}
}

func assertManagedStartupAlert(t *testing.T, store *audit.Store, running bool) {
	t.Helper()
	alerts, err := store.ListAlerts(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, alert := range alerts {
		if !strings.Contains(alert.Details, `"event":"config.activation.refused"`) ||
			!strings.Contains(alert.Details, `"path_class":"startup"`) {
			continue
		}
		if running {
			if !strings.Contains(alert.Details, `"running_bundle_id":`) ||
				!strings.Contains(alert.Details, "running the stored signed bundle in memory") {
				t.Fatalf("startup alert did not name the running bundle: %s", alert.Details)
			}
		} else if strings.Contains(alert.Details, `"running_bundle_id":`) ||
			!strings.Contains(alert.Details, "gateway did not start serving") {
			t.Fatalf("startup alert reported a policy as running: %s", alert.Details)
		}
		return
	}
	t.Fatalf("no startup activation alert in %+v", alerts)
}

func TestManagedStartupWithoutVerifiableBundleRefusesUnsignedBootEdit(t *testing.T) {
	clearGenerationBuildError()
	t.Cleanup(clearGenerationBuildError)
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = bytes.Replace(source, []byte("  mode: observe"), []byte("  enabled: true\n  mode: observe"), 1)
	store := newSignedStore(t, dir)
	signed := store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1, source)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, signed, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1)); err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(signed, []byte("enabled: true"), []byte("enabled: false"), 1)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store.writeAnchors(t, "k9", public)
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
	applied := 0
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
		applied++
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
	mgr.assetDirs = func() []string { return nil }
	mgr.setStartupSource(path, edited)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
	err = <-ready
	cancel()
	<-done
	if err == nil || !strings.Contains(err.Error(), "activation_not_signed") || applied != 0 ||
		!strings.Contains(liveReloadErrorText(), "activation_not_signed") {
		t.Fatalf("unsigned boot with no verifiable bundle: ready=%v applied=%d status=%q, want refusal before serving", err, applied, liveReloadErrorText())
	}
}

func TestManagedStartupRefusesMissingBundleTrust(t *testing.T) {
	for _, cause := range []string{"anchors_removed", "no_stored_version"} {
		t.Run(cause, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			store := newSignedStore(t, dir)
			if cause == "anchors_removed" {
				raw = store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1, raw)
				if _, err := configwrite.ReplaceDocument(t.Context(), path, raw, bundleWrite("b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1)); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(dir, "trust", enterprisebundle.AnchorsName)); err != nil {
					t.Fatal(err)
				}
			}
			mgr := &ConfigManager{path: path}
			refusal := mgr.startupActivationRefusal(raw)
			if refusal == nil || !strings.Contains(refusal.Error(), "activation_not_signed") {
				t.Fatalf("%s: missing signed trust admitted: %v", cause, refusal)
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

// With trust anchors installed, a lifecycle record without a signed bundle
// does not authorize startup. The gateway cannot assume a stored bundle
// that is not named by the record is the right one to run.
func TestManagedStartupRefusesUnbundledLifecycleBootBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	source, _ := os.ReadFile(path)
	store := newSignedStore(t, dir)
	store.store(t, "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1", 1, bytes.Replace(source, []byte("mode: observe"), []byte("mode: action"), 1))
	raw := append([]byte("# base\n"), source...)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, raw, configwrite.Options{Actor: configwrite.ActorLifecycle, Lifecycle: true, Reason: "enterprise ensure"}); err != nil {
		t.Fatal(err)
	}
	mgr := &ConfigManager{path: path}
	if refusal := mgr.startupActivationRefusal(raw); refusal == nil {
		t.Fatal("unbundled lifecycle boot bytes were admitted with trust anchors")
	}
	if refusal := mgr.startupActivationRefusal(append([]byte("# edited while stopped\n"), raw...)); refusal == nil {
		t.Fatal("unrecorded boot bytes with a signed bundle in the store were admitted")
	}
}

func TestManagedStartupAdmitsFirstBundleWithStagedAnchors(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "etc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store := newSignedStore(t, dir)
	const id = "b-01J9ZZZZZZZZZZZZZZZZZZZZZ1"
	rendered, versionDir := store.storeFor(t, id, 1, id, source)
	opt := bundleWrite(id, 1)
	opt.Bundle.Dir = versionDir
	if _, err := configwrite.ReplaceDocument(t.Context(), path, rendered, opt); err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(root, "install", "bundle-anchors-"+id+".json")
	if err := os.MkdirAll(filepath.Dir(stage), 0o700); err != nil {
		t.Fatal(err)
	}
	installedAnchors := filepath.Join(dir, "trust", enterprisebundle.AnchorsName)
	if err := os.Rename(installedAnchors, stage); err != nil {
		t.Fatal(err)
	}
	mgr := &ConfigManager{path: path}
	if refusal := mgr.startupActivationRefusal(rendered); refusal != nil {
		t.Fatalf("first bundle before anchor promotion: %v", refusal)
	}
	if refusal := mgr.startupActivationRefusal(append([]byte("# changed\n"), rendered...)); refusal == nil {
		t.Fatal("unrecorded bytes were admitted before anchor promotion")
	}
	initial, err := config.LoadRuntimeV8File(path)
	if err != nil {
		t.Fatal(err)
	}
	initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
	runtimeMgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(_ context.Context, _, _ *config.Config, _ ConfigDiff, source configReloadSource) error {
		if source.proveUnchanged {
			return errGenerationUnchanged
		}
		return nil
	})
	loader := runtimeMgr.loadSnapshot
	runtimeMgr.loadSnapshot = func(source string, raw []byte) (*config.Config, error) {
		candidate, err := loader(source, raw)
		if err == nil {
			candidate.DeploymentMode, candidate.Enterprise.Profile = "managed_enterprise", "standalone"
		}
		return candidate, err
	}
	runtimeMgr.assetDirs = func() []string { return nil }
	runtimeMgr.setStartupSource(path, rendered)
	ctx, cancel := context.WithCancel(t.Context())
	ready := make(chan error, 1)
	done := make(chan error, 1)
	go func() { done <- runtimeMgr.runWithStartupReconcile(ctx, ready) }()
	startupErr := <-ready
	cancel()
	<-done
	if startupErr != nil {
		t.Fatalf("first bundle before anchor promotion did not start: %v", startupErr)
	}
	if err := os.Rename(stage, installedAnchors); err != nil {
		t.Fatal(err)
	}
	if refusal := mgr.startupActivationRefusal(rendered); refusal != nil {
		t.Fatalf("first bundle after anchor promotion: %v", refusal)
	}
}

func TestManagedStartupNoAnchorReloadOrders(t *testing.T) {
	for _, before := range []string{"startup_first", "watch_first", "asset_watch_first"} {
		t.Run(before, func(t *testing.T) {
			clearGenerationBuildError()
			t.Cleanup(clearGenerationBuildError)
			dir := t.TempDir()
			path := filepath.Join(dir, config.DefaultConfigName)
			writeConfigForManagerTest(t, path, dir, "observe")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw = bytes.Replace(raw, []byte("  mode: observe"), []byte("  enabled: true\n  mode: observe"), 1)
			if _, err := configwrite.ReplaceDocument(t.Context(), path, raw, configwrite.Options{
				Actor: configwrite.ActorLifecycle, Lifecycle: true, Reason: "enterprise ensure",
			}); err != nil {
				t.Fatal(err)
			}
			edited := bytes.Replace(raw, []byte("enabled: true"), []byte("enabled: false"), 1)
			if err := os.WriteFile(path, edited, 0o600); err != nil {
				t.Fatal(err)
			}
			initial, err := config.LoadRuntimeV8File(path)
			if err != nil {
				t.Fatal(err)
			}
			initial.DeploymentMode, initial.Enterprise.Profile = "managed_enterprise", "standalone"
			applied := 0
			mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", func(context.Context, *config.Config, *config.Config, ConfigDiff, configReloadSource) error {
				applied++
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
			mgr.assetDirs = func() []string { return nil }
			mgr.setStartupSource(path, edited)
			if before == "watch_first" {
				_ = mgr.Reload(t.Context(), "watch")
			} else if before == "asset_watch_first" {
				_ = mgr.ReloadAssets(t.Context(), "watch_assets")
			}
			ctx, cancel := context.WithCancel(t.Context())
			ready := make(chan error, 1)
			done := make(chan error, 1)
			go func() { done <- mgr.runWithStartupReconcile(ctx, ready) }()
			err = <-ready
			cancel()
			<-done
			if err == nil || !strings.Contains(err.Error(), "activation_not_signed (config)") || applied != 0 ||
				!strings.Contains(liveReloadErrorText(), "activation_not_signed (config)") {
				t.Fatalf("startup: ready=%v applied=%d status=%q", err, applied, liveReloadErrorText())
			}
		})
	}
}

func TestManagedStartupNoAnchorRecordedConfigStarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append([]byte("# lifecycle\n"), raw...)
	if _, err := configwrite.ReplaceDocument(t.Context(), path, raw, configwrite.Options{
		Actor: configwrite.ActorLifecycle, Lifecycle: true, Reason: "enterprise ensure",
	}); err != nil {
		t.Fatal(err)
	}
	mgr := &ConfigManager{path: path}
	if refusal := mgr.startupActivationRefusal(raw); refusal != nil {
		t.Fatalf("recorded config without anchors: %v", refusal)
	}
	if refusal := mgr.startupActivationRefusal(append([]byte("# changed\n"), raw...)); refusal == nil {
		t.Fatal("unrecorded config without anchors was admitted")
	}
	newSignedStore(t, dir)
	if refusal := mgr.startupActivationRefusal(raw); refusal != nil {
		t.Fatalf("recorded config before first bundle: %v", refusal)
	}
}
