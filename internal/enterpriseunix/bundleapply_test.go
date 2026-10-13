// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// bundleHost is an installed fake host in bundle mode: trust anchors with
// one ed25519 key, a gateway that reports the digest of the installed
// config.yaml (as a generation swap would) unless it is frozen, and a
// bundle digester that hashes the rendered config.
type bundleHost struct {
	*testHost
	key ed25519.PrivateKey
	// frozen makes the gateway keep reporting this digest and reloadError.
	frozen, reloadError string
	// extra are bundle files next to config.yaml in every bundle signed.
	extra map[string]string
}

// bundleRunner answers `policy digest --json` with the digest of the
// installed config.yaml and its recorded generation.
type bundleRunner struct {
	*fakeRunner
	h *testHost
}

func (r *bundleRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.Join(args, " ") == "policy digest --json" {
		digest, generation := installedPolicy(r.h)
		return CommandResult{Stdout: []byte(fmt.Sprintf(`{"effective_digest":%q,"config_generation":%d}`, digest, generation))}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func installedPolicy(h *testHost) (string, uint64) {
	raw, _ := os.ReadFile(h.env.P(h.env.Layout.ConfigPath))
	state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	return "sha256:" + sha256Bytes(raw), state.Generation
}

func newBundleHost(t *testing.T) *bundleHost {
	t.Helper()
	b := &bundleHost{testHost: newTestHost(t, "linux")}
	h := b.testHost
	// Version directories are read-only; the temporary root must go.
	t.Cleanup(func() {
		_ = filepath.WalkDir(h.env.P(filepath.Join(h.env.Layout.ConfigDir, enterprisebundle.BundlesDirName)), func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	h.env.Runner = &bundleRunner{fakeRunner: h.runner, h: h}
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		if !h.healthy || !h.services.isActive(unitGateway) {
			return 0, nil, errors.New("connection refused")
		}
		digest, generation := installedPolicy(h)
		if b.frozen != "" {
			digest = b.frozen
		}
		return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d,"last_reload_error":%q},"inspection":{"local":"active","ai_defense":"disabled"}}`,
			digest, generation, b.reloadError)), nil
	}
	h.env.BundleDigester = func(_ context.Context, _ *config.Config, raw []byte, _, root string) (string, error) {
		// As the gateway digest does, the bundle root is ${bundle_root}.
		if root != "" {
			raw = bytes.ReplaceAll(raw, []byte(root), []byte("${bundle_root}"))
		}
		return "sha256:" + sha256Bytes(raw), nil
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	b.key = key
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	anchors := fmt.Sprintf(`{"schema_version":1,"tenant_id":"acme","device_groups":[],"min_version":0,"keys":[{"key_id":"k1","alg":"ed25519","public_key":%q,"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","status":"active"}]}`,
		base64.StdEncoding.EncodeToString(spki))
	writeRooted(t, h.env.bundleAnchorsPath(), anchors)
	return b
}

func writeRooted(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// signed composes and signs a bundle of config and returns it in memory.
func (b *bundleHost) signed(version uint64, cfg string) *enterprisebundle.Bundle {
	t := b.t
	t.Helper()
	root := t.TempDir()
	writeRooted(t, filepath.Join(root, enterprisebundle.ConfigName), cfg)
	files := &enterprisebundle.Bundle{Files: map[string][]byte{enterprisebundle.ConfigName: []byte(cfg)}}
	for name, content := range b.extra {
		writeRooted(t, filepath.Join(root, filepath.FromSlash(name)), content)
		files.Files[name] = []byte(content)
	}
	_, manifest, err := enterprisebundle.Compose(context.Background(), enterprisebundle.ComposeInput{
		Bundle: files, Root: root, BundleID: fmt.Sprintf("b-01JA%022d", version), TenantID: "acme", DeviceGroup: "eng",
		Platforms: []string{"linux"}, Version: version, CreatedAt: time.Now().Add(-time.Hour), CreatedBy: "operator:mdm-admin",
		ChangeSummary: fmt.Sprintf("version %d", version), ProductVersion: b.env.ProductVersion, HostPlatform: "linux",
		Digester: b.env.BundleDigester,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := enterprisebundle.Sign(manifest, b.key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	rawSig, err := sig.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &enterprisebundle.Bundle{Manifest: manifest, Signature: rawSig, Files: files.Files}
}

// dir writes a signed bundle as a directory and returns its path.
func (b *bundleHost) dir(version uint64, cfg string) string {
	b.t.Helper()
	bundle := b.signed(version, cfg)
	dir := b.t.TempDir()
	writeRooted(b.t, filepath.Join(dir, enterprisebundle.ManifestName), string(bundle.Manifest))
	writeRooted(b.t, filepath.Join(dir, enterprisebundle.SignatureName), string(bundle.Signature))
	for name, content := range bundle.Files {
		writeRooted(b.t, filepath.Join(dir, filepath.FromSlash(name)), string(content))
	}
	return dir
}

func (b *bundleHost) apply(path string) *enterprisestatus.Result {
	b.t.Helper()
	return b.run(Options{Action: ActionEnsure, Bundle: path})
}

func (b *bundleHost) state() enterprisebundle.State {
	b.t.Helper()
	st, err := b.env.bundleStore().LoadState()
	if err != nil {
		b.t.Fatal(err)
	}
	return st
}

func (b *bundleHost) receipt(id string) *enterprisebundle.Receipt {
	b.t.Helper()
	receipts, err := b.env.bundleStore().Receipts()
	if err != nil {
		b.t.Fatal(err)
	}
	for _, r := range receipts {
		if r.BundleID == id {
			return r
		}
	}
	b.t.Fatalf("no receipt for %s", id)
	return nil
}

func bundleID(version uint64) string { return fmt.Sprintf("b-01JA%022d", version) }

// gatewayTouched reports whether the gateway was stopped, started or
// restarted since call index from.
func gatewayTouched(h *testHost, from int) bool {
	for _, call := range h.services.calls[from:] {
		if strings.HasSuffix(call, " "+unitGateway) && !strings.HasPrefix(call, "enable ") {
			return true
		}
	}
	return false
}

func bundleConfigs(h *testHost) (v1, v2, restart string) {
	v1 = string(DefaultConfig(h.env.Layout))
	v2 = strings.Replace(v1, "mode: observe", "mode: action", 1)
	restart = strings.Replace(v2, "mode: action\n", "mode: action\n  hook_self_heal: false\n", 1)
	return v1, v2, restart
}

// A bundle goes through stage, verify, the ensure transaction, the gateway
// confirm and the swap. A policy-only change is applied in the running
// gateway (restart false), a restart-required key restarts it (restart
// true), and a repeated delivery of the current bundle is already_applied.
func TestBundleApplyConfirmsHotAndRestartBundles(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, restart := bundleConfigs(b.testHost)
	from := len(b.services.calls)
	r := b.apply(b.dir(1, v1))
	requireOK(t, r)
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(1) || st.Floor != 1 || st.LastGood != nil {
		t.Fatalf("after v1: state = %+v", st)
	}
	rc := b.receipt(bundleID(1))
	digest, generation := installedPolicy(b.testHost)
	if rc.State != enterprisebundle.StateConfirmed || rc.EffectivePolicyDigest != digest || rc.ConfigGeneration != generation || rc.Restart || gatewayTouched(b.testHost, from) {
		t.Fatalf("v1 receipt = %+v (gateway touched %v)", rc, gatewayTouched(b.testHost, from))
	}
	if r.Bundle == nil || r.Bundle.State != enterprisebundle.StateConfirmed || r.Bundle.BundleID != bundleID(1) {
		t.Fatalf("result bundle block = %+v", r.Bundle)
	}
	gen, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath))
	if err != nil || gen.Actor != "operator:mdm-admin" || gen.BundleID != bundleID(1) || gen.BundleVersion != 1 || gen.SignerKeyID != "k1" || !strings.Contains(gen.Reason, "version 1") {
		t.Fatalf("generation record = %+v, %v", gen, err)
	}
	committed, err := os.ReadFile(b.env.committedConfigPath())
	if err != nil || sha256Bytes(committed) != rc.ConfigSHA256 {
		t.Fatalf("committed-config.yaml is not the bundle config: %v", err)
	}

	from = len(b.services.calls)
	requireOK(t, b.apply(b.dir(2, v2)))
	if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateConfirmed || rc.Restart || gatewayTouched(b.testHost, from) {
		t.Fatalf("hot bundle: receipt = %+v, gateway touched = %v", rc, gatewayTouched(b.testHost, from))
	}
	if st := b.state(); st.LastGood == nil || st.LastGood.BundleID != bundleID(1) || st.Floor != 2 {
		t.Fatalf("after v2: state = %+v", st)
	}

	from = len(b.services.calls)
	path := b.dir(3, restart)
	requireOK(t, b.apply(path))
	if rc := b.receipt(bundleID(3)); rc.State != enterprisebundle.StateConfirmed || !rc.Restart || !gatewayTouched(b.testHost, from) {
		t.Fatalf("restart bundle: receipt = %+v, gateway touched = %v", rc, gatewayTouched(b.testHost, from))
	}
	// Version directories other than current and last good are gone.
	if _, err := os.Stat(b.env.P(b.env.bundleVersionDir(enterprisebundle.VersionDirName(1, bundleID(1))))); !os.IsNotExist(err) {
		t.Fatalf("v1 directory kept: %v", err)
	}

	receipts, _ := b.env.bundleStore().Receipts()
	r = b.apply(path)
	requireOK(t, r)
	after, _ := b.env.bundleStore().Receipts()
	if !r.Noop || r.NoopReason != "already_applied" || len(after) != len(receipts) {
		t.Fatalf("retry: noop = %v (%s), receipts %d -> %d", r.Noop, r.NoopReason, len(receipts), len(after))
	}
}

// A fault at every phase of an apply ends in a failed receipt with the last
// good bundle current and its config installed; the same bundle applies on
// a retry.
func TestBundleApplyFaultAtEveryPhaseKeepsTheLastGoodBundle(t *testing.T) {
	for _, phase := range []string{"received", "verified", "staged", "transaction", "applied"} {
		t.Run(phase, func(t *testing.T) {
			b := newBundleHost(t)
			v1, v2, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			good := b.read(b.env.Layout.ConfigPath)
			b.env.bundleFault = func(p string) error {
				if p == phase {
					return errors.New("injected fault at " + p)
				}
				return nil
			}
			path := b.dir(2, v2)
			r := b.apply(path)
			if r.OK {
				t.Fatal("the apply with a fault succeeded")
			}
			rc := b.receipt(bundleID(2))
			if rc.State != enterprisebundle.StateFailed || rc.ErrorCode == "" {
				t.Fatalf("receipt = %+v", rc)
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(1) || st.Floor != 1 {
				t.Fatalf("state = %+v", st)
			}
			if b.read(b.env.Layout.ConfigPath) != good {
				t.Fatal("config.yaml is not the last good bundle config")
			}
			if (phase == "transaction" || phase == "applied") && !rc.RolledBack {
				t.Fatalf("a fault in the transaction did not roll back: %+v", rc)
			}
			b.env.bundleFault = nil
			requireOK(t, b.apply(path))
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(2) {
				t.Fatalf("retry: state = %+v", st)
			}
		})
	}
}

// A run that dies at any point of an apply leaves the host enforcing the
// last good bundle; the next run recovers (or, after the commit, confirms)
// and a retry of the same bundle succeeds.
func TestBundleApplyCrashPointMatrix(t *testing.T) {
	for _, phase := range []string{"received", "verified", "staged", "transaction", "applied", "committed"} {
		t.Run(phase, func(t *testing.T) {
			b := newBundleHost(t)
			v1, v2, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			good := b.read(b.env.Layout.ConfigPath)
			b.env.bundleFault = func(p string) error {
				if p != phase {
					return nil
				}
				if p == "committed" {
					return errors.New("run ends after the commit")
				}
				panic("crash at " + p)
			}
			path := b.dir(2, v2)
			func() {
				defer func() { _ = recover() }()
				b.apply(path)
			}()
			b.env.bundleFault = nil
			// The next lifecycle run (the verify timer or MDM ensure).
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			st := b.state()
			rc := b.receipt(bundleID(2))
			if phase == "committed" {
				if st.Current == nil || st.Current.BundleID != bundleID(2) || rc.State != enterprisebundle.StateConfirmed {
					t.Fatalf("after the commit: state = %+v, receipt = %+v", st, rc)
				}
				return
			}
			if st.Current == nil || st.Current.BundleID != bundleID(1) || rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeInterrupted {
				t.Fatalf("state = %+v, receipt = %+v", st, rc)
			}
			if b.read(b.env.Layout.ConfigPath) != good {
				t.Fatal("config.yaml is not the last good bundle config after recovery")
			}
			requireOK(t, b.apply(path))
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(2) {
				t.Fatalf("retry: state = %+v", st)
			}
		})
	}
}

// A gateway that does not report the new policy (it refuses the reload)
// rolls the transaction back: not_confirmed, the last good config and
// digest enforce.
func TestBundleApplyThatTheGatewayDoesNotConfirmRollsBack(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	good := b.read(b.env.Layout.ConfigPath)
	b.frozen, _ = installedPolicy(b.testHost)
	b.reloadError = "rule pack refused"
	r := b.apply(b.dir(2, v2))
	requireError(t, r, codeBundleNotConfirmed)
	rc := b.receipt(bundleID(2))
	if rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeNotConfirmed || !rc.RolledBack || rc.EnforcingDigest != b.frozen {
		t.Fatalf("receipt = %+v", rc)
	}
	if strings.Contains(rc.ErrorMessage, "rule pack refused") {
		t.Fatalf("the receipt quotes the gateway error: %q", rc.ErrorMessage)
	}
	if st := b.state(); st.Current.BundleID != bundleID(1) || b.read(b.env.Layout.ConfigPath) != good {
		t.Fatalf("state = %+v", st)
	}
	// The restored config is recorded as the last good bundle again, so
	// /health and config.change.applied name the bundle that enforces.
	if gen, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath)); err != nil ||
		gen.BundleID != bundleID(1) || gen.BundleVersion != 1 || !configwrite.IsPrincipalActor(gen.Actor) {
		t.Fatalf("restored generation = %+v (%v), want bundle 1", gen, err)
	}
}

// The first bundle, installed by a run that ended before it recorded it and
// then not confirmed by the gateway, has no last good bundle to return to: it
// keeps enforcing, so later runs keep the version directory its installed
// config names (gc used to remove it with the failed receipt).
func TestBundleUnconfirmedFirstBundleKeepsItsVersionDirectory(t *testing.T) {
	b := newBundleHost(t)
	v1, _, _ := bundleConfigs(b.testHost)
	b.extra = map[string]string{"discovery/confidence.yaml": "version: 1\n"}
	cfg := v1 + "ai_discovery:\n  confidence_policy_path: discovery/confidence.yaml\n"
	b.env.bundleFault = func(p string) error {
		if p == "committed" {
			return errors.New("run ends after the commit")
		}
		return nil
	}
	b.apply(b.dir(1, cfg))
	b.env.bundleFault = nil
	b.frozen = "sha256:" + strings.Repeat("0", 64)
	b.run(Options{Action: ActionEnsure})
	rc := b.receipt(bundleID(1))
	if rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeNotConfirmed {
		t.Fatalf("receipt = %+v", rc)
	}
	b.run(Options{Action: ActionEnsure})
	dir := b.env.bundleVersionDir(rc.Dir)
	if !strings.Contains(b.read(b.env.Layout.ConfigPath), dir) {
		t.Fatalf("config.yaml does not name %s", dir)
	}
	if _, err := os.Stat(b.env.P(filepath.Join(dir, "discovery", "confidence.yaml"))); err != nil {
		t.Fatalf("the version directory the installed config names is gone: %v", err)
	}
}

// In bundle mode a --config other than the current bundle config is refused
// (bundle_required), an in-place edit of config.yaml is reverted to the
// bundle config, and a bundle with a bad signature changes nothing.
func TestBundleModeRefusesUnsignedConfig(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	good := b.read(b.env.Layout.ConfigPath)
	other := filepath.Join(t.TempDir(), "config.yaml")
	writeRooted(t, other, v2)
	requireError(t, b.run(Options{Action: ActionEnsure, ConfigFile: other}), codeBundleRequired)
	if b.read(b.env.Layout.ConfigPath) != good {
		t.Fatal("a refused --config changed config.yaml")
	}
	same := filepath.Join(t.TempDir(), "config.yaml")
	writeRooted(t, same, good)
	requireOK(t, b.run(Options{Action: ActionEnsure, ConfigFile: same}))

	writeRooted(t, b.env.P(b.env.Layout.ConfigPath), v2)
	requireOK(t, b.run(Options{Action: ActionEnsure, Reason: "path"}))
	if b.read(b.env.Layout.ConfigPath) != good {
		t.Fatal("an in-place edit was applied in bundle mode")
	}

	tampered := b.dir(2, v2)
	writeRooted(t, filepath.Join(tampered, enterprisebundle.ConfigName), v1+"\n# edited\n")
	requireError(t, b.apply(tampered), string(enterprisebundle.CodeFileHashMismatch))
	if st := b.state(); st.Current.BundleID != bundleID(1) || b.read(b.env.Layout.ConfigPath) != good {
		t.Fatalf("a tampered bundle changed the host: %+v", st)
	}
}

// The apply trigger applies the highest version in the inbox and removes
// the processed files.
func TestBundleInboxAppliesTheHighestVersion(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	for version, cfg := range map[uint64]string{2: v1 + "\n# two\n", 3: v2} {
		var buf bytes.Buffer
		if err := enterprisebundle.WriteArchive(&buf, b.signed(version, cfg)); err != nil {
			t.Fatal(err)
		}
		writeRooted(t, filepath.Join(b.env.bundleInboxDir(), fmt.Sprintf("v%d.dcbundle", version)), buf.String())
	}
	requireOK(t, b.run(Options{Action: ActionEnsure, Reason: "path"}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(3) {
		t.Fatalf("state = %+v", st)
	}
	if entries, _ := os.ReadDir(b.env.bundleInboxDir()); len(entries) != 0 {
		t.Fatalf("inbox not emptied: %d entries", len(entries))
	}
	r := b.run(Options{Action: ActionEnsure, BundleInbox: true})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "inbox_empty" {
		t.Fatalf("empty inbox: noop = %v %q", r.Noop, r.NoopReason)
	}
}
