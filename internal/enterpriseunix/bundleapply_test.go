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
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	_ "modernc.org/sqlite"
)

type bundleAuditClock struct{}

func (bundleAuditClock) Now() time.Time { return time.Now().UTC() }

type bundleAuditDeadlines struct{}

func (bundleAuditDeadlines) Context(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// Exercise the Unix bundle transaction and the same runtime reporter and
// generation reader that the gateway wires to its audit store. This catches
// a generic reload_applied row even when the separate receipt is correct.
func TestBundleUnixApplyRuntimeAuditCarriesPrincipal(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			testBundleUnixApplyRuntimeAuditCarriesPrincipal(t, goos)
		})
	}
}

func testBundleUnixApplyRuntimeAuditCarriesPrincipal(t *testing.T, goos string) {
	b := newBundleHost(t, goos)
	v1, _, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	path := b.env.P(b.env.Layout.ConfigPath)
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dataDir, "audit.db")
	store, err := audit.NewStore(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	reporter, err := observabilityruntime.NewReloadReporter(store, engine, nil, "bundle-unix-apply", "v8-test")
	if err != nil {
		t.Fatal(err)
	}
	reporter.SetBundleAttribution(func() (observabilityruntime.BundleAttribution, bool) {
		return observabilityruntime.ReadBundleAttribution(path)
	})
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: auditPath, JudgeBodiesPath: filepath.Join(dataDir, "judge.db"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	graph, err := runtimegraph.New(t.Context(), runtimegraph.ConfigFromPlan(plan, true), nil,
		runtimegraph.Options{Reporter: reporter, DrainTimeout: time.Second, Clock: bundleAuditClock{}, Deadlines: bundleAuditDeadlines{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = graph.Close(ctx)
		_ = graph.WaitReporter(ctx)
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := graph.FlushReports(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var actor, projected string
	if err := db.QueryRowContext(ctx, `SELECT actor, projected_record_json FROM audit_events WHERE event_name = 'config.change.applied' ORDER BY rowid DESC LIMIT 1`).Scan(&actor, &projected); err != nil {
		t.Fatal(err)
	}
	if actor != configwrite.CurrentOSActor() {
		t.Errorf("config.change.applied actor = %q, want local OS account %q", actor, configwrite.CurrentOSActor())
	}
	for _, want := range []string{`"defenseclaw.admin.actor_ref":"` + configwrite.CurrentOSActor() + `"`, `"defenseclaw.admin.principal_ref":"operator:mdm-admin"`, bundleID(1), `"defenseclaw.policy.bundle.version":1`, "k1", "version 1"} {
		if !strings.Contains(projected, want) {
			t.Errorf("Unix bundle audit lacks %q: %s", want, projected)
		}
	}
}

// bundleHost is an installed fake host in bundle mode: trust anchors with
// one ed25519 key, a gateway that reports the digest of the installed
// config.yaml (as a generation swap would) unless it is frozen, and a
// bundle digester that hashes the rendered config.
type bundleHost struct {
	*testHost
	key             ed25519.PrivateKey
	installedDigest func([]byte) string
	// frozen makes the gateway keep reporting this digest and reloadError.
	frozen, reloadError, configError string
	// extra are bundle files next to config.yaml in every bundle signed.
	extra map[string]string
}

// bundleRunner answers `policy digest --json` with the digest of the
// installed config.yaml and its recorded generation.
type bundleRunner struct {
	*fakeRunner
	h                 *bundleHost
	policyDigestCalls int
}

func (r *bundleRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if strings.Join(args, " ") == "policy digest --json" {
		r.policyDigestCalls++
		digest, generation := installedPolicy(r.h)
		return CommandResult{Stdout: []byte(fmt.Sprintf(`{"effective_digest":%q,"config_generation":%d}`, digest, generation))}, nil
	}
	return r.fakeRunner.Run(ctx, name, args...)
}

func installedPolicy(h *bundleHost) (string, uint64) {
	raw, _ := os.ReadFile(h.env.P(h.env.Layout.ConfigPath))
	state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	if h.installedDigest != nil {
		return h.installedDigest(raw), state.Generation
	}
	bundlesDir := filepath.Join(h.env.Layout.ConfigDir, enterprisebundle.BundlesDirName)
	for _, name := range enterprisebundle.VersionDirsNamed(raw, bundlesDir) {
		raw = bytes.ReplaceAll(raw, []byte(filepath.Join(bundlesDir, name)), []byte("${bundle_root}"))
	}
	return "sha256:" + sha256Bytes(raw), state.Generation
}

func newBundleHost(t *testing.T, platforms ...string) *bundleHost {
	t.Helper()
	goos := "linux"
	if len(platforms) != 0 {
		goos = platforms[0]
	}
	b := &bundleHost{testHost: newTestHost(t, goos)}
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
	h.env.Runner = &bundleRunner{fakeRunner: h.runner, h: b}
	gatewayName := unitGateway
	if goos == "darwin" {
		gatewayName = labelGateway
	}
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		if !h.healthy || !h.services.isActive(gatewayName) {
			return 0, nil, errors.New("connection refused")
		}
		digest, generation := installedPolicy(b)
		state, _ := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
		if b.frozen != "" {
			digest = b.frozen
		}
		configState := "running"
		if b.configError != "" {
			configState = "error"
		}
		return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"config":{"state":%q,"last_error":%q},"policy":{"effective_digest":%q,"config_generation":%d,"bundle_id":%q,"bundle_version":%d,"last_reload_error":%q},"inspection":{"local":"active","ai_defense":"disabled"}}`,
			configState, b.configError, digest, generation, state.BundleID, state.BundleVersion, b.reloadError)), nil
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
	// Bind each credential to the value the host stores, else to one it
	// does not hold.
	names, err := enterprisebundle.ConfigCredentials([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]byte{}
	for _, name := range names {
		value, err := os.ReadFile(b.env.P(filepath.Join(b.env.Layout.SecretsDir, name)))
		if err != nil {
			value = []byte("unstored-" + name)
		}
		values[name] = value
	}
	_, manifest, err := enterprisebundle.Compose(context.Background(), enterprisebundle.ComposeInput{
		Bundle: files, Root: root, BundleID: fmt.Sprintf("b-01JA%022d", version), TenantID: "acme", DeviceGroup: "eng",
		Platforms: []string{b.env.GOOS}, Version: version, CreatedAt: time.Now().Add(-time.Hour), CreatedBy: "operator:mdm-admin",
		ChangeSummary: fmt.Sprintf("version %d", version), ProductVersion: b.env.ProductVersion, HostPlatform: b.env.GOOS,
		Digester: b.env.BundleDigester, SecretValues: values,
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

// The fake ownership ledger tracks path names rather than inodes. A real
// rename keeps ownership, so map the promoted path to its staging name.
func (b *bundleHost) mapPromotedBundleOwners(version uint64) {
	store := b.env.bundleStore()
	staging := filepath.Join(store.BundlesDir, ".staging-"+bundleID(version))
	promoted := store.VersionDir(enterprisebundle.VersionDirNameForReceipt(version, bundleID(version), bundleID(version)))
	ownerOf := b.env.OwnerOf
	b.env.OwnerOf = func(path string) (int, int, error) {
		if path == promoted || strings.HasPrefix(path, promoted+string(filepath.Separator)) {
			path = strings.Replace(path, promoted, staging, 1)
		}
		return ownerOf(path)
	}
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
	b.mapPromotedBundleOwners(1)
	from := len(b.services.calls)
	r := b.apply(b.dir(1, v1))
	requireOK(t, r)
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(1) || st.Floor != 1 || st.LastGood != nil {
		t.Fatalf("after v1: state = %+v", st)
	}
	rc := b.receipt(bundleID(1))
	digest, generation := installedPolicy(b)
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
	b.mapPromotedBundleOwners(2)
	runner := b.env.Runner.(*bundleRunner)
	digestsBefore := runner.policyDigestCalls
	requireOK(t, b.apply(b.dir(2, v2)))
	if calls := runner.policyDigestCalls - digestsBefore; calls != 0 {
		t.Fatalf("hot signed bundle rebuilt its verified policy %d times", calls)
	}
	if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateConfirmed || rc.Restart || gatewayTouched(b.testHost, from) {
		t.Fatalf("hot bundle: receipt = %+v, gateway touched = %v", rc, gatewayTouched(b.testHost, from))
	}
	if st := b.state(); st.LastGood == nil || st.LastGood.BundleID != bundleID(1) || st.Floor != 2 {
		t.Fatalf("after v2: state = %+v", st)
	}

	from = len(b.services.calls)
	b.mapPromotedBundleOwners(3)
	path := b.dir(3, restart)
	requireOK(t, b.apply(path))
	if rc := b.receipt(bundleID(3)); rc.State != enterprisebundle.StateConfirmed || !rc.Restart || !gatewayTouched(b.testHost, from) {
		t.Fatalf("restart bundle: receipt = %+v, gateway touched = %v", rc, gatewayTouched(b.testHost, from))
	}
	// Version directories other than current and last good are gone.
	if _, err := os.Stat(b.env.P(b.env.bundleVersionDir(enterprisebundle.VersionDirNameForReceipt(1, bundleID(1), bundleID(1))))); !os.IsNotExist(err) {
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

// A repeated delivery inherits an old confirmed receipt. It must not reuse
// that confirmation when the running gateway reports a different policy,
// even if ensure restored the signed config bytes.
func TestBundleRepeatRefusesCachedConfirmationWhenGatewayDigestDiffers(t *testing.T) {
	for _, drift := range []bool{false, true} {
		b := newBundleHost(t)
		_, _, restart := bundleConfigs(b.testHost)
		path := b.dir(1, restart)
		requireOK(t, b.apply(path))
		if drift {
			configPath := b.env.P(b.env.Layout.ConfigPath)
			original, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, append(original, []byte("\n# local drift\n")...), 0o640); err != nil {
				t.Fatal(err)
			}
		}
		b.frozen = "sha256:" + strings.Repeat("0", 64)
		r := b.apply(path)
		if r.OK || r.Bundle != nil && r.Bundle.State == enterprisebundle.StateConfirmed {
			t.Fatalf("drift=%v: repeat reused confirmation while gateway policy differs: %+v", drift, r)
		}
	}
}

// A confirmed receipt records the policy of its original product build.
// After an upgrade, verifying and enforcing the same signed bundle can have
// a new digest. A repeat must use this build's verified digest, including
// when it repairs a restart-required setting on Linux or macOS.
func TestBundleRepeatAfterProductUpgradeUsesVerifiedDigest(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, fromVersion := range []string{"0.8.10", "1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
			t.Run(goos+"/"+fromVersion, func(t *testing.T) {
				b := newBundleHost(t, goos)
				b.env.ProductVersion = fromVersion
				_, _, restart := bundleConfigs(b.testHost)
				path := b.dir(1, restart)
				requireOK(t, b.apply(path))
				first := b.receipt(bundleID(1))
				oldDigest := first.EffectivePolicyDigest
				originalDigester := b.env.BundleDigester
				b.env.ProductVersion = "1.0.4"
				b.env.BundleDigester = func(ctx context.Context, cfg *config.Config, raw []byte, platform, root string) (string, error) {
					value, err := originalDigester(ctx, cfg, raw, platform, root)
					return "sha256:" + sha256Bytes([]byte(value+"/1.0.4")), err
				}
				b.installedDigest = func(raw []byte) string {
					bundlesDir := filepath.Join(b.env.Layout.ConfigDir, enterprisebundle.BundlesDirName)
					for _, name := range enterprisebundle.VersionDirsNamed(raw, bundlesDir) {
						raw = bytes.ReplaceAll(raw, []byte(filepath.Join(bundlesDir, name)), []byte("${bundle_root}"))
					}
					value := "sha256:" + sha256Bytes(raw)
					return "sha256:" + sha256Bytes([]byte(value+"/1.0.4"))
				}
				if err := os.WriteFile(b.env.P(b.env.Layout.ConfigPath), []byte(strings.Replace(restart,
					"hook_self_heal: false", "hook_self_heal: true", 1)), 0o640); err != nil {
					t.Fatal(err)
				}
				repeated := b.apply(path)
				requireOK(t, repeated)
				if repeated.Policy == nil || !repeated.Policy.Applied || repeated.Policy.EffectiveDigest == oldDigest ||
					repeated.Policy.GatewayReportedDigest != repeated.Policy.EffectiveDigest ||
					repeated.Bundle == nil || repeated.Bundle.State != enterprisebundle.StateConfirmed {
					t.Fatalf("repeat policy=%+v bundle=%+v errors=%+v", repeated.Policy, repeated.Bundle, repeated.Errors)
				}
			})
		}
	}
}

// Match the managed restart-drift cell: an authorized package ensure changes
// the config while anchors are absent, then the same signed bundle restores
// its restart setting after a deferred attempt. The repair must be attributed
// to that bundle and its original confirmed receipt remains current.
func TestBundleRepeatAfterAuthorizedRestartDrift(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			_, _, restart := bundleConfigs(b.testHost)
			path := b.dir(1, restart)
			requireOK(t, b.apply(path))
			first := b.receipt(bundleID(1))
			anchorsPath := b.env.bundleAnchorsPath()
			anchors, err := os.ReadFile(anchorsPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(anchorsPath); err != nil {
				t.Fatal(err)
			}
			drift := strings.Replace(restart, "hook_self_heal: false", "hook_self_heal: true", 1)
			if drift == restart {
				t.Fatal("restart setting missing")
			}
			ensure := Options{Action: ActionEnsure, ConfigFile: writeTempConfig(t, []byte(drift))}
			if goos == "linux" {
				stagePackage(t, b.testHost, "1.0.0")
				ensure.FromPackage = true
			}
			requireOK(t, b.run(ensure))
			writeRooted(t, anchorsPath, string(anchors))
			b.env.DeferRestart = true
			deferred := b.apply(path)
			requireError(t, deferred, string(enterprisebundle.CodeRestartDeferred))
			if deferred.ExitCode != enterprisestatus.BusyExitCode(goos) {
				t.Fatalf("deferred exit=%d", deferred.ExitCode)
			}
			b.env.DeferRestart = false
			before, err := b.env.bundleStore().Receipts()
			if err != nil {
				t.Fatal(err)
			}
			repeated := b.apply(path)
			requireOK(t, repeated)
			after, err := b.env.bundleStore().Receipts()
			if err != nil {
				t.Fatal(err)
			}
			generation, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath))
			if err != nil || generation.BundleID != bundleID(1) || generation.BundleVersion != 1 {
				t.Fatalf("repeat generation=%+v error=%v", generation, err)
			}
			if repeated.Bundle == nil || repeated.Bundle.State != enterprisebundle.StateConfirmed ||
				repeated.Bundle.ReceiptID != first.ReceiptID || repeated.Policy == nil || !repeated.Policy.Applied ||
				repeated.Policy.GatewayReportedDigest != repeated.Policy.EffectiveDigest || len(after) != len(before) {
				t.Fatalf("repeat result=%+v receipts %d -> %d", repeated, len(before), len(after))
			}
		})
	}
}

// A plain ensure in bundle mode repairs an in-place edit from the current
// signed bundle. Its generation must retain that bundle's identity; a later
// delivery of the same bundle must use the original confirmed receipt.
func TestBundlePlainEnsureRepairKeepsConfirmedGeneration(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			_, _, restart := bundleConfigs(b.testHost)
			path := b.dir(1, restart)
			requireOK(t, b.apply(path))
			first := b.receipt(bundleID(1))
			configPath := b.env.P(b.env.Layout.ConfigPath)
			drift := strings.Replace(restart, "hook_self_heal: false", "hook_self_heal: true", 1)
			if drift == restart {
				t.Fatal("restart setting missing")
			}
			if err := os.WriteFile(configPath, []byte(drift), 0o640); err != nil {
				t.Fatal(err)
			}
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			generation, err := configwrite.ReadGenerationState(configPath)
			if err != nil || generation.BundleID != bundleID(1) || generation.BundleVersion != 1 ||
				generation.Actor != first.Principal || generation.SignerKeyID != first.SignerKeyID {
				t.Fatalf("plain ensure generation=%+v error=%v", generation, err)
			}
			before, err := b.env.bundleStore().Receipts()
			if err != nil {
				t.Fatal(err)
			}
			repeated := b.apply(path)
			requireOK(t, repeated)
			after, err := b.env.bundleStore().Receipts()
			if err != nil {
				t.Fatal(err)
			}
			if repeated.Bundle == nil || repeated.Bundle.State != enterprisebundle.StateConfirmed ||
				repeated.Bundle.ReceiptID != first.ReceiptID || len(after) != len(before) {
				t.Fatalf("repeat=%+v receipts %d -> %d", repeated, len(before), len(after))
			}
		})
	}
}

// An older lifecycle could leave equal config bytes under an unattributed
// generation. Reapplying the current signed bundle must bind that generation
// without requiring a byte change, including after an upgrade.
func TestBundleRepeatRebindsUnattributedEqualBytes(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, fromVersion := range []string{"0.8.10", "1.0.0", "1.0.1", "1.0.2", "1.0.3"} {
			t.Run(goos+"/"+fromVersion, func(t *testing.T) {
				b := newBundleHost(t, goos)
				b.env.ProductVersion = fromVersion
				v1, _, _ := bundleConfigs(b.testHost)
				path := b.dir(1, v1)
				requireOK(t, b.apply(path))
				b.env.ProductVersion = "1.0.4"
				first := b.receipt(bundleID(1))
				configPath := b.env.P(b.env.Layout.ConfigPath)
				_, err := configwrite.Locked(t.Context(), configPath, configwrite.Options{Actor: configwrite.ActorLifecycle, Reason: "pre-upgrade ensure"},
					func() (bool, error) { return true, nil })
				if err != nil {
					t.Fatal(err)
				}
				before, err := configwrite.ReadGenerationState(configPath)
				if err != nil || before.BundleID != "" {
					t.Fatalf("unattributed setup=%+v error=%v", before, err)
				}
				repeated := b.apply(path)
				requireOK(t, repeated)
				generation, err := configwrite.ReadGenerationState(configPath)
				if err != nil || generation.Generation <= before.Generation || generation.BundleID != bundleID(1) ||
					generation.BundleVersion != 1 || generation.Actor != first.Principal || generation.SignerKeyID != first.SignerKeyID {
					t.Fatalf("rebound generation=%+v previous=%+v error=%v", generation, before, err)
				}
				if repeated.Bundle == nil || repeated.Bundle.State != enterprisebundle.StateConfirmed ||
					repeated.Bundle.ReceiptID != first.ReceiptID {
					t.Fatalf("repeat=%+v", repeated)
				}
			})
		}
	}
}

func TestUnixBundleRefusesDeviceKeyMoveBeforeChangingConfirmedPolicy(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, _, _ := bundleConfigs(b.testHost)
			b.mapPromotedBundleOwners(1)
			requireOK(t, b.apply(b.dir(1, v1)))
			// The relative spelling resolves to the existing default key.
			v2 := strings.Replace(v1, "gateway:\n", "gateway:\n  device_key_file: device.key\n", 1)
			b.mapPromotedBundleOwners(2)
			requireOK(t, b.apply(b.dir(2, v2)))
			if got := b.state().Current; got == nil || got.BundleID != bundleID(2) {
				t.Fatalf("same-path bundle was not confirmed: %+v", got)
			}
			before := b.read(b.env.Layout.ConfigPath)
			digest, _ := installedPolicy(b)
			from := len(b.services.calls)
			v3 := strings.Replace(v2, "device_key_file: device.key", "device_key_file: moved.key", 1)
			r := b.apply(b.dir(3, v3))
			requireError(t, r, string(enterprisebundle.CodeInvalidArguments))
			if got := b.receipt(bundleID(3)); got.State != enterprisebundle.StateFailed || got.ErrorCode != enterprisebundle.CodeInvalidArguments {
				t.Fatalf("key-move receipt = %+v", got)
			}
			if got := b.state().Current; got == nil || got.BundleID != bundleID(2) {
				t.Fatalf("key move replaced the confirmed bundle: %+v", got)
			}
			if got, now := b.read(b.env.Layout.ConfigPath), len(b.services.calls); got != before || gatewayTouched(b.testHost, from) || now != from {
				t.Fatalf("key move changed the config or services: config=%t, calls=%v", got != before, b.services.calls[from:])
			}
			if got, _ := installedPolicy(b); got != digest {
				t.Fatalf("key move changed the enforcing digest: %s, want %s", got, digest)
			}
		})
	}
}

// The bundle block of an apply names the receipt it reports (receipt_id). A
// fresh apply names the receipt it wrote, which is also the name of its
// public receipt; a repeat of the current bundle writes no receipt and names
// the current confirmed one (noop_reason is already_applied only when ensure
// had nothing else to do); a bundle refused after its
// receipt was written leaves the block on the confirmed receipt and names
// its own receipt in last_refusal; a refusal before any receipt was written
// reports no block.
func TestBundleApplyResultNamesTheReceipt(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	b.mapPromotedBundleOwners(1)
	path := b.dir(1, v1)
	r := b.apply(path)
	requireOK(t, r)
	rc := b.receipt(bundleID(1))
	if r.Bundle == nil || r.Bundle.ReceiptID == "" || r.Bundle.ReceiptID != rc.ReceiptID {
		t.Fatalf("fresh apply: bundle block = %+v, receipt %s", r.Bundle, rc.ReceiptID)
	}
	public := filepath.Join(b.env.bundleStore().PublicReceiptEventsDir(), r.Bundle.ReceiptID+".json")
	if _, err := os.Stat(public); err != nil {
		t.Fatalf("no public receipt named by receipt_id: %v", err)
	}

	receipts, _ := b.env.bundleStore().Receipts()
	r = b.apply(path)
	requireOK(t, r)
	after, _ := b.env.bundleStore().Receipts()
	if len(after) != len(receipts) || r.Bundle == nil || r.Bundle.ReceiptID != rc.ReceiptID {
		t.Fatalf("repeated delivery: receipts %d -> %d, bundle block = %+v", len(receipts), len(after), r.Bundle)
	}

	r = b.apply(b.dir(1, v2))
	if r.OK || !hasMessageCode(r.Errors, string(enterprisebundle.CodeVersionNotNewer)) {
		t.Fatalf("same version, other bytes: ok %v, errors %+v", r.OK, r.Errors)
	}
	if r.Bundle == nil || r.Bundle.ReceiptID != rc.ReceiptID || r.LastRefusal == nil ||
		r.LastRefusal.ReceiptID == "" || r.LastRefusal.ReceiptID == rc.ReceiptID {
		t.Fatalf("refusal after the receipt: bundle block = %+v, last refusal = %+v", r.Bundle, r.LastRefusal)
	}

	fresh := newTestHost(t, "linux")
	r = fresh.run(Options{Action: ActionEnsure, Bundle: path})
	if r.OK || !hasMessageCode(r.Errors, codeNotInstalled) || r.Bundle != nil {
		t.Fatalf("refusal before the receipt: ok %v, errors %+v, bundle block = %+v", r.OK, r.Errors, r.Bundle)
	}
}

// failAfterStaging delivers version v and fails it after its receipt reached
// staging, so it is the latest receipt the store summary reports.
func (b *bundleHost) failAfterStaging(version uint64, cfg string) {
	b.t.Helper()
	b.env.bundleFault = func(phase string) error {
		if phase == enterprisebundle.StateStaged {
			return errors.New("injected failure after staging")
		}
		return nil
	}
	defer func() { b.env.bundleFault = nil }()
	if r := b.apply(b.dir(version, cfg)); r.OK || r.Bundle == nil || r.Bundle.BundleID != bundleID(version) || r.Bundle.State != enterprisebundle.StateFailed {
		b.t.Fatalf("delivery of v%d did not fail after staging: ok %v, bundle block = %+v", version, r.OK, r.Bundle)
	}
}

// A repeat of the current bundle after a newer delivery failed after
// staging reports the current confirmed bundle and its receipt, not the
// failed delivery that is the latest receipt: the receipt_id it returns is
// the one the device enforces.
func TestBundleApplyRepeatAfterANewerFailureNamesTheConfirmedReceipt(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	b.mapPromotedBundleOwners(1)
	path := b.dir(1, v1)
	requireOK(t, b.apply(path))
	confirmed := b.receipt(bundleID(1))
	b.failAfterStaging(2, v2)

	r := b.apply(path)
	requireOK(t, r)
	if r.Bundle == nil || r.Bundle.ReceiptID != confirmed.ReceiptID || r.Bundle.BundleID != bundleID(1) ||
		r.Bundle.State != enterprisebundle.StateConfirmed || r.Bundle.CurrentBundleID != "" || r.Bundle.ConfirmedAt == "" {
		t.Fatalf("repeat after a newer failure: bundle block = %+v, want the confirmed receipt %s", r.Bundle, confirmed.ReceiptID)
	}
	// The first repeat converged what the failed delivery left; the next
	// is the already_applied no-op and reports the same block.
	r = b.apply(path)
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "already_applied" || r.Bundle == nil || r.Bundle.ReceiptID != confirmed.ReceiptID ||
		r.Bundle.BundleID != bundleID(1) || r.Bundle.State != enterprisebundle.StateConfirmed {
		t.Fatalf("no-op repeat: noop %v, reason %q, bundle block = %+v", r.Noop, r.NoopReason, r.Bundle)
	}
}

// A repeat of the current bundle that also repairs drift (here a new
// credential to apply) has no noop_reason, and still passes the contract's
// success test: exit 0, ok, bundle.bundle_id the submitted bundle and
// bundle.state confirmed, also after a newer delivery failed after staging.
func TestBundleApplyRepeatThatRepairsDriftPassesTheSuccessTest(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	b.mapPromotedBundleOwners(1)
	path := b.dir(1, v1)
	requireOK(t, b.apply(path))
	confirmed := b.receipt(bundleID(1))
	b.failAfterStaging(2, v2)
	if err := b.env.WriteSecret(context.Background(), "ai-defense-api-key", []byte("drift-value")); err != nil {
		t.Fatal(err)
	}

	r := b.apply(path)
	requireOK(t, r)
	if r.Noop || r.NoopReason != "" {
		t.Fatalf("repeat with drift: noop %v, reason %q; want the drift repaired", r.Noop, r.NoopReason)
	}
	if r.ExitCode != 0 || r.Bundle == nil || r.Bundle.BundleID != bundleID(1) || r.Bundle.State != enterprisebundle.StateConfirmed ||
		r.Bundle.ReceiptID != confirmed.ReceiptID {
		t.Fatalf("repeat with drift: exit %d, bundle block = %+v; want confirmed %s", r.ExitCode, r.Bundle, bundleID(1))
	}
}

func TestBundlePolicyAssetChangeKeepsGatewayRunning(t *testing.T) {
	b := newBundleHost(t)
	stagePackage(t, b.testHost, "1.0.0")
	requireOK(t, b.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package"}))
	const pack = "policies/guardrail/custom/rules/local-patterns.yaml"
	b.extra = map[string]string{pack: "version: 1\ninjection: []\n"}
	configForPack := func() string {
		root := t.TempDir()
		writeRooted(t, filepath.Join(root, "rules/local-patterns.yaml"), b.extra[pack])
		digest, err := guardrail.RulePackDigest(root)
		if err != nil {
			t.Fatal(err)
		}
		cfg := strings.Replace(string(DefaultConfig(b.env.Layout)), "policy_dir: "+b.env.Layout.VendorPolicyDir, "policy_dir: policies", 1)
		return strings.Replace(cfg, "  rule_pack: default\n",
			"  rule_pack: custom\n  custom_packs:\n    custom:\n      path: policies/guardrail/custom\n      digest: sha256:"+digest+"\n", 1)
	}
	v1 := configForPack()
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, v1)))
	b.extra[pack] = "version: 1\ninjection: []\n# revised\n"
	v2 := strings.Replace(configForPack(), "mode: observe", "mode: action", 1)
	v2 = strings.Replace(v2, "  rule_pack: custom\n", "  block_at: HIGH\n  rule_pack: custom\n", 1)
	b.mapPromotedBundleOwners(2)
	from := len(b.services.calls)
	requireOK(t, b.apply(b.dir(2, v2)))
	if rc := b.receipt(bundleID(2)); rc.Restart || gatewayTouched(b.testHost, from) {
		t.Fatalf("policy asset bundle restarted gateway: receipt=%+v calls=%v", rc, b.services.calls[from:])
	}
}

// A signer stages config.yaml under a temporary path, while the gateway
// loads it from the fixed managed path. Both must resolve implicit rule-pack
// defaults the same way when v2 replaces a confirmed v1 bundle.
func TestBundleApplyReplacementMatchesSignedManagedPathDefaults(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			const pack = "policies/guardrail/replacement/rules/local-patterns.yaml"
			b.extra = map[string]string{pack: "version: 1\ninjection: []\n"}
			packRoot := t.TempDir()
			writeRooted(t, filepath.Join(packRoot, "rules/local-patterns.yaml"), b.extra[pack])
			pin, err := guardrail.RulePackDigest(packRoot)
			if err != nil {
				t.Fatal(err)
			}
			missingPolicyDir := filepath.Join(t.TempDir(), "absent-policies")
			v1 := strings.Replace(string(DefaultConfig(b.env.Layout)), "policy_dir: "+b.env.Layout.VendorPolicyDir,
				"policy_dir: "+missingPolicyDir, 1)
			v1 = strings.Replace(v1, "  rule_pack: default\n",
				"  block_at: HIGH\n  rule_pack: replacement\n  custom_packs:\n    replacement:\n      path: policies/guardrail/replacement\n      digest: sha256:"+pin+"\n", 1)
			v2 := strings.Replace(v1, "mode: observe", "mode: action", 1)
			v2 = strings.Replace(v2, "block_at: HIGH", "block_at: MEDIUM", 1)
			if v2 == v1 {
				t.Fatal("v2 did not change the policy")
			}
			canonical := func(raw []byte, root string) []byte {
				return bytes.ReplaceAll(raw, []byte(root), []byte("${bundle_root}"))
			}
			digestOf := func(cfg *config.Config, raw []byte) string {
				return "sha256:" + sha256Bytes(append(raw, []byte("\n"+cfg.Guardrail.RulePackDir)...))
			}
			b.env.BundleDigester = func(_ context.Context, cfg *config.Config, raw []byte, _, root string) (string, error) {
				return digestOf(cfg, canonical(raw, root)), nil
			}
			b.installedDigest = func(raw []byte) string {
				cfg, err := config.LoadRuntimeV8InspectionCandidateFromBytes(b.env.Layout.ConfigPath, raw)
				if err != nil {
					t.Fatal(err)
				}
				bundlesDir := filepath.Join(b.env.Layout.ConfigDir, enterprisebundle.BundlesDirName)
				for _, name := range enterprisebundle.VersionDirsNamed(raw, bundlesDir) {
					raw = canonical(raw, filepath.Join(bundlesDir, name))
				}
				return digestOf(cfg, raw)
			}
			b.mapPromotedBundleOwners(1)
			first := b.dir(1, v1)
			b.env.ProductVersion = "1.0.1" // The first signature predates the installed build.
			requireOK(t, b.apply(first))
			if rc := b.receipt(bundleID(1)); rc.State != enterprisebundle.StateConfirmed {
				t.Fatalf("v1 receipt: %+v", rc)
			}
			b.mapPromotedBundleOwners(2)
			requireOK(t, b.apply(b.dir(2, v2)))
			if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateConfirmed || rc.ExpectedDigest != rc.EffectivePolicyDigest {
				t.Fatalf("v2 receipt: %+v", rc)
			}
		})
	}
}

func TestBundleApplyReportsAndCanRefuseCapabilityLoss(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, _, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			configPath := b.env.P(b.env.Layout.ConfigPath)
			before, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			off := strings.Replace(v1, "enabled: true\n  mode: observe", "enabled: false\n  mode: observe", 1)
			if off == v1 {
				t.Fatal("test config did not disable guardrail")
			}
			b.env.RefuseCapabilityLoss = true
			refused := b.run(Options{Action: ActionEnsure, Bundle: b.dir(2, off)})
			b.env.RefuseCapabilityLoss = false
			if !hasMessageCode(refused.Errors, string(enterprisebundle.CodeCapabilityLoss)) ||
				!hasMessageCode(refused.Warnings, "capability_disabled") {
				t.Fatalf("strict result = %+v", refused)
			}
			after, err := os.ReadFile(configPath)
			if err != nil || !bytes.Equal(before, after) || b.state().Current.BundleID != bundleID(1) {
				t.Fatalf("strict changed config or current bundle: %v", err)
			}
			if _, err := os.Stat(b.env.P(b.env.bundleVersionDir(enterprisebundle.VersionDirNameForReceipt(2, bundleID(2), bundleID(2))))); !os.IsNotExist(err) {
				t.Fatalf("strict promoted a version: %v", err)
			}
			permissive := b.apply(b.dir(3, off))
			requireOK(t, permissive)
			if permissive.Bundle == nil || !slices.Contains(permissive.Bundle.DisabledByBundle, "guardrail") ||
				!slices.Contains(b.receipt(bundleID(3)).WarningCodes, "capability_disabled") {
				t.Fatalf("permissive result = %+v", permissive.Bundle)
			}
		})
	}
}

func TestBundleShippedRulePackIsReadableByGateway(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			testBundleShippedRulePackIsReadableByGateway(t, goos)
		})
	}
}

func testBundleShippedRulePackIsReadableByGateway(t *testing.T, goos string) {
	b := newBundleHost(t, goos)
	const pack = "policies/guardrail/mgmtp1marker"
	b.extra = map[string]string{pack + "/rules/local-patterns.yaml": "version: 1\ninjection: []\n"}
	marker := t.TempDir()
	writeRooted(t, filepath.Join(marker, "rules/local-patterns.yaml"), b.extra[pack+"/rules/local-patterns.yaml"])
	digest, err := guardrail.RulePackDigest(marker)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(DefaultConfig(b.env.Layout)), "  rule_pack: default\n",
		"  rule_pack: mgmtp1marker\n  custom_packs:\n    mgmtp1marker:\n      path: "+pack+"\n      digest: sha256:"+digest+"\n", 1)
	store := b.env.bundleStore()
	// An existing host can have the original root-only bundle parent.
	if err := os.MkdirAll(store.BundlesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.BundlesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b.owners[store.BundlesDir] = [2]int{0, 0}
	version := store.VersionDir(enterprisebundle.VersionDirNameForReceipt(1, bundleID(1), bundleID(1)))
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, cfg)))
	rc := b.receipt(bundleID(1))
	if rc.State != enterprisebundle.StateConfirmed {
		t.Fatalf("bundle receipt: %+v", rc)
	}
	if goos == "darwin" && !b.services.isActive(labelApply) {
		t.Fatal("launchd apply job was unloaded after bundle confirmation")
	}
	installed, err := os.ReadFile(b.env.P(b.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	packOnDisk := filepath.Join(version, filepath.FromSlash(pack))
	configuredPack := filepath.Join(b.env.bundleVersionDir(rc.Dir), filepath.FromSlash(pack))
	if !strings.Contains(string(installed), configuredPack) {
		t.Fatalf("installed config does not name the promoted pack %s:\n%s", configuredPack, installed)
	}
	account := b.accounts.accounts[b.env.Layout.ServiceUser]
	if err := b.env.rulePackReadable(filepath.Join(b.env.bundleVersionDir(rc.Dir), filepath.FromSlash(pack)), account); err != nil {
		t.Fatalf("service account cannot read the promoted rule pack: %v", err)
	}
	if _, err := guardrail.LoadRulePack(packOnDisk); err != nil {
		t.Fatalf("gateway rule-pack loader cannot load the promoted pack: %v", err)
	}
	for _, path := range []string{store.BundlesDir, version, packOnDisk, filepath.Join(packOnDisk, "rules"), filepath.Join(packOnDisk, "rules/local-patterns.yaml")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o750)
		wantGID := account.GID
		if path == store.BundlesDir {
			want, wantGID = 0o755, 0
		}
		if !info.IsDir() {
			want = 0o640
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s mode %04o, want %04o", path, info.Mode().Perm(), want)
		}
		uid, gid, err := b.env.OwnerOf(path)
		if err != nil || uid != 0 || gid != wantGID {
			t.Errorf("%s owner %d:%d, want root:%d (%v)", path, uid, gid, wantGID, err)
		}
	}
}

// A confirmed bundle must leave its policy inputs traversable by the macOS
// gateway service account. This is the permission check behind the /health
// config reload state after an MDM bundle apply.
func TestDarwinConfirmedBundleHealthInputsAreReadable(t *testing.T) {
	b := newBundleHost(t, "darwin")
	const pack = "policies/guardrail/health"
	b.extra = map[string]string{pack + "/rules/local-patterns.yaml": "version: 1\ninjection: []\n"}
	packRoot := t.TempDir()
	writeRooted(t, filepath.Join(packRoot, "rules/local-patterns.yaml"), b.extra[pack+"/rules/local-patterns.yaml"])
	digest, err := guardrail.RulePackDigest(packRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(DefaultConfig(b.env.Layout)), "  rule_pack: default\n",
		"  rule_pack: health\n  custom_packs:\n    health:\n      path: "+pack+"\n      digest: sha256:"+digest+"\n", 1)
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, cfg)))
	rc := b.receipt(bundleID(1))
	account := b.accounts.accounts[b.env.Layout.ServiceUser]
	if problem := b.env.RulePackServiceReadProblem(context.Background(), filepath.Join(b.env.bundleVersionDir(rc.Dir), pack)); problem != "" {
		t.Fatalf("confirmed bundle leaves an unreadable health input: %s", problem)
	}
	if account.GID == 0 || rc.State != enterprisebundle.StateConfirmed {
		t.Fatalf("service account or receipt is not ready: account=%+v receipt=%+v", account, rc)
	}
	status, raw, err := b.env.HealthGet(context.Background())
	if err != nil || status != 200 || !bytes.Contains(raw, []byte(rc.EffectivePolicyDigest)) ||
		!bytes.Contains(raw, []byte(`"last_reload_error":""`)) {
		t.Fatalf("bundle health = %d %s (%v)", status, raw, err)
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

func TestDarwinFailedBundleRestoresConfigOwnerAndMode(t *testing.T) {
	b := newBundleHost(t, "darwin")
	v1, v2, _ := bundleConfigs(b.testHost)
	b.extra = map[string]string{"policies/guardrail/custom/rules/marker.yaml": "version: 1\n"}
	b.mapPromotedBundleOwners(1)
	requireOK(t, b.apply(b.dir(1, v1)))
	path := b.env.P(b.env.Layout.ConfigPath)
	record, err := b.env.loadDeployment()
	if err != nil {
		t.Fatal(err)
	}
	check := func(path string, mode os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		uid, gid, err := b.env.OwnerOf(path)
		if err != nil || info.Mode().Perm() != mode || uid != 0 || gid != record.ServiceGID {
			t.Fatalf("%s mode/owner = %04o %d:%d, want %04o 0:%d (%v)", path, info.Mode().Perm(), uid, gid, mode, record.ServiceGID, err)
		}
	}
	pack := b.env.P(filepath.Join(b.env.bundleVersionDir(b.state().Current.Dir), "policies/guardrail/custom/rules/marker.yaml"))
	packDir := filepath.Dir(pack)
	check(path, 0o640)
	check(b.env.P(configwrite.GenerationPath(b.env.Layout.ConfigPath)), 0o640)
	check(packDir, 0o750)
	check(pack, 0o640)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, _, err := statOwnerMode(path)
	if err != nil {
		t.Fatal(err)
	}
	b.env.bundleFault = func(phase string) error {
		if phase == "transaction" {
			return errors.New("failed after the staged config was installed")
		}
		return nil
	}
	b.mapPromotedBundleOwners(2)
	requireError(t, b.apply(b.dir(2, v2)), codeBundleNotConfirmed)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	gotUID, gotGID, _, err := statOwnerMode(path)
	if err != nil || gotUID != uid || gotGID != gid || after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("rolled-back config mode/owner = %04o %d:%d, want %04o %d:%d (%v)",
			after.Mode().Perm(), gotUID, gotGID, before.Mode().Perm(), uid, gid, err)
	}
	// The fake chown ledger cannot model snapshot inode ownership: snapshot
	// reads the real host uid/gid. The equality above checks restored owner.
	check(packDir, 0o750)
	check(pack, 0o640)
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.BundleID != bundleID(1) || state.TransactionBundleID != bundleID(2) ||
		state.TransactionActor != "operator:mdm-admin" || state.TransactionBundleVersion != 2 {
		t.Fatalf("rollback generation lost enforcing or attempted bundle: %+v (%v)", state, err)
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
			// Before that run, status (read-only) reports the receipt no run
			// owns as a pending transaction the management agent settles
			// with ensure; it read transaction_pending false (GAP-0028).
			before := b.receipt(bundleID(2))
			status := b.run(Options{Action: ActionStatus})
			if !status.TransactionPending || !hasWarning(status, enterprisebundle.WarnBundlePending) {
				t.Fatalf("status after a crash at %s: transaction_pending=%v warnings=%+v", phase, status.TransactionPending, status.Warnings)
			}
			if after := b.receipt(bundleID(2)); after.State != before.State || len(after.Transitions) != len(before.Transitions) {
				t.Fatalf("status changed the receipt: %+v -> %+v", before, after)
			}
			// The next lifecycle run (the verify timer or MDM ensure).
			requireOK(t, b.run(Options{Action: ActionEnsure}))
			if status := b.run(Options{Action: ActionStatus}); status.TransactionPending || hasWarning(status, enterprisebundle.WarnBundlePending) {
				t.Fatalf("status after ensure settled a crash at %s: transaction_pending=%v warnings=%+v", phase, status.TransactionPending, status.Warnings)
			}
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

// The applied fault is the point where SIGKILL leaves an activated config
// and generation on disk, but no confirmed receipt. Two bundles with the
// same config and pack content still have different rendered version paths.
func TestBundleApplyCrashAfterAppliedRestoresConfirmedPolicy(t *testing.T) {
	b := newBundleHost(t)
	const pack = "policies/guardrail/custom/rules/local-patterns.yaml"
	b.extra = map[string]string{pack: "version: 1\ninjection: []\n"}
	packRoot := t.TempDir()
	writeRooted(t, filepath.Join(packRoot, "rules/local-patterns.yaml"), b.extra[pack])
	pin, err := guardrail.RulePackDigest(packRoot)
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(string(DefaultConfig(b.env.Layout)), "policy_dir: "+b.env.Layout.VendorPolicyDir, "policy_dir: policies", 1)
	cfg = strings.Replace(cfg, "  rule_pack: default\n",
		"  rule_pack: custom\n  custom_packs:\n    custom:\n      path: policies/guardrail/custom\n      digest: sha256:"+pin+"\n", 1)
	b.mapPromotedBundleOwners(11)
	requireOK(t, b.apply(b.dir(11, cfg)))
	confirmed := b.receipt(bundleID(11))
	goodConfig := b.read(b.env.Layout.ConfigPath)
	goodPack := b.env.P(filepath.Join(b.env.bundleVersionDir(b.state().Current.Dir), pack))
	goodPackSHA, err := sha256File(goodPack)
	if err != nil {
		t.Fatal(err)
	}
	before, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	b.mapPromotedBundleOwners(12)
	path := b.dir(12, cfg)
	b.env.bundleFault = func(phase string) error {
		if phase == enterprisebundle.StateApplied {
			panic("killed after applied receipt")
		}
		return nil
	}
	func() {
		defer func() { _ = recover() }()
		b.apply(path)
	}()
	b.env.bundleFault = nil
	if rc := b.receipt(bundleID(12)); rc.State != enterprisebundle.StateApplied {
		t.Fatalf("crash did not reach applied receipt: %+v", rc)
	}
	if got := b.read(b.env.Layout.ConfigPath); got == goodConfig {
		t.Fatal("the unconfirmed bundle did not activate a distinct config path")
	}
	requireOK(t, b.run(Options{Action: ActionEnsure}))
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(11) || st.Current.Version != 11 {
		t.Fatalf("current after recovery = %+v", st.Current)
	}
	if failed := b.receipt(bundleID(12)); failed.State != enterprisebundle.StateFailed || failed.ErrorCode != enterprisebundle.CodeInterrupted {
		t.Fatalf("unconfirmed receipt after recovery = %+v", failed)
	}
	if got := b.read(b.env.Layout.ConfigPath); got != goodConfig {
		t.Fatal("recovery did not restore the confirmed config bytes")
	}
	if got, err := sha256File(goodPack); err != nil || got != goodPackSHA {
		t.Fatalf("confirmed pack hash after recovery = %s, %v; want %s", got, err, goodPackSHA)
	}
	state, err := configwrite.ReadGenerationState(b.env.P(b.env.Layout.ConfigPath))
	if err != nil || state.Generation <= before.Generation || state.ConfigSHA256 != sha256Bytes([]byte(goodConfig)) ||
		state.BundleID != bundleID(11) || state.BundleVersion != 11 {
		t.Fatalf("recovered generation = %+v, %v", state, err)
	}
	digest, generation := installedPolicy(b)
	if digest != confirmed.ExpectedDigest || generation != state.Generation {
		t.Fatalf("running policy = %s generation %d, want %s generation %d", digest, generation, confirmed.ExpectedDigest, state.Generation)
	}
	statusCode, healthRaw, err := b.env.HealthGet(context.Background())
	health := parseBundleHealth(healthRaw)
	if err != nil || statusCode != 200 || health.digest != confirmed.ExpectedDigest ||
		health.bundleID != bundleID(11) || health.bundleVersion != 11 {
		t.Fatalf("gateway health after recovery = %d %+v, %v", statusCode, health, err)
	}
	if status := b.run(Options{Action: ActionStatus}); !status.OK || status.Bundle == nil || status.Bundle.CurrentBundleID != bundleID(11) {
		t.Fatalf("status after recovery = %+v", status)
	}
	writeFreshLedger(t, b.testHost)
	if verify := b.run(Options{Action: ActionVerify}); !verify.OK {
		t.Fatalf("verify after recovery = %+v", verify.Errors)
	}
}

func TestBundleRecoveryKeepsPendingWhenGatewayRetainsUnconfirmedPolicy(t *testing.T) {
	b := newBundleHost(t)
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	path := b.dir(2, v2)
	b.env.bundleFault = func(phase string) error {
		if phase == enterprisebundle.StateApplied {
			panic("killed after applied receipt")
		}
		return nil
	}
	func() {
		defer func() { _ = recover() }()
		b.apply(path)
	}()
	b.env.bundleFault = nil
	b.frozen, _ = installedPolicy(b)
	recovery := b.run(Options{Action: ActionEnsure})
	requireError(t, recovery, codeRollbackFailed)
	if pending, err := b.env.loadPending(); err != nil || pending == nil {
		t.Fatalf("failed rollback lost its retryable transaction: %+v, %v", pending, err)
	}
	if verify := b.run(Options{Action: ActionVerify}); verify.OK {
		t.Fatal("verify accepted a gateway enforcing the unconfirmed policy")
	}
	b.frozen = ""
	requireOK(t, b.run(Options{Action: ActionEnsure}))
	if pending, err := b.env.loadPending(); err != nil || pending != nil {
		t.Fatalf("successful retry left the transaction pending: %+v, %v", pending, err)
	}
}

func TestBundleRetryDigestMarkerComesFromThisDelivery(t *testing.T) {
	for _, signerMatches := range []bool{true, false} {
		for _, phase := range []string{enterprisebundle.StateVerified, enterprisebundle.StateStaged, enterprisebundle.StateApplied} {
			name := fmt.Sprintf("match=%t/%s", signerMatches, phase)
			t.Run(name, func(t *testing.T) {
				b := newBundleHost(t)
				v1, v2, _ := bundleConfigs(b.testHost)
				requireOK(t, b.apply(b.dir(1, v1)))
				path := b.dir(2, v2)
				if !signerMatches {
					b.env.ProductVersion = "1.0.1"
				}
				b.env.bundleFault = func(at string) error {
					if at == phase {
						panic("crash at " + at)
					}
					return nil
				}
				func() {
					defer func() { _ = recover() }()
					b.apply(path)
				}()
				b.env.bundleFault = nil
				requireOK(t, b.run(Options{Action: ActionEnsure}))
				failed := b.receipt(bundleID(2))
				if failed.State != enterprisebundle.StateFailed || failed.ErrorCode != enterprisebundle.CodeInterrupted {
					t.Fatalf("interrupted receipt = %+v", failed)
				}
				requireOK(t, b.apply(path))
				confirmed := b.receipt(bundleID(2))
				if confirmed.ReceiptID == failed.ReceiptID || confirmed.State != enterprisebundle.StateConfirmed ||
					confirmed.ExpectedDigest != confirmed.EffectivePolicyDigest ||
					confirmed.DigestComparable != signerMatches ||
					slices.Contains(confirmed.WarningCodes, enterprisebundle.WarnDigestUnverifiable) == signerMatches {
					t.Fatalf("retried receipt = %+v, failed receipt = %+v", confirmed, failed)
				}
				public, err := enterprisestatus.ReadPublicReceipt(b.env.bundleStore().PublicReceiptPath())
				if err != nil || slices.Contains(public.WarningCodes, enterprisebundle.WarnDigestUnverifiable) == signerMatches {
					t.Fatalf("public receipt = %+v, %v", public, err)
				}
				status := b.run(Options{Action: ActionStatus})
				if status.Bundle == nil || slices.Contains(status.Bundle.WarningCodes, enterprisebundle.WarnDigestUnverifiable) == signerMatches {
					t.Fatalf("status bundle = %+v", status.Bundle)
				}
				found := slices.ContainsFunc(status.Warnings, func(w enterprisestatus.Message) bool {
					return w.Code == enterprisebundle.WarnDigestUnverifiable
				})
				if found == signerMatches {
					t.Fatalf("status warnings = %+v", status.Warnings)
				}
			})
		}
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
	b.frozen, _ = installedPolicy(b)
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

// GAP-0032: a gateway killed after the transaction's confirm (the receipt
// is applied) and absent until the receipt would be confirmed returned
// confirmed with policy.applied false. Confirmed means the running gateway
// enforces the digest, so the apply fails not_confirmed with the retry exit
// code and the receipt stays applied; the resubmit of the same bundle, once
// the gateway runs again, confirms it and passes the success test. A gateway
// that its service manager starts again within the confirm wait confirms
// the bundle in the same run, and the policy block says it is applied.
func TestBundleApplyGatewayKilledBeforeConfirmIsNotConfirmed(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			killAfterApplied := func(phase string) error {
				if phase == enterprisebundle.StateApplied {
					b.healthy = false
				}
				return nil
			}
			b.env.bundleFault = killAfterApplied
			path := b.dir(2, v2)
			r := b.apply(path)
			b.env.bundleFault = nil
			requireError(t, r, codeBundleNotConfirmed)
			if r.OK || r.ExitCode != enterprisestatus.UnixExitBusy {
				t.Fatalf("apply ok=%t exit=%d, want the retry exit %d", r.OK, r.ExitCode, enterprisestatus.UnixExitBusy)
			}
			if r.Bundle == nil || r.Bundle.BundleID != bundleID(2) || r.Bundle.State == enterprisestatus.BundleConfirmed {
				t.Fatalf("bundle block = %+v, want bundle 2 not confirmed", r.Bundle)
			}
			if r.Policy != nil && r.Policy.Applied {
				t.Fatalf("policy block says applied while the gateway is down: %+v", r.Policy)
			}
			if rc := b.receipt(bundleID(2)); rc.State != enterprisebundle.StateApplied {
				t.Fatalf("receipt = %+v, want applied for the next run to settle", rc)
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(1) {
				t.Fatalf("current = %+v, want the last good bundle", st.Current)
			}

			// The gateway runs again; the agent resubmits the same bundle.
			b.healthy = true
			again := b.apply(path)
			requireOK(t, again)
			if again.ExitCode != 0 || again.Bundle == nil || again.Bundle.BundleID != bundleID(2) ||
				again.Bundle.State != enterprisestatus.BundleConfirmed || !hasWarning(again, codeBundleConfirmedLate) {
				t.Fatalf("resubmit exit=%d bundle=%+v warnings=%+v", again.ExitCode, again.Bundle, again.Warnings)
			}
			if again.Policy == nil || !again.Policy.Applied {
				t.Fatalf("resubmit policy = %+v", again.Policy)
			}
			if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(2) {
				t.Fatalf("current after resubmit = %+v", st.Current)
			}

			// Killed after applied, started again by the service manager
			// while the confirm waits: confirmed in the same run.
			_, _, v3 := bundleConfigs(b.testHost)
			down := 0
			health := b.env.HealthGet
			b.env.HealthGet = func(ctx context.Context) (int, []byte, error) {
				if !b.healthy {
					if down++; down == 3 {
						b.healthy = true
					}
				}
				return health(ctx)
			}
			b.env.bundleFault = killAfterApplied
			late := b.apply(b.dir(3, v3))
			b.env.bundleFault, b.env.HealthGet = nil, health
			requireOK(t, late)
			if late.Bundle == nil || late.Bundle.BundleID != bundleID(3) || late.Bundle.State != enterprisestatus.BundleConfirmed {
				t.Fatalf("restarted gateway: bundle = %+v", late.Bundle)
			}
			if late.Policy == nil || !late.Policy.Applied || late.Policy.GatewayReportedDigest != late.Policy.EffectiveDigest {
				t.Fatalf("restarted gateway: policy = %+v", late.Policy)
			}
		})
	}
}

// GAP-0042: on macOS the apply LaunchDaemon watches config.yaml, so the
// path-triggered ensure that the bundle's own config write queued ran as soon
// as the not_confirmed apply released the lock, and confirmed the receipt
// late. The agent's resubmit of the same bytes was then a repeat of the
// current bundle (already_applied) without bundle_confirmed_after_interrupt,
// so the agent could not tell the late confirm from a first one. The
// resubmit reports it; a different bundle submitted after a not_confirmed
// one, and a repeat of a bundle its own run confirmed, do not.
func TestBundleConfirmedLateByAnotherRunWarnsOnResubmit(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, v3 := bundleConfigs(b.testHost)
			requireOK(t, b.apply(b.dir(1, v1)))
			notConfirmed := func(path string) {
				t.Helper()
				b.env.bundleFault = func(phase string) error {
					if phase == enterprisebundle.StateApplied {
						b.healthy = false
					}
					return nil
				}
				r := b.apply(path)
				b.env.bundleFault, b.healthy = nil, true
				requireError(t, r, codeBundleNotConfirmed)
				if r.ExitCode != enterprisestatus.UnixExitBusy || hasWarning(r, codeBundleConfirmedLate) {
					t.Fatalf("not_confirmed apply: exit=%d warnings=%+v", r.ExitCode, r.Warnings)
				}
			}

			path2 := b.dir(2, v2)
			notConfirmed(path2)
			// The path-triggered ensure confirms it before the agent resubmits.
			trigger := b.run(Options{Action: ActionEnsure, Reason: "path"})
			requireOK(t, trigger)
			if st := b.state(); !hasWarning(trigger, codeBundleConfirmedLate) || st.Current == nil || st.Current.BundleID != bundleID(2) {
				t.Fatalf("path ensure: warnings=%+v current=%+v", trigger.Warnings, st.Current)
			}
			again := b.apply(path2)
			requireOK(t, again)
			if again.Bundle == nil || again.Bundle.BundleID != bundleID(2) || again.Bundle.State != enterprisestatus.BundleConfirmed ||
				!hasWarning(again, codeBundleConfirmedLate) || again.Policy == nil || !again.Policy.Applied {
				t.Fatalf("resubmit after a late confirm: bundle=%+v policy=%+v warnings=%+v", again.Bundle, again.Policy, again.Warnings)
			}

			// Bundle 3 is not confirmed and the agent submits bundle 4 (other
			// bytes, another digest): this run's settle confirms bundle 3 late,
			// which its receipt records, but the result reports bundle 4.
			notConfirmed(b.dir(3, v3))
			path4 := b.dir(4, v2)
			other := b.apply(path4)
			requireOK(t, other)
			if other.Bundle == nil || other.Bundle.BundleID != bundleID(4) || other.Bundle.State != enterprisestatus.BundleConfirmed ||
				hasWarning(other, codeBundleConfirmedLate) {
				t.Fatalf("other bundle after not_confirmed: bundle=%+v warnings=%+v", other.Bundle, other.Warnings)
			}
			if rc := b.receipt(bundleID(3)); rc.State != enterprisebundle.StateConfirmed || !slices.Contains(rc.WarningCodes, codeBundleConfirmedLate) {
				t.Fatalf("bundle 3 receipt = %+v, want confirmed late", rc)
			}
			// A repeat of a bundle its own run confirmed is no late confirm.
			repeat := b.apply(path4)
			requireOK(t, repeat)
			if repeat.Bundle == nil || repeat.Bundle.BundleID != bundleID(4) || hasWarning(repeat, codeBundleConfirmedLate) {
				t.Fatalf("repeat of a first-confirmed bundle: bundle=%+v warnings=%+v", repeat.Bundle, repeat.Warnings)
			}
		})
	}
}

func TestBundleConfirmRejectsGatewayConfigErrorAndRestoresLastGood(t *testing.T) {
	b := newBundleHost(t, "darwin")
	v1, v2, _ := bundleConfigs(b.testHost)
	requireOK(t, b.apply(b.dir(1, v1)))
	good := b.read(b.env.Layout.ConfigPath)
	b.configError = "permission denied"
	status := b.run(Options{Action: ActionStatus})
	if status.Policy == nil || status.Policy.Applied || status.Policy.LastReloadError != b.configError {
		t.Fatalf("confirmed bundle status ignored gateway config error: %+v", status.Policy)
	}
	r := b.apply(b.dir(2, v2))
	requireError(t, r, codeBundleNotConfirmed)
	rc := b.receipt(bundleID(2))
	if rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeNotConfirmed || !rc.RolledBack ||
		!strings.Contains(rc.ErrorMessage, "config.state=error") {
		t.Fatalf("failed receipt = %+v", rc)
	}
	if st := b.state(); st.Current == nil || st.Current.BundleID != bundleID(1) || b.read(b.env.Layout.ConfigPath) != good {
		t.Fatalf("last good config was not restored: state = %+v", st)
	}
}

// The first bundle, installed by a run that ended before it recorded it and
// then rejected for a gateway digest mismatch, has no last good bundle to return to: it
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
	if rc.State != enterprisebundle.StateFailed || rc.ErrorCode != enterprisebundle.CodeDigestMismatch {
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
