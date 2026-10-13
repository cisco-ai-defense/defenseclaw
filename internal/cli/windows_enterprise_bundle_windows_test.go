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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

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
	if got.Actor != "control-plane:acme/alice" || got.Bundle.ID != id || got.Bundle.Version != 3 ||
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
	if !ok || got.Principal != "control-plane:acme/alice" || got.ID != id || got.Version != 3 || got.SignerKeyID != "k1" {
		t.Fatalf("Windows config.change.applied bundle attribution = %+v, ok=%v", got, ok)
	}
}

const windowsBundleTestDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func TestWindowsBundleVersionACLGrantsServiceReadOnly(t *testing.T) {
	const sid = "S-1-5-80-1-2-3-4-5"
	if got, want := windowsBundlePrivateSDDL(), "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"; got != want {
		t.Fatalf("private staging ACL = %q, want %q", got, want)
	}
	if got, want := windowsBundleVersionSDDL(sid), "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;"+sid+")"; got != want {
		t.Fatalf("bundle version ACL = %q, want %q", got, want)
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
	savedPrivate, savedSeal, savedPublish := windowsBundlePrivateStage, windowsBundleSealVersion, windowsBundlePublishVersion
	t.Cleanup(func() {
		windowsBundleLayout, windowsBundlePolicy, windowsBundleSleep, windowsBundleTrust, bundleAnchorTrust = savedLayout, savedPolicy, savedSleep, savedTrust, savedAnchorTrust
		windowsBundlePrivateStage, windowsBundleSealVersion, windowsBundlePublishVersion = savedPrivate, savedSeal, savedPublish
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
}
