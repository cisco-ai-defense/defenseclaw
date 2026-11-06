// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0079: a status run that confirms a bundle publishes it on the marker
// through the registry root of the standalone lifecycle. The package's tests
// point that root at the HKCU sandbox, so the real marker sync writes there
// and never on the computer's own HKLM marker, where this fixture's bundle
// landed on a managed computer.
func TestWindowsBundleMarkerSyncWritesOnlyTheTestSandbox(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "sandbox.dcbundle")
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
	digest := run.prepared.EffectivePolicyDigest
	if err := run.driver.Store.Advance(rc, enterprisebundle.StateApplied, func(r *enterprisebundle.Receipt) {
		r.ConfigSHA256, r.ConfigGeneration, r.EffectivePolicyDigest = run.prepared.ConfigSHA256, generation, digest
	}); err != nil {
		t.Fatal(err)
	}
	policy := &enterprisebundle.GatewayPolicy{EffectiveDigest: digest, Digest: digest,
		Generation: generation, BundleID: rc.BundleID, BundleVersion: rc.Version, Applied: true}
	if confirmed, err := settleWindowsAppliedBundle(run.driver, run.prepared.Config, policy); err != nil || !confirmed {
		t.Fatalf("the fixture bundle was not confirmed: confirmed=%t error=%v", confirmed, err)
	}

	marker, _, err := registry.CreateKey(windowsEnterpriseMachineRegistry, WindowsEnterpriseMarkerKey,
		registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatalf("create the sandbox marker: %v", err)
	}
	t.Cleanup(func() {
		for _, name := range []string{"BundleId", "BundleVersion", "BundleState"} {
			_ = marker.DeleteValue(name)
		}
		_ = marker.Close()
	})
	before := snapshotTestMachineRegistry()
	if err := syncWindowsBundleMarker(run.driver.Store); err != nil {
		t.Fatalf("sync the sandbox marker: %v", err)
	}
	for name, want := range map[string]string{
		"BundleId":      rc.BundleID,
		"BundleVersion": strconv.FormatUint(rc.Version, 10),
		"BundleState":   enterprisebundle.StateConfirmed,
	} {
		if got, _, err := marker.GetStringValue(name); err != nil || got != want {
			t.Errorf("sandbox marker %s = %q (%v), want %q", name, got, err, want)
		}
	}
	if changes := diffTestMachineRegistry(before, snapshotTestMachineRegistry()); len(changes) != 0 {
		t.Fatalf("the marker sync changed HKLM:\n%s", strings.Join(changes, "\n"))
	}
}
