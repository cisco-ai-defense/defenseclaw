// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// GAP-1577: the config generation recovery never runs for a signed bundle
// this run applies for the first time, whose staged config may equal the
// installed base byte for byte; a repeat of the confirmed bundle and a plain
// ensure keep it.
func TestWindowsConfigGenerationRecoverySkipsANewBundleDelivery(t *testing.T) {
	digest := windowsEnterprisePolicyDigest
	t.Cleanup(func() { windowsEnterprisePolicyDigest = digest })
	windowsEnterprisePolicyDigest = func(context.Context) ([]byte, error) {
		t.Fatal("the recovery read the gateway policy for a new bundle delivery")
		return nil, nil
	}
	opts := &windowsEnterpriseLifecycleOptions{configPath: `C:\ProgramData\Cisco\DefenseClaw\etc\bundles\staged\config.yaml`,
		bundle: &windowsBundleRun{prepared: &enterprisebundle.Prepared{}}}
	repaired, err := repairWindowsEnterpriseConfigGeneration(context.Background(), opts,
		&windowsEnterpriseInstallerReport{OK: true, Installed: true, InstalledVersion: "1.0.4"})
	if repaired || err != nil {
		t.Fatalf("new bundle delivery: repaired=%t err=%v, want the recovery skipped", repaired, err)
	}
	if !windowsEnterpriseNewBundleDelivery(opts) {
		t.Fatal("a first delivery is not a new bundle delivery")
	}
	opts.bundle.prepared.AlreadyApplied = true
	if windowsEnterpriseNewBundleDelivery(opts) || windowsEnterpriseNewBundleDelivery(&windowsEnterpriseLifecycleOptions{}) {
		t.Fatal("a repeat of the confirmed bundle or a plain ensure skipped the recovery")
	}
}
