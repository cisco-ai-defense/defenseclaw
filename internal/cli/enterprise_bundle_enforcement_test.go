// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0114: a bundle-mode device whose config.yaml was edited outside the
// lifecycle verified ok with a warning, so Intune's Remediations reported it
// compliant while the gateway enforced a policy nobody signed. The decision
// below makes such a device fail verification (and ensure re-apply the
// bundle) on every platform's lifecycle; base-only devices are unaffected.
func TestBundleEnforcementDecision(t *testing.T) {
	const (
		bundleDigest = "sha256:bd021570b814a56644816c791ad88aa6bf163b72b1cf27af8462bbe84e799543"
		editedDigest = "sha256:f7d2f379e9819384e611f7365a22c5c3569d0159390a6c864bb4d3192b8d9765"
	)
	current := &enterprisebundle.Ref{BundleID: "b-01M4XRVFSG2C3VST7D5FYX95E9", Version: 3, EffectivePolicyDigest: bundleDigest}
	bundleConfig := []byte("config_version: 9\n")
	edited := append(append([]byte(nil), bundleConfig...), []byte("# appended by hand\n")...)
	enforcing := &enterprisestatus.PolicyState{EffectiveDigest: bundleDigest, GatewayReportedDigest: bundleDigest, Applied: true}
	for _, tc := range []struct {
		name     string
		in       bundleEnforcement
		replaced bool
		problem  string // "" = enforces; else a fragment of the message
	}{
		{name: "base-only device", in: bundleEnforcement{InstalledConfig: edited, GatewayReady: true,
			Policy: &enterprisestatus.PolicyState{GatewayReportedDigest: editedDigest, ConfigUnrecorded: true}}},
		{name: "untampered bundle enforces", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: bundleConfig, GatewayReady: true, Policy: enforcing}},
		{name: "tampered config, gateway on the edit", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: edited, GatewayReady: true,
			Policy: &enterprisestatus.PolicyState{EffectiveDigest: editedDigest, GatewayReportedDigest: editedDigest, Applied: true, ConfigUnrecorded: true}},
			replaced: true, problem: "config.yaml is not the config of signed policy bundle b-01M4XRVFSG2C3VST7D5FYX95E9 version 3"},
		{name: "tampered config, gateway stopped", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: edited}, replaced: true, problem: "ensure re-applies the bundle from the bundle store"},
		{name: "config restored, gateway still on the edit", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: bundleConfig, GatewayReady: true,
			Policy: &enterprisestatus.PolicyState{EffectiveDigest: bundleDigest, GatewayReportedDigest: editedDigest}},
			problem: "the gateway enforces effective policy sha256:f7d2f379e981, not sha256:bd021570b814"},
		{name: "gateway rejected the reload", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: bundleConfig, GatewayReady: true,
			Policy: &enterprisestatus.PolicyState{GatewayReportedDigest: bundleDigest, LastReloadError: "rule pack p2int: hash mismatch"}},
			problem: "rejected its last reload (rule pack p2int: hash mismatch)"},
		{name: "gateway ready but reports no policy", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: bundleConfig, GatewayReady: true}, problem: "did not report its policy"},
		{name: "gateway not ready, config is the bundle's", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			CurrentDigest: bundleDigest, InstalledConfig: bundleConfig}},
		{name: "current build digest unavailable", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig,
			InstalledConfig: bundleConfig, GatewayReady: true, Policy: enforcing}, problem: "cannot be read from the bundle store"},
		{name: "bundle store unreadable", in: bundleEnforcement{Current: current, CurrentErr: errors.New("file_hash_mismatch: policies/guardrail/p2int/rules.yaml"),
			InstalledConfig: bundleConfig, GatewayReady: true, Policy: enforcing}, problem: "cannot be read from the bundle store (file_hash_mismatch"},
		{name: "installed config unreadable", in: bundleEnforcement{Current: current, CurrentConfig: bundleConfig, CurrentDigest: bundleDigest,
			GatewayReady: true, Policy: enforcing},
			replaced: true, problem: "the installed config.yaml cannot be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.ConfigReplaced(); got != tc.replaced {
				t.Fatalf("ConfigReplaced() = %v, want %v", got, tc.replaced)
			}
			got := tc.in.Problem()
			if tc.problem == "" {
				if got != "" {
					t.Fatalf("Problem() = %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tc.problem) {
				t.Fatalf("Problem() = %q, want it to contain %q", got, tc.problem)
			}
		})
	}
}

// A deleted config.yaml is the same tamper as an edited one: ensure and
// repair write the bundle config in its place, with nothing to keep and no
// file expected. It used to fail the run with bundle_restore_failed, so the
// remediation could never repair it (GAP-0114).
func TestBundleEnforcementRestorePlan(t *testing.T) {
	current := &enterprisebundle.Ref{BundleID: "b-01M4XRVFSG2C3VST7D5FYX95E9", Version: 3}
	bundleConfig := []byte("config_version: 9\n")
	edited := append(append([]byte(nil), bundleConfig...), []byte("# appended by hand\n")...)
	confirmed := bundleEnforcement{Current: current, CurrentConfig: bundleConfig}
	denied := fmt.Errorf("open config.yaml: %w", fs.ErrPermission)
	for _, tc := range []struct {
		name      string
		in        bundleEnforcement
		installed []byte
		readErr   error
		want      bundleConfigRestore
		wantErr   bool
	}{
		{name: "edited", in: confirmed, installed: edited, want: bundleConfigRestore{Write: true, ExpectSHA256: configwrite.SHA256Hex(edited)}},
		{name: "deleted", in: confirmed, readErr: fmt.Errorf("open config.yaml: %w", fs.ErrNotExist), want: bundleConfigRestore{Write: true, Missing: true}},
		{name: "untampered", in: confirmed, installed: bundleConfig},
		{name: "unreadable", in: confirmed, readErr: denied, wantErr: true},
		{name: "deleted, bundle store unreadable", in: bundleEnforcement{Current: current, CurrentErr: errors.New("file_hash_mismatch")},
			readErr: fs.ErrNotExist},
		{name: "deleted, no bundle confirmed", readErr: fs.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.in.planRestore(tc.installed, tc.readErr)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("planRestore = %+v, %v; want %+v (error %v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestBundleEnforcementCheckedActions(t *testing.T) {
	for action, want := range map[string]bool{"status": true, "verify": true, "ensure": true, "repair": true, "upgrade": true,
		"install": false, "uninstall": false, "reconcile": false} {
		if got := bundleEnforcementCheckedAction(action); got != want {
			t.Errorf("bundleEnforcementCheckedAction(%q) = %v, want %v", action, got, want)
		}
	}
}
