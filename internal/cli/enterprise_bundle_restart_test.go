// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// The prediction classifies the change from the installed config to the
// bundle config the way the apply on each platform does, and names
// settings, never change paths.
func TestPredictBundleRestart(t *testing.T) {
	const base = "config_version: 9\nguardrail:\n  mode: observe\n  connectors:\n    claudecode:\n      enabled: true\n"
	withConnector := func(name string) string { return base + "    " + name + ":\n      enabled: true\n" }
	enrollment := func(user string) string {
		return "config_version: 9\nenterprise:\n  enrollment:\n    exclude_users:\n      - " + user + "\n" + strings.TrimPrefix(base, "config_version: 9\n")
	}
	for _, tc := range []struct {
		name, goos, installed, next string
		want                        string
		reasons, settings           []string
	}{
		{"hot mode change", "linux", base, strings.Replace(base, "mode: observe", "mode: action", 1), bundleRestartNotRequired, []string{}, nil},
		{"formatting only", "darwin", base, "# managed\n" + base, bundleRestartNotRequired, []string{}, nil},
		{"restart-required key", "linux", base, base + "  hook_self_heal: false\n", bundleRestartRequired, []string{restartReasonSettings}, []string{"guardrail.hook_self_heal"}},
		{"connector added on Linux", "linux", base, withConnector("amp"), bundleRestartRequired, []string{restartReasonSettings}, []string{"guardrail.connectors.*.enabled"}},
		{"connector added on macOS", "darwin", base, withConnector("amp"), bundleRestartRequired, []string{restartReasonSettings}, []string{"guardrail.connectors.*.enabled"}},
		{"connector added on Windows", "windows", base, withConnector("amp"), bundleRestartNotRequired, []string{}, nil},
		{"enrollment list on Linux", "linux", enrollment("alice"), enrollment("bob"), bundleRestartRequired, []string{restartReasonSettings}, []string{"enterprise.enrollment"}},
		{"enrollment list on Windows", "windows", enrollment("alice"), enrollment("bob"), bundleRestartNotRequired, []string{}, nil},
		{"gateway key on Windows", "windows", base, base + "gateway:\n  port: 18971\n", bundleRestartRequired, []string{restartReasonSettings}, []string{"gateway"}},
		{"Codex on Windows", "windows", base, withConnector("codex"), bundleRestartRequired, []string{restartReasonCodexMachinePolicy}, []string{"guardrail.connectors.*.enabled"}},
		{"Codex on Linux", "linux", base, withConnector("codex"), bundleRestartRequired, []string{restartReasonSettings}, []string{"guardrail.connectors.*.enabled"}},
		{"Fleet on Windows", "windows", base, base + "fleet:\n  enabled: true\n", bundleRestartUnknown, []string{restartReasonFleetSetup}, nil},
		// The apply replaces a config it cannot parse wholesale: every key
		// changes, so a restart-required one restarts the gateway.
		{"unparseable installed config", "linux", "guardrail: [", base, bundleRestartRequired, []string{restartReasonSettings}, []string{"guardrail.connectors.*.enabled"}},
		// The Windows apply refuses it (it cannot read the Fleet setting).
		{"unparseable installed config on Windows", "windows", "guardrail: [", base, bundleRestartUnknown, []string{restartReasonInstalledUnreadable}, nil},
		{"empty installed config", "darwin", "", base, bundleRestartUnknown, []string{restartReasonInstalledUnreadable}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := predictBundleRestart(tc.goos, []byte(tc.installed), nil, []byte(tc.next))
			if got.GatewayRestart != tc.want || !slices.Equal(got.ReasonCodes, tc.reasons) || !slices.Equal(got.Settings, tc.settings) {
				t.Fatalf("prediction = %+v, want %s %v %v", got, tc.want, tc.reasons, tc.settings)
			}
			if got.ReasonCodes == nil {
				t.Fatal("reason_codes must render as [] when there is no reason")
			}
		})
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		got := predictBundleRestart(goos, nil, errors.New("permission denied"), []byte(base))
		if got.GatewayRestart != bundleRestartUnknown || !slices.Equal(got.ReasonCodes, []string{restartReasonInstalledUnreadable}) {
			t.Fatalf("%s unreadable installed config: %+v", goos, got)
		}
	}
}

// The prediction agrees with the shared classifier on every change, and a
// map key below a restart-required setting (an enrollment group, a
// connector) never appears in it.
func TestPredictBundleRestartNamesNoMapKey(t *testing.T) {
	installed := "config_version: 9\nenterprise:\n  enrollment:\n    include_groups:\n      - DCLAB\\eng-team-alice\nguardrail:\n  connectors:\n    claudecode:\n      enabled: true\n"
	next := strings.Replace(installed, "eng-team-alice", "ops-team-bob", 1) + "    secret-agent-x:\n      enabled: true\n"
	restart, err := configwrite.ManagedConfigRestartRequired([]byte(installed), []byte(next))
	if err != nil || len(restart) == 0 {
		t.Fatalf("classifier: %v %v", restart, err)
	}
	got := predictBundleRestart("linux", []byte(installed), nil, []byte(next))
	if got.GatewayRestart != bundleRestartRequired {
		t.Fatalf("prediction = %+v, classifier %v", got, restart)
	}
	for _, setting := range got.Settings {
		for _, secret := range []string{"alice", "bob", "secret-agent", "DCLAB"} {
			if strings.Contains(setting, secret) {
				t.Fatalf("setting %q names %q", setting, secret)
			}
		}
	}
}

// A repeat of the confirmed bundle is never classified (apply changes
// nothing); any other verified bundle is classified against the installed
// config the seam reads.
func TestBundleVerifyRestartPrediction(t *testing.T) {
	saved := bundleInstalledConfig
	t.Cleanup(func() { bundleInstalledConfig = saved })
	bundleInstalledConfig = func(string) ([]byte, error) {
		t.Fatal("an already-applied bundle read the installed config")
		return nil, nil
	}
	got := bundleVerifyRestartPrediction("linux", &enterprisebundle.VerifyResult{AlreadyApplied: true})
	if got.GatewayRestart != bundleRestartNotRequired || !slices.Equal(got.ReasonCodes, []string{restartReasonAlreadyApplied}) {
		t.Fatalf("already applied: %+v", got)
	}
	const installed = "config_version: 9\nguardrail:\n  mode: observe\n"
	bundleInstalledConfig = func(platform string) ([]byte, error) {
		if platform != "darwin" {
			t.Fatalf("installed config read for %s", platform)
		}
		return []byte(installed), nil
	}
	got = bundleVerifyRestartPrediction("darwin", &enterprisebundle.VerifyResult{Rendered: []byte(installed + "  hook_self_heal: false\n")})
	if got.GatewayRestart != bundleRestartRequired || !slices.Equal(got.Settings, []string{"guardrail.hook_self_heal"}) {
		t.Fatalf("restart bundle: %+v", got)
	}
}

// The Windows hot path and the prediction share one filter of the
// restart-required paths: enrollment lists and the connector set apply in
// the running deployment, every other key restarts the gateway.
func TestWindowsBundleStartOnlyPaths(t *testing.T) {
	startOnly, refresh := windowsBundleStartOnlyPaths([]string{
		"enterprise.enrollment.include_users", "guardrail.connectors.amp", "guardrail.connectors.amp.enabled",
		"guardrail.connectors.amp.mode", "enterprise.enrollment.mode", "gateway.port",
	})
	if !refresh || !slices.Equal(startOnly, []string{"guardrail.connectors.amp.mode", "enterprise.enrollment.mode", "gateway.port"}) {
		t.Fatalf("start only %v, refresh %v", startOnly, refresh)
	}
	if startOnly, refresh := windowsBundleStartOnlyPaths(nil); startOnly != nil || refresh {
		t.Fatalf("no change: %v %v", startOnly, refresh)
	}
}
