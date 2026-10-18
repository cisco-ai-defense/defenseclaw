// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

// verifyV2Device signs a bundle whose config names the credential
// ai-defense-api-key, makes the test a managed device and returns the
// bundle path and the source config.yaml.
func verifyV2Device(t *testing.T) (e *bundleCLIEnv, signed string, source string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the Windows device layout needs a registered install; predictBundleRestart and the hot-path parity test cover Windows")
	}
	e = newBundleCLIEnv(t)
	path := filepath.Join(e.in, "config.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source = strings.Replace(string(raw), "enterprise:\n  profile: standalone\n", "enterprise:\n  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	writeBundleTestFile(t, path, []byte(source))
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed = filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	bundleDevice(t, e)
	savedPresent, savedInstalled := bundleSecretPresent, bundleInstalledConfig
	t.Cleanup(func() { bundleSecretPresent, bundleInstalledConfig = savedPresent, savedInstalled })
	return e, signed, source
}

// treeOf lists every file and directory below root with its exact size,
// mode and modification time, so a test can prove a run wrote nothing there.
func treeOf(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, err := entry.Info()
		if err == nil {
			out = append(out, fmt.Sprintf("%s %s %d %s", path, info.ModTime(), info.Size(), info.Mode()))
		}
		return nil
	})
	return out
}

// On a managed device bundle verify --json lists the missing credentials
// and predicts the gateway restart; every outcome validates against the
// closed schema, and verify writes nothing.
func TestManagementContractBundleVerifyV2(t *testing.T) {
	schemas := contracttest.Compile(t)
	e, signed, source := verifyV2Device(t)
	stored := func(names ...string) func(string) (bool, error) {
		return func(name string) (bool, error) { return slices.Contains(names, name), nil }
	}
	installed := func(raw string, err error) func(string) ([]byte, error) {
		return func(platform string) ([]byte, error) {
			if platform != runtime.GOOS {
				t.Fatalf("installed config read for %s", platform)
			}
			return []byte(raw), err
		}
	}
	restartInstalled := strings.Replace(source, "  mode: observe\n", "  mode: observe\n  hook_self_heal: false\n", 1)
	for _, tc := range []struct {
		name      string
		present   func(string) (bool, error)
		installed func(string) ([]byte, error)
		exit      int
		missing   []string // nil: absent
		restart   string   // "": absent
		settings  []string
	}{
		{"stored, hot", stored("ai-defense-api-key"), installed(source, nil), 0, []string{}, bundleRestartNotRequired, nil},
		{"stored, restart", stored("ai-defense-api-key"), installed(restartInstalled, nil), 0, []string{}, bundleRestartRequired, []string{"guardrail.hook_self_heal"}},
		{"installed config unreadable", stored("ai-defense-api-key"), installed("", fs.ErrPermission), 0, []string{}, bundleRestartUnknown, nil},
		{"credential missing", stored(), installed(source, nil), bundleFailureExitCode(), []string{"ai-defense-api-key"}, "", nil},
		{"store unreadable", func(string) (bool, error) { return false, fs.ErrPermission }, installed(source, nil), 0, nil, bundleRestartNotRequired, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundleSecretPresent, bundleInstalledConfig = tc.present, tc.installed
			before := treeOf(t, e.dir)
			out, code := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--json")
			doc := schemas.Validate(t, "bundle-verify.schema.json", []byte(out))
			requireExit(t, doc, code, tc.exit)
			if after := treeOf(t, e.dir); !slices.Equal(before, after) {
				t.Fatalf("verify changed the device files:\nbefore %v\nafter  %v", before, after)
			}
			var res bundleVerifyResult
			if err := json.Unmarshal([]byte(out), &res); err != nil {
				t.Fatal(err)
			}
			switch {
			case tc.missing == nil && res.SecretRefsMissing != nil:
				t.Fatalf("secret_refs_missing = %v, want absent", *res.SecretRefsMissing)
			case tc.missing != nil && (res.SecretRefsMissing == nil || !slices.Equal(*res.SecretRefsMissing, tc.missing)):
				t.Fatalf("secret_refs_missing = %v, want %v:\n%s", res.SecretRefsMissing, tc.missing, out)
			}
			switch {
			case tc.restart == "" && res.RestartPrediction != nil:
				t.Fatalf("restart_prediction = %+v, want absent", res.RestartPrediction)
			case tc.restart != "" && (res.RestartPrediction == nil || res.RestartPrediction.GatewayRestart != tc.restart || !slices.Equal(res.RestartPrediction.Settings, tc.settings)):
				t.Fatalf("restart_prediction = %+v, want %s %v:\n%s", res.RestartPrediction, tc.restart, tc.settings, out)
			}
			if strings.Contains(out, "hook_self_heal: false") {
				t.Fatal("verify printed installed config content")
			}
		})
	}

	// The text form names the missing credential and the restart.
	bundleSecretPresent, bundleInstalledConfig = stored(), installed(source, nil)
	if out, _ := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors); !strings.Contains(out, "Credentials missing: ai-defense-api-key") {
		t.Fatalf("text refusal:\n%s", out)
	}
	bundleSecretPresent, bundleInstalledConfig = stored("ai-defense-api-key"), installed(restartInstalled, nil)
	if out, code := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors); code != 0 ||
		!strings.Contains(out, "Gateway restart on apply: required (restart_settings); settings: guardrail.hook_self_heal") {
		t.Fatalf("text restart (exit %d):\n%s", code, out)
	}

	// Another --platform than this OS is not this device's apply: no prediction.
	other := "linux"
	if runtime.GOOS == "linux" {
		other = "darwin"
	}
	out, _ := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--platform", other, "--json")
	if doc := schemas.Validate(t, "bundle-verify.schema.json", []byte(out)); doc["restart_prediction"] != nil {
		t.Fatalf("prediction for another platform: %v", doc["restart_prediction"])
	}

	// Off a device neither member is printed.
	bundleManagedDevice = func() bool { return false }
	out, code := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--json")
	doc := schemas.Validate(t, "bundle-verify.schema.json", []byte(out))
	requireExit(t, doc, code, 0)
	if _, ok := doc["secret_refs_missing"]; ok {
		t.Fatalf("secret_refs_missing off a device: %s", out)
	}
	if _, ok := doc["restart_prediction"]; ok {
		t.Fatalf("restart_prediction off a device: %s", out)
	}
}

// The closed schema describes every member bundle verify can print.
func TestManagementContractBundleVerifyDescribesEveryMember(t *testing.T) {
	contracttest.RequireMembers(t, "bundle-verify.schema.json", reflect.TypeOf(bundleVerifyResult{}))
	contracttest.RequireMembers(t, "bundle-verify.schema.json#/$defs/restartPrediction", reflect.TypeOf(bundleRestartPrediction{}))
}
