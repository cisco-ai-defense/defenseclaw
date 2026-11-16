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
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
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
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1",
		"--secret-file", "ai-defense-api-key="+e.secretSource(t, "key-1"))...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	bundleDevice(t, e)
	savedValue, savedInstalled := bundleSecretValue, bundleInstalledConfig
	t.Cleanup(func() { bundleSecretValue, bundleInstalledConfig = savedValue, savedInstalled })
	return e, signed, source
}

// secretSource writes value to a credential source file for --secret-file.
func (e *bundleCLIEnv) secretSource(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(e.dir, fmt.Sprintf("secret-%d", len(value)+len(e.secretFiles)))
	e.secretFiles = append(e.secretFiles, path)
	writeBundleTestFile(t, path, []byte(value+"\n"))
	return path
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
	// stored holds the signed value "key-1" of names; holding holds value.
	stored := func(names ...string) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			if !slices.Contains(names, name) {
				return nil, nil
			}
			return []byte("key-1"), nil
		}
	}
	holding := func(value string) func(string) ([]byte, error) {
		return func(string) ([]byte, error) { return []byte(value), nil }
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
		value     func(string) ([]byte, error)
		installed func(string) ([]byte, error)
		exit      int
		missing   []string // nil: absent
		mismatch  []string // nil: absent
		restart   string   // "": absent
		settings  []string
	}{
		{"stored, hot", stored("ai-defense-api-key"), installed(source, nil), 0, []string{}, []string{}, bundleRestartNotRequired, nil},
		{"stored, restart", stored("ai-defense-api-key"), installed(restartInstalled, nil), 0, []string{}, []string{}, bundleRestartRequired, []string{"guardrail.hook_self_heal"}},
		{"installed config unreadable", stored("ai-defense-api-key"), installed("", fs.ErrPermission), 0, []string{}, []string{}, bundleRestartUnknown, nil},
		{"credential missing", stored(), installed(source, nil), bundleFailureExitCode(), []string{"ai-defense-api-key"}, []string{}, "", nil},
		{"credential not the signed value", holding("key-2"), installed(source, nil), bundleFailureExitCode(), []string{}, []string{"ai-defense-api-key"}, "", nil},
		{"store unreadable", func(string) ([]byte, error) { return nil, fs.ErrPermission }, installed(source, nil), 0, nil, nil, bundleRestartNotRequired, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bundleSecretValue, bundleInstalledConfig = tc.value, tc.installed
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
			case tc.mismatch == nil && res.SecretRefsMismatch != nil:
				t.Fatalf("secret_refs_mismatch = %v, want absent", *res.SecretRefsMismatch)
			case tc.mismatch != nil && (res.SecretRefsMismatch == nil || !slices.Equal(*res.SecretRefsMismatch, tc.mismatch)):
				t.Fatalf("secret_refs_mismatch = %v, want %v:\n%s", res.SecretRefsMismatch, tc.mismatch, out)
			}
			if strings.Contains(out, "key-2") {
				t.Fatalf("verify printed a credential value:\n%s", out)
			}
			// secret_refs is present exactly with secret_refs_missing and
			// carries names and booleans only (private #16).
			switch {
			case tc.missing == nil && res.SecretRefs != nil:
				t.Fatalf("secret_refs = %v, want absent", *res.SecretRefs)
			case tc.missing != nil:
				want := []enterprisebundle.SecretRefState{{Name: "ai-defense-api-key", Required: true,
					Present: len(tc.missing) == 0, ValueMatch: len(tc.missing) == 0 && len(tc.mismatch) == 0}}
				if res.SecretRefs == nil || !slices.Equal(*res.SecretRefs, want) {
					t.Fatalf("secret_refs = %v, want %v:\n%s", res.SecretRefs, want, out)
				}
				for _, entry := range doc["secret_refs"].([]any) {
					for key := range entry.(map[string]any) {
						if strings.Contains(key, "sha256") || strings.Contains(key, "digest") || key == "value" {
							t.Fatalf("secret_refs entry carries %s:\n%s", key, out)
						}
					}
				}
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

	// The text form names the missing or changed credential and the
	// restart.
	bundleSecretValue, bundleInstalledConfig = stored(), installed(source, nil)
	if out, _ := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors); !strings.Contains(out, "Credentials missing: ai-defense-api-key") {
		t.Fatalf("text refusal:\n%s", out)
	}
	bundleSecretValue = holding("key-2")
	if out, _ := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors); !strings.Contains(out, "Credentials not the signed value: ai-defense-api-key") {
		t.Fatalf("text mismatch refusal:\n%s", out)
	}
	bundleSecretValue, bundleInstalledConfig = stored("ai-defense-api-key"), installed(restartInstalled, nil)
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
	if _, ok := doc["secret_refs_mismatch"]; ok {
		t.Fatalf("secret_refs_mismatch off a device: %s", out)
	}
	if _, ok := doc["secret_refs"]; ok {
		t.Fatalf("secret_refs off a device: %s", out)
	}
	if _, ok := doc["restart_prediction"]; ok {
		t.Fatalf("restart_prediction off a device: %s", out)
	}
}

// The closed schema describes every member bundle verify can print.
func TestManagementContractBundleVerifyDescribesEveryMember(t *testing.T) {
	contracttest.RequireMembers(t, "bundle-verify.schema.json", reflect.TypeOf(bundleVerifyResult{}))
	contracttest.RequireMembers(t, "bundle-verify.schema.json#/$defs/restartPrediction", reflect.TypeOf(bundleRestartPrediction{}))
	contracttest.RequireMembers(t, "bundle-verify.schema.json#/$defs/secretRefState", reflect.TypeOf(enterprisebundle.SecretRefState{}))
}
