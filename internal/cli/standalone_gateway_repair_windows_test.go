// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// Repair restamps its installed config, runtime root and bundle store. It
// leaves administrator-selected policy inputs and destinations in place.
// Each row exercises the real Windows DACL walk before a running service is
// stopped, with a drifted path where the row names one.
func TestWindowsRepairRollbackPreflightClassifiesDrift(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the fixture needs to set administrator-owned Windows DACLs")
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Skipf("resolve ProgramData: %v", err)
	}
	cases := []struct {
		name, drift, selected, want string
	}{
		{name: "installed config ACL", drift: "config"},
		{name: "managed runtime ACL", drift: "runtime"},
		{name: "bundle rule pack ACL", drift: "bundle", selected: "bundle"},
		{name: "runtime JSONL folder ACL", drift: "runtime", selected: "jsonl_runtime"},
		{name: "runtime JSONL existing file ACL", drift: "jsonl_file", selected: "jsonl_runtime_existing", want: `destination "local-copy"`},
		{name: "runtime JSONL nested folder ACL", drift: "jsonl_nested", selected: "jsonl_runtime_nested", want: `destination "local-copy"`},
		{name: "external JSONL folder ACL", drift: "jsonl_external", selected: "jsonl_external", want: `destination "local-copy"`},
		{name: "external policy ACL", drift: "policy", selected: "policy", want: "policy_dir"},
		{name: "external rule pack ACL", drift: "pack", selected: "pack", want: "rule_pack_dir"},
		{name: "external rule pack service read", selected: "pack", want: "lost rule-pack read access"},
		{name: "managed team IDs", selected: "team", want: "managed.allowed_team_ids"},
		{name: "managed signing IDs", selected: "signing", want: "managed.allowed_signing_ids"},
		{name: "managed bundle IDs", selected: "bundle_id", want: "managed.allowed_bundle_ids"},
		{name: "protected credential ACL", drift: "credential_file", selected: "credential"},
		{name: "empty protected credential", selected: "credential_empty", want: "protected credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, err := os.MkdirTemp(programData, "dc-repair-rollback-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			configDir := filepath.Join(root, "etc")
			dataDir := filepath.Join(root, "runtime")
			policyDir := filepath.Join(root, "external-policy")
			jsonlDir := filepath.Join(root, "external-jsonl")
			nestedJSONLDir := filepath.Join(dataDir, "nested")
			secretsDir := filepath.Join(root, "secrets")
			packDir := filepath.Join(root, "external-pack")
			if tc.selected == "bundle" {
				packDir = filepath.Join(configDir, "bundles", "pack")
			}
			for _, dir := range []string{configDir, dataDir, policyDir, jsonlDir, nestedJSONLDir, secretsDir, packDir} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(packDir, "suppressions.yaml"),
				[]byte("version: 1\npre_judge_strips: []\nfinding_suppressions: []\ntool_suppressions: []\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			body := standaloneGatewayCheckConfig
			switch tc.selected {
			case "bundle", "pack":
				body = strings.Replace(body, `  rule_pack_dir: ""`, "  rule_pack_dir: '"+packDir+"'", 1)
			case "policy":
				body += "policy_dir: '" + policyDir + "'\n"
			case "jsonl_runtime", "jsonl_runtime_existing", "jsonl_runtime_nested", "jsonl_external":
				folder := dataDir
				if tc.selected == "jsonl_runtime_nested" {
					folder = nestedJSONLDir
				}
				if tc.selected == "jsonl_external" {
					folder = jsonlDir
				}
				if tc.selected == "jsonl_runtime_existing" {
					if err := os.WriteFile(filepath.Join(folder, "events.jsonl"), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				body += "observability:\n  destinations:\n    - name: local-copy\n      kind: jsonl\n      path: '" +
					filepath.Join(folder, "events.jsonl") + "'\n"
			case "team":
				body += "managed:\n  allowed_team_ids: [team]\n"
			case "signing":
				body += "managed:\n  allowed_signing_ids: [signer]\n"
			case "bundle_id":
				body += "managed:\n  allowed_bundle_ids: [bundle]\n"
			case "credential", "credential_empty":
				body += "observability:\n  destinations:\n    - name: hec\n      kind: splunk_hec\n" +
					"      endpoint: https://collector.example.test/services/collector/event\n      token_credential: observer\n"
				value := []byte("fixture value\n")
				if tc.selected == "credential_empty" {
					value = nil
				}
				if err := os.WriteFile(filepath.Join(secretsDir, "observer"), value, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(configDir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			icacls := func(args ...string) {
				t.Helper()
				if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
					t.Fatalf("icacls %v: %v: %s", args, err, out)
				}
			}
			icacls(root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/T", "/C")
			icacls(root, "/setowner", "*S-1-5-32-544", "/T", "/C")
			if tc.selected == "credential" || tc.selected == "credential_empty" {
				icacls(secretsDir, "/inheritance:r", "/remove:g", "*S-1-5-32-545", "/T", "/C")
			}
			driftPath := map[string]string{
				"config": configPath, "runtime": dataDir, "bundle": packDir,
				"policy": policyDir, "pack": packDir, "jsonl_external": jsonlDir,
				"jsonl_file": filepath.Join(dataDir, "events.jsonl"), "jsonl_nested": nestedJSONLDir,
				"credential_file": filepath.Join(secretsDir, "observer"),
			}[tc.drift]
			if driftPath != "" {
				grant := "*S-1-5-32-545:(WD)"
				if tc.drift == "credential_file" {
					grant = "*S-1-5-32-545:(R)"
				}
				icacls(driftPath, "/grant", grant)
			}
			if tc.name == "external rule pack service read" {
				prior := standaloneServiceCanReadTree
				t.Cleanup(func() { standaloneServiceCanReadTree = prior })
				standaloneServiceCanReadTree = func(string, string, string) error {
					return errors.New("gateway service lost rule-pack read access")
				}
			}
			_, err = validateWindowsRepairRollbackConfig(configPath, dataDir, managed.DefaultGatewayServiceAccount)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Repair refused restampable drift: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Repair preflight error = %v, want %q", err, tc.want)
			}
		})
	}
}
