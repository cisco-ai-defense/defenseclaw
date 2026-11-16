// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Hermes 0.21 can deny a timed-out or unstarted pre_tool_call hook only when
// Setup explicitly sets fail_closed on that handler. A killed process still
// can fail open on its non-2 exit. Other events cannot use the setting, and
// the older 0.19/0.20 contract does not implement it.
func TestHermesPreToolHookFailureContract(t *testing.T) {
	useVerifiedSecureClientDeployment(t)
	for _, tc := range []struct {
		name string
		opts SetupOpts
		want bool
	}{
		{"v1", SetupOpts{HookContractID: "hermes-hooks-v1"}, false},
		{"v2", SetupOpts{HookContractID: "hermes-hooks-v2"}, true},
		{"secure-client", SetupOpts{HookContractID: "hermes-hooks-v2", ManagedEnterprise: true, SecureClientHookDelivery: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.opts.DataDir = filepath.Join(root, "state")
			path := filepath.Join(root, "config.yaml")
			if err := os.WriteFile(path, []byte("operator_value: keep\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			conn := NewHermesConnector()
			command := conn.hookCommand(tc.opts)
			if err := patchHermesHooks(path, command, "", tc.opts); err != nil {
				t.Fatal(err)
			}
			cfg, err := readYAMLObject(path)
			if err != nil {
				t.Fatal(err)
			}
			hooks := cfg["hooks"].(map[string]interface{})
			for _, spec := range hermesRequiredHooks {
				entry := hooks[spec.event].([]interface{})[0].(map[string]interface{})
				got, present := entry["fail_closed"].(bool)
				if spec.event == "pre_tool_call" {
					if got != tc.want || present != tc.want {
						t.Fatalf("%s fail_closed = %v, want %t", spec.event, entry["fail_closed"], tc.want)
					}
				} else if present {
					t.Fatalf("non-blocking %s has fail_closed = %v", spec.event, entry["fail_closed"])
				}
			}
			if !conn.renderedHookEntriesPresent(tc.opts, cfg) {
				t.Fatal("verify rejected Setup's own hook registration")
			}
			if tc.want {
				delete(hooks["pre_tool_call"].([]interface{})[0].(map[string]interface{}), "fail_closed")
				if conn.renderedHookEntriesPresent(tc.opts, cfg) {
					t.Fatal("verify accepted a pre-tool hook whose timeout fails open")
				}
				body, err := yaml.Marshal(cfg)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := patchHermesHooks(path, command, "", tc.opts); err != nil {
					t.Fatal(err)
				}
				upgraded, err := readYAMLObject(path)
				if err != nil {
					t.Fatal(err)
				}
				if !conn.renderedHookEntriesPresent(tc.opts, upgraded) || upgraded["operator_value"] != "keep" {
					t.Fatalf("upgrade did not repair the pre-tool hook and keep operator config: %v", upgraded)
				}
			}
		})
	}
}

func TestHermesSandboxV2PreToolFailureBlocks(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"0.19.0", false},
		{"0.21.5", true},
	} {
		contract := ResolveHookContract("hermes", tc.version).Contract
		hooks, err := hermesSandboxHookEntries(resolvedSandboxTarget{contract: contract})
		if err != nil {
			t.Fatal(err)
		}
		pre := hooks["pre_tool_call"].([]interface{})[0].(map[string]interface{})
		if got, _ := pre["fail_closed"].(bool); got != tc.want {
			t.Errorf("Hermes %s sandbox pre_tool_call fail_closed = %v, want %t", tc.version, pre["fail_closed"], tc.want)
		}
	}
}
