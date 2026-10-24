// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestRemoveCodexManagedHookFeaturePreservesOtherUserSettings(t *testing.T) {
	for _, tc := range []struct {
		name, input, preserved string
	}{
		{"table", "model = 'gpt-5'\n[features]\nhooks = false # user command\nmulti_agent = true\n", "multi_agent = true"},
		{"dotted root", "features.hooks = false\nmodel = 'gpt-5'\n", "model = 'gpt-5'"},
		{"quoted keys", "['features']\n'hooks' = false\nmulti_agent = true\n", "multi_agent = true"},
		{"inline table", "features = { hooks = false, multi_agent = true }\nmodel = 'gpt-5'\n", "multi_agent = true"},
		{"windows newline", "[features]\r\nhooks = false\r\nmulti_agent = true\r\n", "multi_agent = true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(tc.input)
			if tc.name == "windows newline" {
				input = append([]byte{0xef, 0xbb, 0xbf}, input...)
			}
			got, err := RemoveCodexManagedHookFeature(input)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), tc.preserved) || bytes.Contains(got, []byte("hooks = false")) {
				t.Fatalf("repaired config lost settings or kept disabled hooks: %q", got)
			}
			if tc.name == "windows newline" && (!bytes.HasPrefix(got, []byte{0xef, 0xbb, 0xbf}) || !bytes.Contains(got, []byte("\r\n"))) {
				t.Fatalf("repaired config lost BOM or CRLF: %q", got)
			}
			var checked map[string]interface{}
			if err := toml.Unmarshal(bytes.TrimPrefix(got, []byte{0xef, 0xbb, 0xbf}), &checked); err != nil {
				t.Fatalf("repaired config is invalid TOML: %v", err)
			}
			if features, ok := checked["features"].(map[string]interface{}); ok {
				if _, present := features["hooks"]; present {
					t.Fatalf("managed hook feature remains in user config: %#v", features)
				}
			}
		})
	}
	unchanged := []byte("model = 'gpt-5'\n[features]\nmulti_agent = true\n")
	got, err := RemoveCodexManagedHookFeature(unchanged)
	if err != nil || !bytes.Equal(got, unchanged) {
		t.Fatalf("unrelated user config was rewritten: %q, %v", got, err)
	}
	if _, err := RemoveCodexManagedHookFeature([]byte("[features]\nhooks = [\n")); err == nil || !strings.Contains(err.Error(), "parse Codex user config") {
		t.Fatalf("malformed config must return its cause: %v", err)
	}
}
