// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0574HermesBlockTextStartsWithRuleAndReason(t *testing.T) {
	home, project := hermesPatchHome(t)
	cases := []struct {
		name, path, wantAction string
	}{
		{"protected", filepath.Join(home, ".ssh", "authorized_keys"), "block"},
		{"ordinary", filepath.Join(project, "notes.txt"), "allow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := hermesPatchBody(t, project, "write_file", map[string]any{"path": tc.path, "content": "# k\n"})
			var answer struct {
				Action     string            `json:"action"`
				Reason     string            `json:"reason"`
				HookOutput map[string]string `json:"hook_output"`
			}
			if err := json.Unmarshal([]byte(hermesPatchHostHook(t, home, project, body)), &answer); err != nil {
				t.Fatal(err)
			}
			if answer.Action != tc.wantAction {
				t.Fatalf("action=%q, want %q", answer.Action, tc.wantAction)
			}
			if tc.wantAction == "allow" {
				if answer.HookOutput["reason"] != "" {
					t.Fatalf("ordinary call has block text: %q", answer.HookOutput["reason"])
				}
				return
			}
			want := "DefenseClaw blocked this call: " + hermesPatchAuthorizedKeysRule + ": "
			if !strings.HasPrefix(answer.HookOutput["reason"], want) ||
				len(strings.TrimPrefix(answer.HookOutput["reason"], want)) == 0 {
				t.Fatalf("hook text=%q, want prefix %q and a reason", answer.HookOutput["reason"], want)
			}
			if answer.Reason != answer.HookOutput["reason"] {
				t.Fatalf("response reason=%q, hook text=%q", answer.Reason, answer.HookOutput["reason"])
			}
		})
	}
}
