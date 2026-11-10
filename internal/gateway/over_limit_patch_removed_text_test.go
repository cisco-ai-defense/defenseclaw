// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestOverLimitPatchRemovedTextKeepsContentRuleVerdict pins that a typed
// apply_patch envelope that removes a long line from a file a content rule
// decides on, and adds a short line, is judged at every size of the removed
// line: the PAM and sudoers proofs read the removed text as well as the added
// text, so a removed line over what they read takes the conservative finding
// and no size leaves a band where neither applies. The same patch to an
// ordinary file, and a short benign edit of the protected file, stay allowed,
// in the default and the strict tier.
func TestOverLimitPatchRemovedTextKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	for _, c := range []struct {
		name, target, attack, benign, rule string
	}{
		{"pam.d", "/etc/pam.d/sshd", "auth sufficient pam_permit.so", "auth required pam_unix.so", "tamper.pam_permit_authentication_bypass"},
		{"sudoers.d", "/etc/sudoers.d/review", "review ALL=(ALL) NOPASSWD: ALL", "", "privilege.sudoers_unrestricted_nopasswd"},
	} {
		patch := func(target string, removed int, added string) nativeWriteCall {
			return nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
				return map[string]any{"command": "*** Begin Patch\n*** Update File: " + target +
					"\n@@\n-#" + strings.Repeat("x", removed) + "\n+" + added + "\n*** End Patch\n"}
			}}
		}
		verdict := func(t *testing.T, pack string, call nativeWriteCall) string {
			body := call.body(t, project, project)
			return overLimitHostHookInPack(t, "codex", pack, home, body,
				hookpaths.ResolveConnector("codex", "", "PreToolUse", []byte(body)))
		}
		for _, removed := range []int{1000, 60000, 65535, 65537, 100000, 200000, 262000, 270000} {
			for _, pack := range []string{"", "strict"} {
				t.Run(fmt.Sprintf("%s/removed %d/%q", c.name, removed, pack), func(t *testing.T) {
					got := verdict(t, pack, patch(c.target, removed, c.attack))
					if overLimitHookAction(t, got) != "block" {
						t.Fatalf("removed line of %d bytes before %q allowed: %.600s", removed, c.attack, got)
					}
					if removed <= 60000 && !strings.Contains(got, c.rule) {
						t.Fatalf("block does not name %s: %.600s", c.rule, got)
					}
					ordinary := verdict(t, pack, patch(filepath.Join(project, "ordinary.txt"), removed, c.attack))
					if overLimitHookAction(t, ordinary) == "block" {
						t.Fatalf("the same patch to an ordinary file blocked: %.600s", ordinary)
					}
				})
			}
		}
		// Every write under sudoers.d is blocked by the path rule, so that file
		// has no benign twin.
		if c.benign == "" {
			continue
		}
		for _, pack := range []string{"", "strict"} {
			t.Run(fmt.Sprintf("%s/short benign edit/%q", c.name, pack), func(t *testing.T) {
				got := verdict(t, pack, patch(c.target, 1000, c.benign))
				if overLimitHookAction(t, got) == "block" {
					t.Fatalf("short benign edit of %s blocked: %.600s", c.target, got)
				}
			})
		}
	}
}
