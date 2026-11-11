// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestPatchEnvelopeRepeatedTargetKeepsContentRuleVerdict pins that an
// apply_patch envelope naming one protected file in two blocks is blocked in
// the default and the strict tier by every route that carries the envelope (a
// typed Codex call, a Codex shell here-document, a Claude Code shell
// here-document), whichever block holds the protected text, however the second
// name is spelled and with the envelope padded. Each block is applied, so each
// is judged on its own and the blocks together. The same repetition of an
// ordinary file stays allowed.
func TestPatchEnvelopeRepeatedTargetKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		preload = "/etc/ld.so.preload"
		library = "/usr/local/lib/liblogger.so"
	)
	block := func(kind, target, line string) string {
		return "*** " + kind + " File: " + target + "\n@@\n+" + line + "\n"
	}
	add := func(target, line string) string {
		return "*** Add File: " + target + "\n+" + line + "\n"
	}
	ordinary := filepath.Join(project, "notes.txt")
	for _, row := range []struct {
		name, blocks string
		rule         string // empty: the patch is ordinary and stays allowed
	}{
		{"single block", add(preload, library), "persistence.global_ld_preload_install"},
		{"add twice, protected second", add(preload, "# comment") + add(preload, library), "persistence.global_ld_preload_install"},
		{"add twice, protected first", add(preload, library) + add(preload, "# comment"), "persistence.global_ld_preload_install"},
		{"add twice, dot spelling", add(preload, "# comment") + add("/etc/./ld.so.preload", library), "persistence.global_ld_preload_install"},
		{"update twice", block("Update", preload, "# comment") + block("Update", preload, library), "persistence.global_ld_preload_install"},
		{"add then delete", add(preload, library) + "*** Delete File: " + preload + "\n", "persistence.global_ld_preload_install"},
		{"profile.d twice", add("/etc/profile.d/logger.sh", "export CLICOLOR=1") + add("/etc/profile.d/logger.sh", "export LD_PRELOAD="+library), "persistence.global_ld_preload_install"},
		{"pam.d twice", block("Update", "/etc/pam.d/sshd", "auth required pam_unix.so") + block("Update", "/etc/pam.d/sshd", "auth sufficient pam_permit.so"), "tamper.pam_permit_authentication_bypass"},
		{"ordinary file twice", add(ordinary, "# comment") + add(ordinary, "hello"), ""},
		{"ordinary update twice", block("Update", ordinary, "one") + block("Update", ordinary, "two"), ""},
	} {
		for _, pad := range []struct{ name, before, after string }{
			{"exact", "", ""},
			{"padded", " \n", "\n \t\n"},
		} {
			patch := pad.before + "*** Begin Patch\n" + row.blocks + "*** End Patch\n" + pad.after
			for _, pack := range []string{"", "strict"} {
				for _, route := range []string{"typed", "codex heredoc", "claudecode heredoc"} {
					t.Run(fmt.Sprintf("%s/%s/%q/%s", row.name, pad.name, pack, route), func(t *testing.T) {
						connector, tool, input := "codex", "apply_patch", map[string]any{"command": patch}
						if route != "typed" {
							command := "apply_patch <<'PATCH'\n" + patch + "PATCH"
							if route == "codex heredoc" {
								tool, input = "exec_command", map[string]any{"cmd": command}
							} else {
								connector, tool, input = "claudecode", "Bash", map[string]any{"command": command}
							}
						}
						body := (nativeWriteCall{connector, tool, func(string) map[string]any { return input }}).body(t, project, project)
						got := overLimitHostHookInPack(t, connector, pack, home, body,
							hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
						action := overLimitHookAction(t, got)
						if row.rule != "" && (action != "block" || !strings.Contains(got, row.rule)) {
							t.Fatalf("not blocked by %s: %.600s", row.rule, got)
						}
						if row.rule == "" && action == "block" {
							t.Fatalf("ordinary repeated patch blocked: %.600s", got)
						}
					})
				}
			}
		}
	}
}

// TestPatchEnvelopeRepeatedTargetPastProofBoundIsStrictOnly pins that two
// readable comment-only blocks of one content-rule file, which together make a
// text past the proof bound, stay allowed in the default and permissive tiers
// (each block is read and judged, as the same blocks in one call each are) and
// take the conservative block of the file rule in the strict tier only (the
// typed call; the here-document routes are not changed by this reading). On every route the same two blocks of an ordinary
// file, and one such block alone, are allowed in every tier.
func TestPatchEnvelopeRepeatedTargetPastProofBoundIsStrictOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	half := strings.Repeat("+# no libraries are preloaded on this host\n", 40<<10/len("+# no libraries are preloaded on this host\n"))
	add := func(target string) string { return "*** Add File: " + target + "\n" + half }
	ordinary := filepath.Join(project, "notes.txt")
	for _, row := range []struct {
		name, blocks string
		rule         string // empty: allowed in every tier
	}{
		{"preload twice", add("/etc/ld.so.preload") + add("/etc/ld.so.preload"), "persistence.global_ld_preload_install"},
		{"daemon.json twice", add("/etc/docker/daemon.json") + add("/etc/docker/daemon.json"), "tamper.docker_insecure_http_registry"},
		{"preload once", add("/etc/ld.so.preload"), ""},
		{"ordinary twice", add(ordinary) + add(ordinary), ""},
	} {
		patch := "*** Begin Patch\n" + row.blocks + "*** End Patch\n"
		for _, pack := range []string{"", "permissive", "strict"} {
			for _, route := range []string{"typed", "codex heredoc", "claudecode heredoc"} {
				t.Run(fmt.Sprintf("%s/%q/%s", row.name, pack, route), func(t *testing.T) {
					connector, tool, input := "codex", "apply_patch", map[string]any{"command": patch}
					if route != "typed" {
						command := "apply_patch <<\x27PATCH\x27\n" + patch + "PATCH"
						if route == "codex heredoc" {
							tool, input = "exec_command", map[string]any{"cmd": command}
						} else {
							connector, tool, input = "claudecode", "Bash", map[string]any{"command": command}
						}
					}
					body := (nativeWriteCall{connector, tool, func(string) map[string]any { return input }}).body(t, project, project)
					got := overLimitHostHookInPack(t, connector, pack, home, body,
						hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
					action := overLimitHookAction(t, got)
					if want := row.rule != "" && pack == "strict" && route == "typed"; (action == "block") != want {
						t.Fatalf("blocked = %t, want %t: %.600s", action == "block", want, got)
					}
					if action == "block" && !strings.Contains(got, row.rule) {
						t.Fatalf("not blocked by %s: %.600s", row.rule, got)
					}
				})
			}
		}
	}
}

// TestPatchEnvelopeRepeatedTargetPastProofBoundBlocksOnManagedInstall pins that
// a managed install, which fails closed, takes the conservative block of the
// file rule for two readable blocks of one content-rule file that make a text
// past the proof bound, in its default tier as well as in a strict one, and
// that the same blocks of an ordinary file stay allowed.
func TestPatchEnvelopeRepeatedTargetPastProofBoundBlocksOnManagedInstall(t *testing.T) {
	home, project := hermesPatchHome(t)
	line := "+# no libraries are preloaded on this host\n"
	half := strings.Repeat(line, 40<<10/len(line))
	for _, row := range []struct {
		name, target string
		blocked      bool
	}{
		{"preload twice", "/etc/ld.so.preload", true},
		{"ordinary twice", filepath.Join(project, "notes.txt"), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			block := "*** Add File: " + row.target + "\n" + half
			patch := "*** Begin Patch\n" + block + block + "*** End Patch\n"
			body := (nativeWriteCall{"codex", "apply_patch", func(string) map[string]any { return map[string]any{"command": patch} }}).body(t, project, project)
			store, logger := testStoreAndLogger(t)
			cfg := config.DefaultConfig()
			cfg.DataDir = t.TempDir()
			cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			cfg.Enterprise.Profile = managed.ProfileStandalone
			cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "codex"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(body)))
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(recorder, req)
			got := recorder.Body.String()
			if blocked := overLimitHookAction(t, got) == "block"; blocked != row.blocked {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, row.blocked, got)
			}
		})
	}
}
