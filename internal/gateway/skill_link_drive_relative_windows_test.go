// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A drive-relative path on the drive of the working folder (C:link\SKILL.md)
// names the link below the working folder, so a Read, Grep, Glob or shell
// reader of it reaches the held skill folder in every policy tier and in a
// managed deployment, as the same name without the drive does. A drive-relative
// path on another drive has a working folder the hook event does not hold: the
// strict tier and a managed deployment refuse it while a skill is held, the
// default and permissive tiers allow it with a warning. The same-drive path of
// an ordinary file and of a link to another skill stays allowed.
func TestHeldSkillFolderNamedByADriveRelativePathIsRefused(t *testing.T) {
	for _, tier := range []string{"default", "permissive", "strict", "managed"} {
		t.Run(tier, func(t *testing.T) {
			store, logger := newNativeSkillRuntimeTestStore(t)
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(home, ".claude", "skills")
			for _, name := range []string{"held", "ordinary"} {
				if err := os.MkdirAll(filepath.Join(root, name), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, name, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			proj := filepath.Join(home, "proj")
			if err := os.MkdirAll(proj, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proj, "notes.txt"), []byte("notes"), 0o644); err != nil {
				t.Fatal(err)
			}
			for link, target := range map[string]string{"lnk-held": "held", "lnk-ordinary": "ordinary"} {
				if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(proj, link), filepath.Join(root, target)).CombinedOutput(); err != nil {
					t.Skipf("cannot create a junction here: %v %s", err, out)
				}
			}
			if err := enforce.NewPolicyEngine(store).Disable("skill", "held", "quarantine failed"); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
			switch tier {
			case "permissive", "strict":
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "claudecode"
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier)
			case "managed":
				cfg.DeploymentMode = "managed_enterprise"
				cfg.Enterprise.Profile = "standalone"
			}
			api := &APIServer{store: store, logger: logger, scannerCfg: cfg}
			ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
			decide := func(tool, key, value string) (blocked bool, source string) {
				t.Helper()
				defer hookpaths.HookCall()()
				decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: tool, CWD: proj,
					ToolInput: map[string]interface{}{key: value},
				})
				return matched && decision.Action == "block", decision.Source
			}
			vol := filepath.VolumeName(proj)
			otherVol := "D:"
			if strings.EqualFold(vol, otherVol) {
				otherVol = "E:"
			}
			for name, tc := range map[string]struct{ tool, key, value string }{
				"read":          {"Read", "file_path", vol + `lnk-held\SKILL.md`},
				"read dot":      {"Read", "file_path", vol + `.\lnk-held\SKILL.md`},
				"grep":          {"Grep", "path", vol + `lnk-held`},
				"glob":          {"Glob", "path", vol + `lnk-held`},
				"shell reader":  {"Bash", "command", `type ` + vol + `lnk-held\SKILL.md`},
				"shell listing": {"Bash", "command", `dir ` + vol + `lnk-held`},
			} {
				if blocked, _ := decide(tc.tool, tc.key, tc.value); !blocked {
					t.Errorf("%s: %s %s=%q was allowed, want the held skill refused", name, tc.tool, tc.key, tc.value)
				}
			}
			for name, tc := range map[string]struct{ tool, key, value string }{
				"ordinary file":    {"Read", "file_path", vol + `notes.txt`},
				"link to ordinary": {"Read", "file_path", vol + `lnk-ordinary\SKILL.md`},
				"working folder":   {"Grep", "path", vol + `.`},
				"ordinary reader":  {"Bash", "command", `type ` + vol + `notes.txt`},
			} {
				if blocked, _ := decide(tc.tool, tc.key, tc.value); blocked {
					t.Errorf("twin %s: %s %s=%q was refused, want it allowed", name, tc.tool, tc.key, tc.value)
				}
			}
			wantUnprovenBlock := tier == "strict" || tier == "managed"
			for name, tc := range map[string]struct{ tool, key, value string }{
				"read": {"Read", "file_path", otherVol + `lnk-held\SKILL.md`},
				"grep": {"Grep", "path", otherVol + `lnk-held`},
			} {
				blocked, source := decide(tc.tool, tc.key, tc.value)
				if blocked != wantUnprovenBlock {
					t.Errorf("other drive %s: blocked=%t, want %t", name, blocked, wantUnprovenBlock)
				}
				if blocked && source != "skill-links-unproven" {
					t.Errorf("other drive %s: source = %q, want skill-links-unproven", name, source)
				}
			}
		})
	}
}
