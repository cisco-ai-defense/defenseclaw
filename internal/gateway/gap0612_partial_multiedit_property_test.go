// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// One protected change is assembled from incomplete member/value fragments,
// rather than moving an already-complete mutation through a temporary token.
func TestGAP0612PartialMultiEditProperty(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	packDir := installDefaultRulePackForDataDir(t, t.TempDir())
	pack := mustLoadRulePack(t, packDir)
	installDefaultProfileConnector(t, "claudecode")
	if err := ApplyConnectorRulePackOverrides("claudecode", pack); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	const seedBase int64 = 5770800
	cases, noops := 0, 0
	for rendering := 0; rendering < 128; rendering++ {
		seed := seedBase + int64(rendering)
		rng := rand.New(rand.NewSource(seed))
		var doc map[string]any
		if err := json.Unmarshal([]byte(gap0433LaptopSettings), &doc); err != nil {
			t.Fatal(err)
		}
		doc["model"] = fmt.Sprintf("nf8-%d", rng.Int63())
		rendered := gapNF6Render(doc, rng)
		space := []string{"", " ", "\n", "\t"}[rng.Intn(4)]
		// This ordinary member is the sole target. The rest of the document
		// varies in order, escapes and whitespace for each reported seed.
		member := `"nf8Switch"` + space + ":" + space + `false`
		before := "{" + member + "," + rendered[1:]
		for _, rel := range []string{".claude/settings.json", ".claude/settings.local.json", "proj/.claude/settings.json", "proj/.claude/settings.local.json"} {
			target := filepath.Join(home, rel)
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(before), 0600); err != nil {
				t.Fatal(err)
			}
			for _, steps := range []int{2, 3} {
				for _, benign := range []bool{false, true} {
					name := fmt.Sprintf("partial seed=%d path=%s steps=%d noop=%t", seed, rel, steps, benign)
					t.Run(name, func(t *testing.T) {
						var edits []any
						add := func(old, next string) { edits = append(edits, map[string]any{"old_string": old, "new_string": next}) }
						if benign {
							// Applicable byte-identical edits must be allowed in both
							// modes; "everything blocks" fails this property.
							for i := 0; i < steps; i++ {
								add(`"nf8Switch"`, `"nf8Switch"`)
							}
						} else {
							if steps == 3 {
								add("nf8Switch", "disableAll")
								add("disableAll", "disableAllHooks")
							} else {
								add("nf8Switch", "disableAllHooks")
							}
							add("false", "true")
						}
						input := map[string]any{"file_path": target, "edits": edits}
						args, err := json.Marshal(input)
						if err != nil {
							t.Fatal(err)
						}
						request := trustedActionRequest{Connector: "claudecode", EnforcementCapable: true,
							Input: actionfacts.Input{Tool: "MultiEdit", Args: args, ActiveHome: home, CWD: project}}
						// Prove the generated partial edits apply and yield exactly
						// one semantic protected mutation (or identical bytes).
						changes, native := agentHookConfigFileChanges("MultiEdit", args)
						if !native || len(changes) != 1 {
							t.Fatal("generator did not produce one native change")
						}
						after, exists, ok := changes[0].after(func(string) ([]byte, bool) { return []byte(before), true })
						if !ok || !exists {
							t.Fatal("generated edits do not apply")
						}
						wantAfter := strings.Replace(strings.Replace(before, "nf8Switch", "disableAllHooks", 1), "false", "true", 1)
						if benign {
							wantAfter = before
						}
						if string(after) != wantAfter {
							t.Fatal("generator changed more than the one protected member")
						}
						laptop := agentHookConfigFindingsAs(context.Background(), request, nil)
						want := agentHookConfigDisableRuleID
						if benign {
							want = ""
						}
						check := func(label string, findings []RuleFinding) {
							t.Helper()
							if want == "" {
								if len(findings) != 0 {
									t.Errorf("%s rejected byte no-op: %+v", label, findings)
								}
							} else if len(findings) != 1 || findings[0].RuleID != want || findings[0].Severity != "CRITICAL" {
								t.Errorf("%s must block CRITICAL: %+v", label, findings)
							}
						}
						check("laptop", laptop)
						actorTarget := sandboxauth.SandboxHome + "/" + rel
						if strings.HasPrefix(rel, "proj/") {
							actorTarget = gap0264ActorWorkdir + "/" + strings.TrimPrefix(rel, "proj/")
						}
						input["file_path"] = actorTarget
						request.Input.Args, err = json.Marshal(input)
						if err != nil {
							t.Fatal(err)
						}
						request.Input.ActiveHome = sandboxauth.SandboxHome
						request.Input.CWD = gap0264ActorWorkdir
						for _, facts := range []bool{false, true} {
							ctx := context.Background()
							if facts {
								ctx = gapNF8Facts(ctx, actorTarget, before)
							}
							actor := sandboxAgentHookConfigFindings(ctx, request, nil)
							verdict := func(f []RuleFinding) string {
								if len(f) == 0 {
									return "allow/NONE"
								}
								return f[0].RuleID + "/" + f[0].Severity
							}
							gapNF6Probe(t, fmt.Sprintf("%s/facts=%t", name, facts), before, input, verdict(laptop), verdict(actor))
							check(fmt.Sprintf("actor facts=%t", facts), actor)
							if !facts && !benign {
								if len(actor) == 0 || !strings.Contains(actor[0].Title, sandboxAgentHookNoBefore) {
									t.Error("partial edit lost the current-kit ambiguity message")
								}
							}
							cases++
							if benign {
								noops++
							}
						}
					})
				}
			}
		}
	}
	t.Logf("PARTIAL_PROPERTY seeds=%d..%d cases=%d byte_noops=%d", seedBase, seedBase+127, cases, noops)
}
