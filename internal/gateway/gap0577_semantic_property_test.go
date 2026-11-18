// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// Use the real kit fact channel; never read an actor path on the gateway host.
func gapNF6Facts(ctx context.Context, before string) context.Context {
	sum := sha256.Sum256([]byte(before))
	return context.WithValue(ctx, substrateEnvelopeKey{}, substrateEnvelope{
		Facts: &SubstrateFacts{Files: []SubstrateAttachedFile{{
			Role: "agent_hook_config_before", Path: sandboxauth.SandboxHome + "/.claude/settings.json",
			Content: []byte(before), Size: int64(len(before)), SHA256: hex.EncodeToString(sum[:]),
		}}},
	})
}

// Optional export is test data only. JSON strings in TSV preserve tabs/newlines.
func gapNF6Probe(t *testing.T, name, before string, edit map[string]any, laptop, actor string) {
	t.Helper()
	target := os.Getenv("DC_NF6_PROBES")
	if target == "" {
		return
	}
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := json.Marshal(before)
	e, _ := json.Marshal(edit)
	n, _ := json.Marshal(name)
	if _, err := fmt.Fprintf(f, "%s\t%s\t%s\t%s\t%s\n", n, b, e, laptop, actor); err != nil {
		t.Fatal(err)
	}
}

// Thousands of full guard-entry-point comparisons without HTTP/policy
// evaluation per rendering. The fixed case suite separately checks full API
// action, severity and rules for laptop, copy and mount actors.
func TestGAP0577SemanticProperty(t *testing.T) {
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
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, row := range gapNF6PropertyRows(t) {
		t.Run(row.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(row.file), 0600); err != nil {
				t.Fatal(err)
			}
			input := gap0264Expand(row.input, home, home).(map[string]any)
			args, _ := json.Marshal(input)
			request := trustedActionRequest{Connector: "claudecode", EnforcementCapable: true, Input: actionfacts.Input{
				Tool: row.tool, Args: args, ActiveHome: home, CWD: home,
			}}
			laptop := agentHookConfigFindingsAs(context.Background(), request, nil)
			actorInput := gap0264Expand(row.input, gap0264ActorWorkdir, sandboxauth.SandboxHome).(map[string]any)
			request.Input.Args, _ = json.Marshal(actorInput)
			request.Input.ActiveHome = sandboxauth.SandboxHome
			request.Input.CWD = gap0264ActorWorkdir
			actor := sandboxAgentHookConfigFindings(gapNF6Facts(context.Background(), row.file), request, nil)
			verdict := func(findings []RuleFinding) string {
				if len(findings) == 0 {
					return "allow/NONE"
				}
				if len(findings) != 1 {
					t.Fatalf("unexpected findings: %+v", findings)
				}
				f := findings[0]
				if f.RuleID == agentHookConfigDisableRuleID {
					return "block/" + f.Severity + "/" + f.RuleID
				}
				return "alert/" + f.Severity + "/" + f.RuleID
			}
			l, a := verdict(laptop), verdict(actor)
			gapNF6Probe(t, row.name, row.file, row.input, l, a)
			if !strings.HasPrefix(l, row.want+"/") {
				t.Fatalf("laptop=%s want %s", l, row.want)
			}
			// Equality is stronger than never-weaker, and also pins benign controls.
			if l != a {
				t.Errorf("laptop=%s actor=%s", l, a)
			}
		})
	}
}

const gapNF6Seed int64 = 5770600

func gapNF6PropertyRows(t *testing.T) []gapNF6ParityRow {
	t.Helper()
	// 128 renderings x 10 mutations x 3 edit shapes = 3840 deterministic cases.
	// Sorted input plus seeded key shuffling makes the byte corpus reproducible.
	var rows []gapNF6ParityRow
	for rendering := 0; rendering < 128; rendering++ {
		for mutation := 0; mutation < 10; mutation++ {
			seed := gapNF6Seed + int64(rendering)
			var doc map[string]any
			if err := json.Unmarshal([]byte(gap0433LaptopSettings), &doc); err != nil {
				t.Fatal(err)
			}
			doc["model"] = "before quote\" slash/ newline\n"
			doc["x"] = []any{"array", map[string]any{"model": "nested"}}
			doc["disableAllHooks"] = false
			doc["env"] = map[string]any{"NODE_OPTIONS": "--max-old-space-size=4096", "LD_LIBRARY_PATH": "/opt/lib", "BASH_ENV": "/opt/good.sh"}
			if mutation == 9 {
				doc["env"].(map[string]any)["NODE_OPTIONS"] = "--require=/opt/good.js"
			}
			before := gapNF6Render(doc, rand.New(rand.NewSource(seed)))
			want := "block"
			switch mutation {
			case 0:
				doc["hooks"].(map[string]any)["Other"] = doc["hooks"].(map[string]any)["PreToolUse"]
				delete(doc["hooks"].(map[string]any), "PreToolUse")
			case 1:
				delete(doc, "hooks")
			case 2:
				doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["matcher"] = "Never"
			case 3:
				doc["disableAllHooks"] = true
			case 4:
				doc["env"].(map[string]any)["LD_LIBRARY_PATH"] = "/tmp/evil"
			case 5:
				doc["env"].(map[string]any)["NODE_OPTIONS"] = []string{"--require=/tmp/x.js", "--require=\"/tmp/x.js\"", "--require /tmp/x.js", "--require '/tmp/x.js'"}[rendering%4]
			case 6:
				doc["env"].(map[string]any)["BASH_ENV"] = "/tmp/evil.sh"
			case 7:
				if rendering%2 == 0 {
					doc["model"] = "LD_LIBRARY_PATH --require=/tmp/benign.js"
				} else {
					doc["x"] = []any{"LD_LIBRARY_PATH --require=/tmp/benign.js", map[string]any{"model": "changed nested"}}
				}
				doc["alwaysThinkingEnabled"] = true
				want = "allow"
			case 8:
				doc["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"] = "/bin/true"
			case 9:
				doc["env"].(map[string]any)["NODE_OPTIONS"] = "--require=/tmp/evil.js"
			}
			after := gapNF6Render(doc, rand.New(rand.NewSource(seed)))
			for shape := 0; shape < 3; shape++ {
				old, newText := before, after
				// Minimal changed span can be wholly inside escape digits, quotes or flags.
				if shape != 0 {
					old, newText = gapNF6Span(before, after)
				}
				input := map[string]any{"file_path": "{H}/.claude/settings.json", "old_string": old, "new_string": newText}
				tool := "Edit"
				if shape == 2 {
					tool = "MultiEdit"
					// First a JSON-equivalent layout edit, followed by the semantic change.
					input = map[string]any{"file_path": "{H}/.claude/settings.json", "edits": []any{
						map[string]any{"old_string": before, "new_string": " \n" + before},
						map[string]any{"old_string": old, "new_string": newText},
					}}
				}
				rows = append(rows, gapNF6ParityRow{name: fmt.Sprintf("property seed=%d render=%d mutation=%d shape=%d", seed, rendering, mutation, shape), tool: tool, input: input, file: before, want: want})
			}
		}
	}
	t.Logf("PROPERTY seed=%d..%d cases=%d", gapNF6Seed, gapNF6Seed+127, len(rows))
	return rows
}

func gapNF6Span(a, b string) (string, string) {
	prefix := 0
	for prefix < len(a) && prefix < len(b) && a[prefix] == b[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(a)-prefix && suffix < len(b)-prefix && a[len(a)-1-suffix] == b[len(b)-1-suffix] {
		suffix++
	}
	// Empty old_string means creation, not insertion. Retain one surrounding byte.
	if prefix == len(a)-suffix && prefix > 0 {
		prefix--
	}
	return a[prefix : len(a)-suffix], b[prefix : len(b)-suffix]
}

func gapNF6Render(v any, r *rand.Rand) string {
	space := func() string { return []string{"", " ", "\n", "\n  ", "\t"}[r.Intn(5)] }
	quote := func(s string) string {
		var b strings.Builder
		b.WriteByte('"')
		for _, c := range s {
			if c == '/' && r.Intn(2) == 0 {
				b.WriteString(`\/`)
				continue
			}
			if c < 128 && r.Intn(3) == 0 {
				fmt.Fprintf(&b, "\\u%04x", c)
				continue
			}
			encoded, _ := json.Marshal(string(c))
			b.Write(encoded[1 : len(encoded)-1])
		}
		b.WriteByte('"')
		return b.String()
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		r.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, quote(k)+space()+":"+space()+gapNF6Render(x[k], r))
		}
		return "{" + space() + strings.Join(parts, ","+space()) + space() + "}"
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			parts[i] = gapNF6Render(e, r)
		}
		return "[" + space() + strings.Join(parts, ","+space()) + space() + "]"
	case string:
		return quote(x)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}
