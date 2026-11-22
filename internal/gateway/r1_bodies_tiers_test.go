// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// DET111 step 3, class R1 (nested and staged bodies, the frontends and the
// walker of internal/effects): verdict-level rows for the R1 gaps. The rows
// are the DET111 gap corpus copies the effects package judges at the IR
// (internal/effects/testdata/det111_r1*.cases.jsonl), read here so no attack
// spelling is written by hand. Each POSIX row runs on the hook path of two
// connectors and on the content route (/inspect/tool, OpenClaw exec) in all
// five tiers, with the shipped effects lane and with the lane off (the
// a64bfdb931 verdicts):
//   - an attack row reaches at least the unknown tier (alert in default,
//     permissive and managed; block in strict and managed strict) and is never
//     below its lane-off verdict;
//   - a benign row is never stricter than its lane-off verdict (the lane adds
//     no benign raise).
// With the lane off (DET111_R1_LANE=off) the attack rows allow: the fail-before.

// det111R1VerdictPending are attack rows whose verdict does not reach the
// unknown tier yet, with the lane that closes each (the IR table's
// det111Pending, plus rows whose IR is green but whose verdict is decided
// elsewhere). A pending row that starts to pass fails the test.
var det111R1VerdictPending = map[string]string{
	"GAP-1502/var2":  "the file a staged curl -d @FILE sends is not graded (send source, S3-PRE flow lane)",
	"GAP-1508/seed":  "fetch piped to a shell is the remote-code verdict, not an effect target (decision side)",
	"GAP-1508/var":   "fetch piped to a shell under coproc: remote-code verdict, not an effect target (decision side)",
	"GAP-1508/var2":  "fetch piped to a shell under coproc { }: remote-code verdict, not an effect target (decision side)",
	"GAP-1561/seed5": ".git/config is not a protected set (decision side)",
	"GAP-1640/var":   "the written script's text (os.system) is a content verdict, not an effect target (R7 / content scanners)",
	"GAP-1640/var2":  "the written script's text (os.system) is a content verdict, not an effect target (R7 / content scanners)",
	"GAP-1641/var":   ".env staged then sent: .env is not a protected set; send-source flow (S3-PRE flow lane)",
	"GAP-1641/var2":  ".env copied then sent: .env is not a protected set; send-source flow (S3-PRE flow lane)",
	"GAP-1653/seed":  ".env read: .env is not a protected set (decision side)",
	"GAP-1653/seed2": ".env read: .env is not a protected set (decision side)",
	"GAP-1653/var":   ".env read through an alias of open: .env is not a protected set (decision side)",
}

type det111R1Row struct {
	id, gap, role, platform, tool, command string
	attack, benign                         bool
}

func loadDET111R1Rows(t *testing.T) []det111R1Row {
	t.Helper()
	var rows []det111R1Row
	for _, fn := range []string{"det111_r1.cases.jsonl", "det111_r1_launch.cases.jsonl"} {
		f, err := os.Open(filepath.Join("..", "effects", "testdata", fn))
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var c struct {
				ID      string `json:"id"`
				Payload struct {
					Args     map[string]any `json:"args"`
					Dialect  string         `json:"dialect"`
					ToolName string         `json:"tool_name"`
				} `json:"payload"`
				Strata struct {
					Platform string `json:"platform"`
				} `json:"strata"`
				Truth struct {
					Categories []string `json:"categories"`
					Truth      string   `json:"deterministic_truth"`
				} `json:"truth"`
			}
			if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
				t.Fatal(err)
			}
			r := det111R1Row{id: strings.TrimPrefix(c.ID, "gap/det111-b_"), platform: c.Strata.Platform, tool: c.Payload.ToolName}
			r.command, _ = c.Payload.Args["command"].(string)
			attackMiss := false
			for _, k := range c.Truth.Categories {
				switch {
				case strings.HasPrefix(k, "gap:"):
					r.gap = strings.TrimPrefix(k, "gap:")
				case strings.HasPrefix(k, "role:"):
					r.role = strings.TrimPrefix(k, "role:")
				case k == "kind:attack-miss":
					attackMiss = true
				}
			}
			r.attack = attackMiss && c.Truth.Truth == "deterministic_malicious"
			r.benign = c.Truth.Truth == "benign"
			if c.Payload.Dialect != "posix" || (r.platform != "linux" && r.platform != "macos") || r.command == "" {
				continue // the Windows and tool-argument rows run in their own tests
			}
			rows = append(rows, r)
		}
		f.Close()
	}
	return rows
}

// det111R1Home lays out the test home the rows name (/home/alice on Linux,
// /Users/alice on macOS, rewritten to it).
func det111R1Home(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	for _, f := range []string{".ssh/authorized_keys", ".ssh/id_rsa", ".aws/credentials", ".claude/settings.json",
		".defenseclaw/config.yaml", ".bashrc", "proj/notes.txt", "proj/out.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home
}

type det111R1Route struct {
	name, connector string
	decide          func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string
}

func det111R1Routes() []det111R1Route {
	return []det111R1Route{
		{"claudecode Bash", "claudecode", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-r1", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}},
		{"codex shell", "codex", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			return api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			}).Action
		}},
		{"openclaw inspect/tool", "openclaw", func(t *testing.T, api *APIServer, ctx context.Context, cwd, command string) string {
			out := gap0437Inspect(t, api, cwd, command)
			// the content route reports the pack's action; observe never applies here (action mode)
			a, _ := out["action"].(string)
			return a
		}},
	}
}

func TestDET111R1BodiesVerdictFiveTiers(t *testing.T) {
	home := det111R1Home(t)
	rows := loadDET111R1Rows(t)
	if len(rows) < 60 {
		t.Fatalf("only %d POSIX rows: the corpus copy lost rows", len(rows))
	}
	laneOff := os.Getenv("DET111_R1_LANE") == "off"
	probe := os.Getenv("DET111_R1_PROBE") != ""
	cwd := filepath.Join(home, "proj")
	rewrite := strings.NewReplacer("/home/alice", home, "/Users/alice", home)
	attacks, failed := 0, map[string]bool{}
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range det111R1Routes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				command := rewrite.Replace(row.command)
				useEffectsRulesMode(t, "off")
				off := boundedParse(route.decide(t, api, t.Context(), cwd, command))
				on := off
				if !laneOff {
					useDefaultEffectsLane(t)
					on = boundedParse(route.decide(t, api, t.Context(), cwd, command))
				}
				if probe {
					t.Logf("ROW\t%s\t%s\t%s\t%s\toff=%s\ton=%s", tier.name, route.name, row.id, row.role, off, on)
				}
				where := tier.name + " " + route.name + " " + row.id
				switch {
				case row.attack:
					attacks++
					if bounded.Stricter(on, off) != on {
						t.Errorf("%s: lane on %s is below lane off %s (raise-only)", where, on, off)
					}
					ok := bounded.Stricter(on, floor) == on
					if !ok {
						failed[row.id] = true
						if _, pending := det111R1VerdictPending[row.id]; !pending {
							t.Errorf("%s %q: %s, want at least %s", where, command, on, floor)
						}
					}
				case row.benign:
					if bounded.Stricter(on, off) != off {
						t.Errorf("%s %q: benign row raised by the lane: %s, lane off %s", where, command, on, off)
					}
				}
			}
		}
	}
	for id, why := range det111R1VerdictPending {
		if !failed[id] {
			t.Errorf("%s reaches the unknown tier now: remove it from det111R1VerdictPending (%s)", id, why)
		}
	}
	if attacks == 0 {
		t.Fatal("no attack rows judged")
	}
}
