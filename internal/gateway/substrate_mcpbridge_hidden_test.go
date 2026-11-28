// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// The bridge tests of the SUB-MCP-0841 train (substrate-1). Two rules:
//   - one depth floor for every key: an envelope the shared reader walks
//     (input/parameters/request/args) reached at its projection depth floors
//     the call at the unknown tier, whatever it holds (as fix0841 landed it
//     at 9cb524bc1d);
//   - an action the reader cannot read (under an unknown key, in an array,
//     in a payload or other non-envelope container, in a JSON string under
//     an unknown key) is judged by the rules as the same key is at the top
//     level, and is never marked unknown for being there.

type hiddenWant int

const (
	hiddenForward  hiddenWant = iota // forwarded, no audit row
	hiddenRuleDeny                   // denied by CMD-RM-RF in both tiers, denied row
	hiddenFloor                      // strict: bounded deny + row; default: forwarded + alert row
)

type hiddenCase struct {
	name, raw string
	want      hiddenWant
}

func hiddenJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// hiddenFrames sends every case as a read_file tools/call on one bridge per
// tier and checks each answer and, at the end, the audit rows by count.
func hiddenFrames(t *testing.T, cases []hiddenCase) {
	t.Helper()
	for _, strict := range []bool{true, false} {
		tier := "default"
		if strict {
			tier = "strict"
		}
		t.Run(tier, func(t *testing.T) {
			b := newTixgBridge(t, false)
			if strict {
				b.fixture.api.scannerCfg.Guardrail.Cascade.Unknown = config.CascadeBlock
			}
			laptop, agent, resp := b.open(t)
			if laptop == nil {
				t.Fatalf("attach refused: %+v", resp)
			}
			ruleDenied, floorDenied, floorAlerts := 0, 0, 0
			for i, tc := range cases {
				switch {
				case tc.want == hiddenRuleDeny:
					ruleDenied++
				case tc.want == hiddenFloor && strict:
					floorDenied++
				case tc.want == hiddenFloor:
					floorAlerts++
				}
				t.Run(tc.name, func(t *testing.T) {
					id := 2100 + i
					frame := `{"jsonrpc":"2.0","id":` + strconv.Itoa(id) +
						`,"method":"tools/call","params":{"name":"read_file","arguments":` + tc.raw + `}}`
					tixgSend(t, agent, frame)
					switch {
					case tc.want == hiddenRuleDeny:
						tixgExpectErr(t, agent, laptop, float64(id), -32001, "CMD-RM-RF")
					case tc.want == hiddenFloor && strict:
						tixgExpectErr(t, agent, laptop, float64(id), -32001, "bounded_truncated")
					default:
						if got := tixgMethods(tixgLaptopUntilBarrier(t, agent, laptop)); got != "tools/call" {
							t.Fatalf("not forwarded: %q", got)
						}
					}
				})
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				b.mu.Lock()
				rd, fd, fa, other := 0, 0, 0, 0
				for _, row := range b.audits {
					reason, _ := row["reason"].(string)
					switch row["event"] {
					case "substrate.mcp.denied":
						switch {
						case strings.Contains(reason, "CMD-RM-RF"):
							rd++
						case strings.Contains(reason, "bounded_truncated"):
							fd++
						default:
							other++
						}
					case "substrate.mcp.alert":
						if strings.Contains(reason, "bounded_truncated") {
							fa++
						} else {
							other++
						}
					}
				}
				b.mu.Unlock()
				if rd == ruleDenied && fd == floorDenied && fa == floorAlerts && other == 0 {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("audit rows: rule denied %d/%d, floor denied %d/%d, floor alerts %d/%d, other %d",
						rd, ruleDenied, fd, floorDenied, fa, floorAlerts, other)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

func hiddenOverCap(raw string) bool {
	return substrateMCPOverCap(substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{json.RawMessage(raw)}})
}

// GAP-1123, GAP-1126, GAP-1130 (not present at the base; regression pins):
// benign data under unknown keys, in arrays and in payloads forwards in
// both tiers with no audit row and no actor permit.
func TestMCPBridgeHiddenBenignDataForwards(t *testing.T) {
	var batch9, batch20 []string
	for i := 0; i < 20; i++ {
		item := `{"command":"echo step` + strconv.Itoa(i) + `"}`
		if i < 9 {
			batch9 = append(batch9, item)
		}
		batch20 = append(batch20, item)
	}
	cases := []hiddenCase{
		// GAP-1123
		{"unknown-metadata-depth", `{"metadata":{"input":{"request":{"parameters":{"note":"hello"}}}}}`, hiddenForward},
		{"payload-object-depth", `{"content":{"input":{"request":{"parameters":{"note":"hello"}}}}}`, hiddenForward},
		{"array-of-arrays-depth", `{"items":[[{"input":{"request":{"parameters":{"note":"hello"}}}}]]}`, hiddenForward},
		{"empty-array", `{"items":[]}`, hiddenForward},
		{"array-note", `{"items":[{"note":"hello"}]}`, hiddenForward},
		{"five-hundred-empty-objects", `{"items":[` + strings.Repeat(`{},`, 499) + `{}]}`, hiddenForward},
		{"many-inert-objects", `{"items":[` + strings.Repeat(`{"note":"hello"},`, 249) + `{"note":"hello"}]}`, hiddenForward},
		{"readable-depth2", `{"input":{"request":{"command":"echo safe"}}}`, hiddenForward},
		// GAP-1126
		{"push-files-small", `{"owner":"o","repo":"r","files":[{"path":"README.md","content":"hello"}]}`, hiddenForward},
		{"translate-options", `{"text":"hello","options":{"source":"en","target":"fr"}}`, hiddenForward},
		{"schema-url-object", `{"schema":{"properties":{"url":{"type":"string"}}}}`, hiddenForward},
		{"filter-target-object", `{"filter":{"target":{"$exists":true}}}`, hiddenForward},
		{"null-path", `{"meta":{"path":null}}`, hiddenForward},
		{"numeric-target", `{"stats":{"target":5}}`, hiddenForward},
		{"schema-code-object", `{"schema":{"code":{"type":"string"}}}`, hiddenForward},
		{"schema-command-object", `{"schema":{"command":{"type":"string"}}}`, hiddenForward},
		{"null-command", `{"meta":{"command":null}}`, hiddenForward},
		{"numeric-command", `{"stats":{"command":5}}`, hiddenForward},
		{"boolean-command", `{"filter":{"command":true}}`, hiddenForward},
		{"empty-command", `{"items":[{"command":"  "}]}`, hiddenForward},
		{"embed-batch-input", `{"requests":[{"input":"text to embed"}]}`, hiddenForward},
		{"http-batch", `{"requests":[{"method":"GET","url":"https://example.com/a"}]}`, hiddenForward},
		{"payload-string-json", `{"content":"{\"command\":\"echo safe\"}"}`, hiddenForward},
		// GAP-1130 and ordinary hidden commands
		{"batch-9", `{"items":[` + strings.Join(batch9, ",") + `]}`, hiddenForward},
		{"batch-20", `{"items":[` + strings.Join(batch20, ",") + `]}`, hiddenForward},
		{"hidden-git-status", `{"items":[{"command":"git status"}]}`, hiddenForward},
		{"hidden-make", `{"steps":[{"cmd":"make build"}]}`, hiddenForward},
		{"hidden-argv", `{"items":[{"argv":["ls","-la"]}]}`, hiddenForward},
		{"hidden-code-object", `{"code":{"command":"echo safe"}}`, hiddenForward},
		{"hidden-cwd-object", `{"cwd":{"command":"echo safe"}}`, hiddenForward},
		{"hidden-json-string", `{"metadata":"{\"command\":\"echo safe\"}"}`, hiddenForward},
	}
	for _, tc := range cases {
		if strings.HasPrefix(tc.name, "batch-") {
			continue // more than the free candidate count: admitted, still forwarded
		}
		if hiddenOverCap(tc.raw) {
			t.Fatalf("%s: benign arguments took an actor permit", tc.name)
		}
	}
	hiddenFrames(t, cases)
}

// GAP-1140, GAP-1129, GAP-1137 (not present at the base; regression pins):
// the depth floor applies at the reader's envelope depth whatever the key
// under the envelope and whatever its value, as at 9cb524bc1d.
func TestMCPBridgeDepthFloorEveryKey(t *testing.T) {
	cmd := hiddenJSON(t, tixgCommand)
	argv := hiddenJSON(t, strings.Fields(tixgCommand))
	argvString := hiddenJSON(t, `{"argv":`+argv+`}`)
	d3 := func(inner string) string { return `{"input":{"request":{"parameters":` + inner + `}}}` }
	cases := []hiddenCase{
		{"note", d3(`{"note":` + cmd + `}`), hiddenFloor},
		{"payload-object", d3(`{"payload":{"command":` + cmd + `}}`), hiddenFloor},
		{"cwd-object", d3(`{"cwd":{"command":` + cmd + `}}`), hiddenFloor},
		{"plain-note", d3(`{"note":"hello"}`), hiddenFloor},
		{"args-note", `{"args":{"input":{"request":{"note":"hello"}}}}`, hiddenFloor},
		{"argv-array", d3(`{"argv":` + argv + `}`), hiddenFloor},
		{"command-array", d3(`{"command":` + argv + `}`), hiddenFloor},
		{"argv-json-string", `{"input":{"request":{"parameters":` + argvString + `}}}`, hiddenFloor},
		{"code-object", d3(`{"code":{"command":` + cmd + `}}`), hiddenFloor},
		{"code-array-object", d3(`{"code":[{"command":` + cmd + `}]}`), hiddenFloor},
		{"code-argv", d3(`{"code":` + argv + `}`), hiddenFloor},
		{"depth4-code-object", d3(`{"input":{"code":{"command":` + cmd + `}}}`), hiddenFloor},
	}
	hiddenFrames(t, cases)
}

// GAP-1125, GAP-1127, GAP-1131, GAP-1138: an action the reader cannot read
// where it sits is judged by the rules as at the top level.
func TestMCPBridgeHiddenActionsAreJudged(t *testing.T) {
	cmd := hiddenJSON(t, tixgCommand)
	inString := hiddenJSON(t, `{"command":`+cmd+`}`)
	var batch []string
	for i := 0; i < 8; i++ {
		batch = append(batch, `{"command":"echo step`+strconv.Itoa(i)+`"}`)
	}
	batch = append(batch, `{"command":`+cmd+`}`)
	cases := []hiddenCase{
		// control: the reader reads this at the top level
		{"top-command", `{"command":` + cmd + `}`, hiddenRuleDeny},
		// GAP-1125
		{"array-action", `{"items":[{"command":` + cmd + `}]}`, hiddenRuleDeny},
		{"envelope-array-action", `{"input":{"items":[{"command":` + cmd + `}]}}`, hiddenRuleDeny},
		{"array-depth2-action", `{"items":[{"input":{"request":{"command":` + cmd + `}}}]}`, hiddenRuleDeny},
		{"batch-8-plus-1", `{"items":[` + strings.Join(batch, ",") + `]}`, hiddenRuleDeny},
		// GAP-1127
		{"payload-object", `{"payload":{"command":` + cmd + `}}`, hiddenRuleDeny},
		{"body-array", `{"body":[{"command":` + cmd + `}]}`, hiddenRuleDeny},
		{"unknown-json-string", `{"metadata":` + inString + `}`, hiddenRuleDeny},
		{"cwd-object", `{"cwd":{"command":` + cmd + `}}`, hiddenRuleDeny},
		// GAP-1138
		{"code-object", `{"code":{"command":` + cmd + `}}`, hiddenRuleDeny},
		{"array-code-object", `{"items":[{"code":{"command":` + cmd + `}}]}`, hiddenRuleDeny},
	}
	for _, tc := range cases {
		if tc.name != "batch-8-plus-1" && hiddenOverCap(tc.raw) {
			t.Fatalf("%s: a call with one hidden action took an actor permit", tc.name)
		}
	}
	hiddenFrames(t, cases)
}

// GAP-1131: a command or argv string array under an unknown key or in an
// array gets the one-key reading the reader reads at the top level, so it
// has the top-level verdict (the shipped rules read neither array form on
// an MCP tool: both forward, and a rule that reads one now holds both).
func TestMCPBridgeHiddenArraysReadLikeTopLevel(t *testing.T) {
	argv := hiddenJSON(t, strings.Fields(tixgCommand))
	for _, key := range []string{"argv", "command"} {
		top := `{"` + key + `":` + argv + `}`
		want := hiddenForward
		b := newTixgBridge(t, false)
		laptop, agent, resp := b.open(t)
		if laptop == nil {
			t.Fatalf("attach refused: %+v", resp)
		}
		tixgSend(t, agent, `{"jsonrpc":"2.0","id":2200,"method":"tools/call","params":{"name":"read_file","arguments":`+top+`}}`)
		if got := tixgMethods(tixgLaptopUntilBarrier(t, agent, laptop)); got != "tools/call" {
			want = hiddenRuleDeny
			_ = tixgRead(t, agent)
		}
		hiddenFrames(t, []hiddenCase{
			{key + "-top", top, want},
			{key + "-array", `{"items":[` + top + `]}`, want},
			{key + "-unknown", `{"meta":` + top + `}`, want},
		})
		scan := substrateMCPScanArguments(json.RawMessage(`{"items":[` + top + `]}`))
		if len(scan.candidates) != 1 || string(scan.candidates[0]) != top {
			t.Fatalf("%s array under items: candidates %d, want the top-level reading", key, len(scan.candidates))
		}
	}
}

// The scan: what floors, what is a candidate, what stays data.
func TestSubstrateMCPScanArguments(t *testing.T) {
	cases := []struct {
		name, raw  string
		depth      bool
		candidates []string
	}{
		{"top-command", `{"command":"echo a"}`, false, nil},
		{"depth2-command", `{"input":{"request":{"command":"echo a"}}}`, false, nil},
		{"depth3-anything", `{"input":{"request":{"parameters":{"x":1}}}}`, true, nil},
		{"depth3-null", `{"input":{"request":{"parameters":null}}}`, true, nil},
		{"depth3-json-string", `{"input":{"request":"{\"parameters\":{\"x\":1}}"}}`, true, nil},
		{"args-depth", `{"args":{"input":{"request":{}}}}`, true, nil},
		{"hidden-under-unknown", `{"meta":{"input":{"request":{"parameters":{"cmd":"echo a"}}}}}`, false, []string{`{"cmd":"echo a"}`}},
		{"items", `{"items":[{"command":"echo a"},{"command":"echo a"},{"CMD":"echo b"}]}`, false, []string{`{"command":"echo a"}`, `{"CMD":"echo b"}`}},
		{"top-array", `[{"command":"echo a"}]`, false, []string{`{"command":"echo a"}`}},
		{"hidden-input-string", `{"requests":[{"input":"text"}]}`, false, []string{`{"input":"text"}`}},
		{"json-string-unknown", `{"meta":"{\"command\":\"echo a\"}"}`, false, []string{`{"command":"echo a"}`}},
		{"json-string-payload-opaque", `{"content":"{\"command\":\"echo a\"}"}`, false, nil},
		{"payload-object", `{"payload":{"command":"echo a"}}`, false, []string{`{"command":"echo a"}`}},
		{"cwd-object", `{"cwd":{"command":"echo a"}}`, false, []string{`{"command":"echo a"}`}},
		{"command-object", `{"command":{"command":"echo a"}}`, false, []string{`{"command":"echo a"}`}},
		{"non-action-values", `{"m":{"command":null,"cmd":5,"argv":[1],"script":"  ","path":"/x","url":"u"}}`, false, nil},
		{"mixed-argv", `{"m":{"argv":["a",{"command":"echo a"}]}}`, false, []string{`{"command":"echo a"}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scan := substrateMCPScanArguments(json.RawMessage(tc.raw))
			var got []string
			for _, c := range scan.candidates {
				got = append(got, string(c))
			}
			if scan.depthLimited != tc.depth || strings.Join(got, "|") != strings.Join(tc.candidates, "|") {
				t.Fatalf("depth=%t candidates=%q, want depth=%t candidates=%q", scan.depthLimited, got, tc.depth, tc.candidates)
			}
		})
	}
	members := `{"items":[` + strings.Repeat(`{"command":"echo a"},`, 600) + `{}]}`
	if scan := substrateMCPScanArguments(json.RawMessage(members)); scan.overflow || len(scan.candidates) != 1 {
		t.Fatalf("duplicates: overflow=%t candidates=%d", scan.overflow, len(scan.candidates))
	}
}

// GAP-1141: a depth-limited call, and one with more hidden actions than the
// free count, take the per-actor permit like a reader-limit call.
func TestMCPBridgeAdmissionCoversDepthAndCandidates(t *testing.T) {
	var many []string
	for i := 0; i <= 8; i++ {
		many = append(many, `{"command":"echo step`+strconv.Itoa(i)+`"}`)
	}
	for name, raw := range map[string]string{
		"depth3-note":    `{"input":{"request":{"parameters":{"note":"hello"}}}}`,
		"depth3-command": `{"input":{"request":{"parameters":{"command":"echo safe"}}}}`,
		"args-depth":     `{"args":{"input":{"request":{"note":"hello"}}}}`,
		"nine-hidden":    `{"items":[` + strings.Join(many, ",") + `]}`,
	} {
		if !hiddenOverCap(raw) {
			t.Errorf("%s did not take the actor permit", name)
		}
	}
	if hiddenOverCap(`{"items":[` + strings.Join(many[:8], ",") + `]}`) {
		t.Error("eight hidden actions took the actor permit")
	}
}

// GAP-1124: over-cap judging is bounded per owner and gateway-wide, not
// only per actor UID; ordinary calls never wait for it.
func TestMCPBridgeOverCapAggregateAdmission(t *testing.T) {
	large := substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{json.RawMessage(strings.Repeat(" ", actionfacts.MaxArgsJSONBytes+1))}}
	normal := substrateMCPJudgedCall{tool: "read_file", args: []json.RawMessage{json.RawMessage(`{"command":"echo hi"}`)}}
	run := func(t *testing.T, regs []registry.Registration) {
		t.Helper()
		real := substrateMCPJudge
		release := make(chan struct{})
		var entered atomic.Int32
		substrateMCPJudge = func(_ *APIServer, _ context.Context, _ registry.Registration, req substrateCalloutRequest) SubstrateCalloutVerdict {
			if len(req.Args) > actionfacts.MaxArgsJSONBytes {
				entered.Add(1)
				<-release
			}
			return SubstrateCalloutVerdict{V: "1", Verdict: "allow"}
		}
		released := false
		t.Cleanup(func() {
			if !released {
				close(release)
			}
			substrateMCPJudge = real
		})
		st := &substrateState{}
		results := make(chan SubstrateCalloutVerdict, len(regs))
		for _, reg := range regs {
			b := &substrateMCPBridge{st: st, reg: reg, s: &substrateStream{target: "notes"}}
			go func() { results <- b.judge(t.Context(), "tools/call", large) }()
		}
		select {
		case v := <-results:
			if v.Verdict != "deny" || !strings.Contains(v.Reason, "over-cap actor budget") {
				t.Fatalf("first answer %+v, want the over-cap refusal", v)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%d over-cap calls entered judging at once; none was refused", entered.Load())
		}
		other := &substrateMCPBridge{st: st, reg: registry.Registration{Atespace: "other", UID: "plain"}, s: &substrateStream{target: "notes"}}
		if v := other.judge(t.Context(), "tools/call", normal); v.Verdict != "allow" {
			t.Fatalf("ordinary call held by over-cap calls: %+v", v)
		}
		close(release)
		released = true
		for range len(regs) - 1 {
			<-results
		}
	}
	person := func(sub string) registry.Person {
		return registry.Person{Kind: "oidc", Issuer: "https://idp.example", Subject: sub}
	}
	t.Run("owner", func(t *testing.T) {
		var regs []registry.Registration
		for i := 0; i < 3; i++ {
			regs = append(regs, registry.Registration{Atespace: "team", UID: fmt.Sprint("uid-", i), Person: person("one")})
		}
		run(t, regs)
	})
	t.Run("gateway", func(t *testing.T) {
		var regs []registry.Registration
		for i := 0; i < runtime.GOMAXPROCS(0)+2; i++ {
			regs = append(regs, registry.Registration{Atespace: fmt.Sprint("team-", i), UID: fmt.Sprint("uid-", i), Person: person(fmt.Sprint("p-", i))})
		}
		run(t, regs)
	})
}

// GAP-1132 (and the GAP-1128 class): the gateway's conflict checks take the
// reader's argument aliases from actionfacts.ReadArgumentField, so an alias
// the reader adds cannot be missing from them. No reader alias spelling is
// spelled out again in either function, and both agree with the reader.
func TestGatewayConflictChecksUseReaderAliases(t *testing.T) {
	spellings := []string{
		"cmd", "script", "rawcommand", "raw_command", "raw-command", "shellcommand", "shell_command",
		"shell-command", "commandline", "command_line", "command-line", "commandargv", "command_argv",
		"command-argv", "workdir", "work_dir", "work-dir", "workingdirectory", "working_directory",
		"working-directory", "filepath", "file_path", "file-path", "uri", "endpoint", "httpmethod",
		"http_method", "http-method", "parameters", "request",
	}
	fset := token.NewFileSet()
	for file, fn := range map[string]string{
		"conflicting_tool_argument_keys.go": "conflictingToolArgumentField",
		"trusted_action_dispatch.go":        "trustedCommandFieldName",
	} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, decl := range f.Decls {
			d, ok := decl.(*ast.FuncDecl)
			if !ok || d.Name.Name != fn {
				continue
			}
			found = true
			ast.Inspect(d, func(n ast.Node) bool {
				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, _ := strconv.Unquote(lit.Value)
					for _, sp := range spellings {
						if s == sp {
							t.Errorf("%s spells reader alias %q again", fn, s)
						}
					}
				}
				return true
			})
		}
		if !found {
			t.Fatalf("%s not found in %s", fn, file)
		}
	}
	keys := append([]string{"command", "argv", "args", "cwd", "path", "url", "method", "source", "destination",
		"target", "body", "data", "payload", "content", "headers", "input", "code", "Command", "CMD", " command",
		"old_string", "new_str", "replace_all", "edits", "note", ""}, spellings...)
	for _, k := range keys {
		want, known := actionfacts.ReadArgumentField(k)
		got, gotKnown := conflictingToolArgumentField(k)
		if known && (!gotKnown || got != want) {
			t.Errorf("conflictingToolArgumentField(%q) = %q,%t; reader reads %q", k, got, gotKnown, want)
		}
		lower := strings.ToLower(k)
		readerCommand := false
		if f, ok := actionfacts.ReadArgumentField(lower); ok && f == "command" {
			readerCommand = true
		}
		if trustedCommandFieldName(lower) != readerCommand {
			t.Errorf("trustedCommandFieldName(%q) = %t; reader command alias %t", lower, !readerCommand, readerCommand)
		}
	}
}

// GAP-1128 (not present at the base; regression pin): a code data field
// does not hide a denied command on the generic hook path, for shell and
// non-shell tool names.
func TestGAP1128CodeAndCommandHookParity(t *testing.T) {
	installSandboxMarkerRules(t)
	action := newAmpShellToolHooks(t, "action")
	bad := hiddenJSON(t, tixgCommand)
	for _, tool := range []string{"Bash", "execute_code", "mcp__jupyter__execute_code"} {
		t.Run(tool, func(t *testing.T) {
			resp := action(t, "gap1128-"+tool, tool, `{"code":"true","command":`+bad+`}`)
			if resp.Action != "block" || resp.RawAction != "block" || !strings.Contains(resp.Reason, "CMD-RM-RF") {
				t.Fatalf("hook action=%q raw=%q reason=%q, want a CMD-RM-RF block", resp.Action, resp.RawAction, resp.Reason)
			}
		})
	}
}
