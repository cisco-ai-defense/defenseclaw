// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// Review findings of rel-1-0-10:GAP-0176 (GAP-0295, GAP-0296, GAP-0297 and
// the Kiro-shaped edit input). Like the parity test, the actions are not
// written here: they are the shell, Write and Edit cases of the existing
// fixtures (testdata/acp_parity_cases.jsonl, by case id), re-framed.

func acpBlocked(raw string) bool {
	decided := normalizeCodexAction(raw)
	return decided == "block" || decided == "confirm"
}

func acpJSONText(t *testing.T, value any) string {
	t.Helper()
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestACPFrameWithKeysThatDifferOnlyInCaseIsRefused: encoding/json reads
// "Command" and "command" as one field and keeps the last, while the editor
// reads the exact key. A twin key after the real one made the guard judge one
// action and the editor run another, for every blocked fixture frame
// (GAP-0295). The parser now refuses such a frame, in params and on the
// envelope, and the gateway refuses it too.
func TestACPFrameWithKeysThatDifferOnlyInCaseIsRefused(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	env := newACPActionEnv(t, "default")
	benign := filepath.Join(env.project, "notes.txt")
	cwd := acpJSONText(t, env.project)
	var blocked, refused int
	check := func(id, frame string, asMethod string) {
		t.Helper()
		if _, err := acp.ParseMessage([]byte(frame)); err == nil {
			t.Errorf("%s: the guard parses a frame with a twin key: %.200s", id, frame)
			return
		}
		if response := env.post(t, acp.AgentToClient, []byte(frame), asMethod); response.Code != http.StatusBadRequest {
			t.Errorf("%s: the gateway answers %d to a frame with a twin key, want 400", id, response.Code)
			return
		}
		refused++
	}
	for _, pair := range pairs {
		var control string
		var twins []struct{ name, frame string }
		switch pair.method {
		case "terminal/create":
			command := acpJSONText(t, pair.params["command"])
			params := `{"sessionId":"s","command":` + command + `,"cwd":` + cwd + `}`
			control = `{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":` + params + `}`
			twins = []struct{ name, frame string }{
				{"Command", `{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":{"sessionId":"s","command":` + command + `,"Command":"echo ok","cwd":` + cwd + `}}`},
				{"Method", `{"jsonrpc":"2.0","id":1,"method":"terminal/create","Method":"terminal/output","params":` + params + `}`},
				{"Params", `{"jsonrpc":"2.0","id":1,"method":"terminal/create","params":` + params + `,"Params":{"sessionId":"s","command":"echo ok"}}`},
			}
		case "fs/write_text_file":
			path, content := acpJSONText(t, pair.params["path"]), acpJSONText(t, pair.params["content"])
			control = `{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"sessionId":"s","path":` + path + `,"content":` + content + `}}`
			twins = []struct{ name, frame string }{
				{"Path", `{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"sessionId":"s","path":` + path + `,"Path":` + acpJSONText(t, benign) + `,"content":` + content + `}}`},
				{"Content", `{"jsonrpc":"2.0","id":1,"method":"fs/write_text_file","params":{"sessionId":"s","path":` + path + `,"content":` + content + `,"Content":"ok"}}`},
			}
		default:
			continue
		}
		if !acpBlocked(env.evaluate(t, acp.AgentToClient, []byte(control)).RawAction) {
			continue
		}
		blocked++
		for _, twin := range twins {
			check(pair.id+" "+twin.name, twin.frame, pair.method)
		}
	}
	if blocked < 60 {
		t.Fatalf("only %d fixture frames are blocked: the rules did not load?", blocked)
	}
	t.Logf("%d blocked fixture frames, %d twin-key variants refused", blocked, refused)
}

// TestACPPermissionPastTheLocationBoundIsJudgedAtTheUnknownTier: a permission
// that names more locations than the guard judges one by one has its first
// ones judged (a block among them stays a block) and is then raised to the
// unknown tier of the pack: an alert in the default and permissive packs,
// where the editor asks the user the permission it was sent, and a block in
// strict (GAP-0296, GAP-0331). A report of the same cannot be refused, so its
// raw action and would_block follow the tier.
func TestACPPermissionPastTheLocationBoundIsJudgedAtTheUnknownTier(t *testing.T) {
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			creds := env.credentialsFile()
			strict := pack == "strict"
			locations := func(benign int, first, last string) []any {
				var out []any
				if first != "" {
					out = append(out, map[string]any{"path": first})
				}
				for i := 0; i < benign; i++ {
					out = append(out, map[string]any{"path": filepath.Join(env.project, fmt.Sprintf("f%d.txt", i))})
				}
				if last != "" {
					out = append(out, map[string]any{"path": last})
				}
				return out
			}
			permission := func(list []any) acp.Verdict {
				return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
					"toolCall": map[string]any{"toolCallId": "t", "kind": "edit", "title": "Edit", "locations": list}}))
			}
			// The credentials file among the judged locations is blocked, whatever
			// follows it.
			for _, benign := range []int{0, 7, 8, 20, acpMaxFrameToolCalls - 1} {
				if verdict := permission(locations(benign, "", creds)); !acpBlocked(verdict.RawAction) {
					t.Errorf("%d workspace locations then the credentials file: %+v, want a block", benign, verdict)
				}
			}
			for _, benign := range []int{0, 7, acpMaxFrameToolCalls, acpMaxFrameToolCalls + 40} {
				if verdict := permission(locations(benign, creds, "")); !acpBlocked(verdict.RawAction) {
					t.Errorf("the credentials file then %d workspace locations: %+v, want a block", benign, verdict)
				}
			}
			if verdict := permission(locations(20, "", "")); verdict.Action != "allow" || verdict.RawAction != "allow" {
				t.Errorf("20 workspace locations: %+v, want a plain allow", verdict)
			}
			if verdict := permission(locations(acpMaxFrameToolCalls, "", "")); verdict.Action != "allow" || verdict.RawAction != "allow" {
				t.Errorf("%d workspace locations: %+v, want a plain allow", acpMaxFrameToolCalls, verdict)
			}
			over := permission(locations(acpMaxFrameToolCalls+1, "", ""))
			switch {
			case strict && !acpBlocked(over.RawAction):
				t.Errorf("strict, %d workspace locations: %+v, want a block", acpMaxFrameToolCalls+1, over)
			case !strict && (over.Action != "alert" || over.RawAction != "alert" || over.WouldBlock):
				t.Errorf("%s, %d workspace locations: %+v, want an alert the editor can ask", pack, acpMaxFrameToolCalls+1, over)
			}
			// A report of the same: the raw action and would_block follow the tier.
			report := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s",
				"update": map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "edit", "locations": locations(acpMaxFrameToolCalls+1, "", "")}}))
			switch {
			case strict && (report.Action != "alert" || report.RawAction != "block" || !report.WouldBlock):
				t.Errorf("strict report over the bound: %+v, want an alert that would have blocked", report)
			case !strict && (report.Action != "alert" || report.RawAction != "alert" || report.WouldBlock):
				t.Errorf("%s report over the bound: %+v, want a plain alert", pack, report)
			}
			// The bound counts locations, whatever the kind (a search is a call of its own).
			for _, count := range []int{acpMaxFrameToolCalls, acpMaxFrameToolCalls + 1} {
				other := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 2, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
					"toolCall": map[string]any{"toolCallId": "t", "kind": "search", "title": "Search", "locations": locations(count, "", "")}}))
				switch {
				case count <= acpMaxFrameToolCalls && (other.Action != "allow" || other.RawAction != "allow"):
					t.Errorf("%s, a search over %d locations: %+v, want a plain allow", pack, count, other)
				case count > acpMaxFrameToolCalls && strict && !acpBlocked(other.RawAction):
					t.Errorf("strict, a search over %d locations: %+v, want a block", count, other)
				case count > acpMaxFrameToolCalls && !strict && other.Action != "alert":
					t.Errorf("%s, a search over %d locations: %+v, want an alert", pack, count, other)
				}
			}
		})
	}
}

// TestACPTerminalWithoutDirectoryRunsInTheSessionDirectory: terminal/create
// names its directory optionally; the editor runs it in the session's, which
// the guard sends. The command is judged there, as the hook of a session in
// that directory judges it (GAP-0297). The pairs are the fixtures' shell
// cases; the parity test checks the project, this the account's home too.
func TestACPTerminalWithoutDirectoryRunsInTheSessionDirectory(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	env := newACPActionEnv(t, "default")
	t.Chdir(t.TempDir()) // not the project: the gateway's own directory never decides
	home := filepath.Dir(env.project)
	for _, sessionDir := range []string{env.project, home} {
		env.sessionCWD = sessionDir
		hookEnv := *env
		hookEnv.project = sessionDir
		var compared, mismatches int
		var example string
		for _, pair := range pairs {
			if pair.method != "terminal/create" || pair.noCWD {
				continue
			}
			hook, _ := hookEnv.kiroHook(t, pair.hookTool, pair.hookInput, true)
			acpVerdict := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "terminal/create", map[string]any{"sessionId": "s", "command": pair.hookInput["command"]}))
			compared++
			if normalizeCodexAction(hook) != normalizeCodexAction(acpVerdict.RawAction) {
				mismatches++
				if example == "" {
					example = fmt.Sprintf("%s hook %s / ACP %s", pair.id, hook, acpVerdict.RawAction)
				}
			}
		}
		if compared < 100 || mismatches > 0 {
			t.Errorf("session directory %s: %d terminal pairs, %d differ (e.g. %s)", filepath.Base(sessionDir), compared, mismatches, example)
		}
	}
}

// TestACPActionWithNoKnownDirectoryIsAtTheUnknownTier: with no directory in the
// frame and none for the session, a command, or a file named relative, is not
// clean: it is judged as given and raised to the unknown tier of the pack (an
// alert in the default and permissive packs, a block in strict), and a report
// follows the tier in its raw action and would_block (GAP-0297, GAP-0331). A
// relative directory is joined to the session's. A call that needs no
// directory (a read or write of an absolute path) is judged as before.
func TestACPActionWithNoKnownDirectoryIsAtTheUnknownTier(t *testing.T) {
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			strict := pack == "strict"
			env.sessionCWD = ""
			command := map[string]any{"sessionId": "s", "command": "git", "args": []string{"status"}}
			wantAction := func(name string, verdict acp.Verdict) {
				t.Helper()
				switch {
				case strict && !acpBlocked(verdict.RawAction):
					t.Errorf("%s: %+v, want a block", name, verdict)
				case !strict && (verdict.Action != "alert" || verdict.RawAction != "alert" || verdict.WouldBlock):
					t.Errorf("%s: %+v, want an alert", name, verdict)
				}
			}
			wantAction("terminal with no directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "terminal/create", command)))
			wantAction("execute permission with no directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 2, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
				"toolCall": map[string]any{"toolCallId": "t", "kind": "execute", "rawInput": map[string]any{"command": "git status"}}})))
			for method, params := range map[string]map[string]any{
				"fs/read_text_file":  {"sessionId": "s", "path": "docs/README.md"},
				"fs/write_text_file": {"sessionId": "s", "path": "docs/README.md", "content": "x"},
			} {
				wantAction("relative path of "+method+" with no directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 3, method, params)))
			}
			wantAction("permission to edit a relative location with no directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 4, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
				"toolCall": map[string]any{"toolCallId": "t", "kind": "edit", "locations": []any{map[string]any{"path": "docs/README.md"}}}})))
			report := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
				"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "rawInput": map[string]any{"command": "git status"}}}))
			switch {
			case strict && (report.Action != "alert" || report.RawAction != "block" || !report.WouldBlock):
				t.Errorf("execute report with no directory: %+v, want an alert that would have blocked", report)
			case !strict && (report.Action != "alert" || report.RawAction != "alert" || report.WouldBlock):
				t.Errorf("execute report with no directory: %+v, want a plain alert", report)
			}
			// Calls that name their place, or need none, are clean.
			clean := func(name string, verdict acp.Verdict) {
				t.Helper()
				if verdict.Action != "allow" || verdict.RawAction != "allow" {
					t.Errorf("%s: %+v, want a plain allow", name, verdict)
				}
			}
			clean("read of an absolute path", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 5, "fs/read_text_file", map[string]any{"sessionId": "s", "path": filepath.Join(env.project, "README.md")})))
			clean("terminal naming its directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 6, "terminal/create", map[string]any{"sessionId": "s", "command": "git", "cwd": env.project})))
			env.sessionCWD = env.project
			clean("terminal naming a relative directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 7, "terminal/create", map[string]any{"sessionId": "s", "command": "git", "cwd": "sub"})))
			clean("relative path in the session directory", env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 8, "fs/read_text_file", map[string]any{"sessionId": "s", "path": "docs/README.md"})))
			if got := acpCallDirectory(env.project, "sub"); got != env.project+string(filepath.Separator)+"sub" {
				t.Errorf("relative directory joined to %q", got)
			}
			if got := acpCallDirectory(env.project, ""); got != env.project {
				t.Errorf("no directory read as %q", got)
			}
		})
	}
}

// TestACPAbsolutePathsAreRecognisedInBothSpellings: a path that names its
// place needs no session directory, in the POSIX, Windows and home spellings,
// whatever platform the gateway runs on.
func TestACPAbsolutePathsAreRecognisedInBothSpellings(t *testing.T) {
	for path, want := range map[string]bool{
		"/tmp/x": true, `C:\Users\alice\x`: true, "c:/Users/alice/x": true, `\\host\share\x`: true, "~/x": true,
		"x": false, "./x": false, "sub/x": false, `sub\x`: false, "C:x": false, "": false,
	} {
		if got := acpAbsolute(path); got != want {
			t.Errorf("acpAbsolute(%q) = %t, want %t", path, got, want)
		}
	}
}

// acpGuardState is what the guard (acp.ToolCallTracker, the code the proxy
// runs) sends with a permission that names a call after the call was
// reported with kind, input and locations.
func acpGuardState(t *testing.T, kind string, input map[string]any, locations []any) json.RawMessage {
	t.Helper()
	var tracker acp.ToolCallTracker
	report := map[string]any{"sessionUpdate": "tool_call", "toolCallId": "t", "title": "x", "kind": kind, "rawInput": input}
	if locations != nil {
		report["locations"] = locations
	}
	tracker.Commit(acpParsedFrame(t, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": report})))
	return tracker.Peek(acpParsedFrame(t, acpFrameJSON(t, 1, "session/request_permission",
		map[string]any{"sessionId": "s", "options": []any{}, "toolCall": map[string]any{"toolCallId": "t", "title": "x"}})))
}

func acpParsedFrame(t *testing.T, frame []byte) acp.Message {
	t.Helper()
	msg, err := acp.ParseMessageAllowingNullIDErrors(frame)
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// TestACPPermissionWithoutAKindIsJudgedByItsInput: toolCall of a permission is
// a ToolCallUpdate, whose kind is optional: the editor applies it onto the
// tool_call that gave the kind. Without it the permission is read by the shape
// of its input (a command is a shell call, text or a replacement for a path is
// a Write or Edit of it), as the same action with its kind is judged, never as
// a generic tool that reads its locations as reads (GAP-0330). A path with no
// text to write shows no action: it is judged as a read and raised to the
// unknown tier, never as a write the input does not show (GAP-0375). The
// actions are the fixtures' shell, Write, Edit and read cases, in the three
// packs, and the state comes from the guard's own tracker.
func TestACPPermissionWithoutAKindIsJudgedByItsInput(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			strict := pack == "strict"
			permission := func(toolCall map[string]any, state json.RawMessage) acp.Verdict {
				env.toolCallState = state
				defer func() { env.toolCallState = nil }()
				return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission",
					map[string]any{"sessionId": "s", "options": []any{}, "toolCall": toolCall}))
			}
			var compared, blocked, reads, readsBlocked, readsHookBlocked int
			for _, pair := range pairs {
				var input map[string]any
				var kind string
				var locations []any
				switch pair.method {
				case "terminal/create":
					if pair.noCWD {
						continue
					}
					input, kind = map[string]any{"command": pair.hookInput["command"]}, "execute"
				case "fs/write_text_file":
					input, kind = map[string]any{"path": pair.hookInput["path"], "content": pair.hookInput["content"]}, "edit"
					locations = []any{map[string]any{"path": pair.hookInput["path"]}}
				case "session/request_permission": // the fixtures' Edit cases
					input, kind = map[string]any{"path": pair.hookInput["path"], "old_string": pair.hookInput["oldStr"], "new_string": pair.hookInput["newStr"]}, "edit"
					locations = []any{map[string]any{"path": pair.hookInput["path"]}}
				case "fs/read_text_file":
					kind, locations = "read", []any{map[string]any{"path": pair.hookInput["path"]}}
				default:
					continue
				}
				// As in the parity test: a file action names an absolute path (the
				// corpus holds Windows spellings a POSIX gateway reads as relative to
				// a directory when it has one), so the guard sends no directory for it.
				env.sessionCWD = ""
				if kind == "execute" {
					env.sessionCWD = env.project
				}
				withKind := map[string]any{"toolCallId": "t", "kind": kind, "title": "x"}
				withoutKind := map[string]any{"toolCallId": "t", "title": "x"}
				if input != nil {
					withKind["rawInput"], withoutKind["rawInput"] = input, input
				}
				if locations != nil {
					withKind["locations"], withoutKind["locations"] = locations, locations
				}
				want := permission(withKind, nil)
				compared++
				if kind == "read" {
					// A path with no text to write and no kind: a read at the unknown
					// tier. In the default and permissive packs it is what the same
					// permission as a read is, or an alert; strict blocks it. Never a
					// write the input does not show.
					reads++
					got := permission(withoutKind, nil)
					if acpBlocked(got.RawAction) {
						readsBlocked++
					}
					if acpBlocked(want.RawAction) {
						readsHookBlocked++
					}
					switch {
					case strict && !acpBlocked(got.RawAction):
						t.Errorf("%s: a path with no kind and no text, %s, want a block at the strict tier", pair.id, got.RawAction)
					case !strict && !acpBlocked(want.RawAction) && acpBlocked(got.RawAction):
						t.Errorf("%s: a path with no kind and no text blocks (%s, %s), the read of it is %s", pair.id, got.RawAction, got.Severity, want.RawAction)
					case !strict && normalizeCodexAction(got.RawAction) == "allow":
						t.Errorf("%s: a path with no kind and no text is a clean allow, want the unknown tier", pair.id)
					}
					continue
				}
				if acpBlocked(want.RawAction) {
					blocked++
				}
				if got := permission(withoutKind, nil); normalizeCodexAction(got.RawAction) != normalizeCodexAction(want.RawAction) {
					t.Errorf("%s: without a kind %s, with the kind %s", pair.id, got.RawAction, want.RawAction)
				}
				// The guard's own tracker gives the kind and the input of the first
				// report; the permission names only its id and title.
				state := acpGuardState(t, kind, input, locations)
				got := permission(map[string]any{"toolCallId": "t", "title": "x"}, state)
				if !strings.Contains(string(state), `"truncated"`) {
					if normalizeCodexAction(got.RawAction) != normalizeCodexAction(want.RawAction) {
						t.Errorf("%s: kind and input from the guard's state %s, in the permission %s", pair.id, got.RawAction, want.RawAction)
					}
				} else if rank := map[string]int{"allow": 0, "alert": 1, "block": 2}; rank[normalizeCodexAction(got.RawAction)] < rank[normalizeCodexAction(want.RawAction)] {
					// An input the guard cut to a prefix is judged at the unknown
					// tier at least, never below the whole call.
					t.Errorf("%s: a cut input from the guard's state %s, below the permission %s", pair.id, got.RawAction, want.RawAction)
				}
			}
			t.Logf("%s: %d permissions compared, %d blocked with their kind; %d read pairs, %d blocked as a read, %d blocked with no kind", pack, compared, blocked, reads, readsHookBlocked, readsBlocked)
			if compared < 250 || blocked < 100 || reads < 20 {
				t.Fatalf("%d permissions compared, %d blocked, %d reads: the rules did not load?", compared, blocked, reads)
			}
			// An input of a shape nothing reads, with no kind and no location, is the unknown tier.
			unknown := env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 2, "session/request_permission", map[string]any{"sessionId": "s", "options": []any{},
				"toolCall": map[string]any{"toolCallId": "t", "rawInput": map[string]any{"opaque": "x"}}}))
			switch {
			case strict && !acpBlocked(unknown.RawAction):
				t.Errorf("an input of an unknown shape with no kind: %+v, want a block", unknown)
			case !strict && (unknown.Action != "alert" || unknown.RawAction != "alert"):
				t.Errorf("an input of an unknown shape with no kind: %+v, want an alert", unknown)
			}
		})
	}
}

// TestACPKindsOtherThanReadJudgeTheirLocationsAsWrites: only a read reads. A
// permission for a delete, a move (a write of the destination, a delete of the
// source) or any kind that names no file action of its own (other, search,
// think...) is an action on its locations, which are judged as writes
// (GAP-0373). The locations are the fixtures' Write and Edit cases the hook
// blocks, sent with the kind and with the paths in the input or the locations.
func TestACPKindsOtherThanReadJudgeTheirLocationsAsWrites(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	env := newACPActionEnv(t, "default")
	env.sessionCWD = ""
	permission := func(toolCall map[string]any) acp.Verdict {
		return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission",
			map[string]any{"sessionId": "s", "options": []any{}, "toolCall": toolCall}))
	}
	type shape struct {
		name  string
		build func(kind, path string) map[string]any
	}
	shapes := []shape{
		{"locations", func(kind, path string) map[string]any {
			return map[string]any{"toolCallId": "t", "kind": kind, "locations": []any{map[string]any{"path": path}}}
		}},
		{"locations and input path", func(kind, path string) map[string]any {
			return map[string]any{"toolCallId": "t", "kind": kind, "locations": []any{map[string]any{"path": path}}, "rawInput": map[string]any{"path": path}}
		}},
		{"move destination", func(kind, path string) map[string]any {
			return map[string]any{"toolCallId": "t", "kind": kind, "rawInput": map[string]any{"source": filepath.Join(env.project, "a.txt"), "destination": path}}
		}},
		{"move source", func(kind, path string) map[string]any {
			return map[string]any{"toolCallId": "t", "kind": kind, "rawInput": map[string]any{"from": path, "to": filepath.Join(env.project, "a.txt")}}
		}},
	}
	for _, kind := range []string{"edit", "delete", "move", "other", "search", "think", "switch_mode", "fetch"} {
		var tried, blocked int
		var example string
		for _, pair := range pairs {
			if pair.method != "fs/write_text_file" {
				continue
			}
			path, _ := pair.hookInput["path"].(string)
			hook, _ := env.kiroHook(t, pair.hookTool, pair.hookInput, false)
			if !acpBlocked(hook) {
				continue
			}
			for _, sh := range shapes {
				if (sh.name == "move destination" || sh.name == "move source") && kind != "move" {
					continue
				}
				tried++
				if got := permission(sh.build(kind, path)); acpBlocked(got.RawAction) {
					blocked++
				} else if example == "" {
					example = fmt.Sprintf("%s (%s): %s %s", pair.id, sh.name, got.RawAction, got.Severity)
				}
			}
		}
		if tried < 100 {
			t.Fatalf("kind %s: only %d permissions tried", kind, tried)
		}
		t.Logf("kind %s: %d of %d permissions for a file the hook blocks are blocked", kind, blocked, tried)
		if blocked != tried {
			t.Errorf("kind %s: %d of %d permissions for a file the hook blocks are not blocked (e.g. %s)", kind, tried-blocked, tried, example)
		}
	}
	// A read reads.
	for _, pair := range pairs {
		if pair.method != "fs/read_text_file" {
			continue
		}
		path, _ := pair.hookInput["path"].(string)
		if got := permission(shapes[0].build("read", path)); acpBlocked(got.RawAction) {
			t.Errorf("%s: a read permission blocks: %+v", pair.id, got)
		}
	}
	// Moving one workspace file onto another is clean.
	clean := permission(map[string]any{"toolCallId": "t", "kind": "move",
		"rawInput": map[string]any{"source": filepath.Join(env.project, "a.txt"), "destination": filepath.Join(env.project, "b.txt")}})
	if clean.Action != "allow" || clean.RawAction != "allow" {
		t.Errorf("a move inside the workspace: %+v, want a plain allow", clean)
	}
}

// TestACPDroppedToolCallStateIsTheUnknownTier: a permission that names only the
// id of a call the guard no longer holds (past its 256 calls) shows no action;
// a call whose command was cut keeps its prefix, so what the guard saw is still
// judged. Neither is a fixed block: both follow the pack (GAP-0374).
func TestACPDroppedToolCallStateIsTheUnknownTier(t *testing.T) {
	pairs, _ := acpParityPairs(t, loadACPParityCases(t))
	for _, pack := range []string{"default", "permissive", "strict"} {
		t.Run(pack, func(t *testing.T) {
			env := newACPActionEnv(t, pack)
			strict := pack == "strict"
			permission := func(state json.RawMessage) acp.Verdict {
				env.toolCallState = state
				defer func() { env.toolCallState = nil }()
				return env.evaluate(t, acp.AgentToClient, acpFrameJSON(t, 1, "session/request_permission",
					map[string]any{"sessionId": "s", "options": []any{}, "toolCall": map[string]any{"toolCallId": "t", "title": "Run it"}}))
			}
			// The state was dropped: the id names an action that is not known.
			dropped := permission(json.RawMessage(`{"dropped":true}`))
			switch {
			case strict && !acpBlocked(dropped.RawAction):
				t.Errorf("a dropped call: %+v, want a block", dropped)
			case !strict && (dropped.Action != "alert" || dropped.RawAction != "alert"):
				t.Errorf("a dropped call: %+v, want an alert", dropped)
			}
			// With no state and nothing else, an id-only permission is still unreadable.
			if got := permission(nil); !acpBlocked(got.RawAction) {
				t.Errorf("an id-only permission with no state: %+v, want the unreadable refusal", got)
			}
			// A command cut to its prefix: what was seen is judged, and a block in it stays one.
			var blockedCommands, kept int
			env.sessionCWD = env.project
			for _, pair := range pairs {
				if pair.method != "terminal/create" || pair.noCWD {
					continue
				}
				command, _ := pair.hookInput["command"].(string)
				hook, _ := env.kiroHook(t, pair.hookTool, pair.hookInput, true)
				if !acpBlocked(hook) {
					continue
				}
				if len(command) > 4<<10 {
					continue // longer than the prefix the guard keeps
				}
				blockedCommands++
				var tracker acp.ToolCallTracker
				padded := command + "\n# " + strings.Repeat("x", acp.MaxToolCallStateBytes)
				tracker.Commit(acpParsedFrame(t, acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": map[string]any{
					"sessionUpdate": "tool_call", "toolCallId": "t", "kind": "execute", "rawInput": map[string]any{"command": padded}}})))
				state := tracker.Peek(acpParsedFrame(t, acpFrameJSON(t, 1, "session/request_permission",
					map[string]any{"sessionId": "s", "toolCall": map[string]any{"toolCallId": "t"}})))
				// The same cut command through the hook is what the verdict is
				// compared with: what the guard kept is judged as the hook judges it.
				cut := padded[:8<<10]
				hookCut, _ := env.kiroHook(t, pair.hookTool, map[string]any{"command": cut}, true)
				got := permission(state)
				if normalizeCodexAction(got.RawAction) != normalizeCodexAction(hookCut) && !acpBlocked(got.RawAction) {
					t.Errorf("%s: the cut command is %s through ACP and %s through the hook", pair.id, got.RawAction, hookCut)
				}
				if acpBlocked(got.RawAction) {
					kept++
				} else if !acpBlocked(hookCut) {
					kept++ // the hook does not block the cut command either
					t.Logf("%s: a block of %d bytes is not a block once %d bytes of comment follow it, through the hook too (%s)", pair.id, len(command), len(cut)-len(command), hookCut)
				}
			}
			if blockedCommands < 25 || kept != blockedCommands {
				t.Errorf("%d of %d blocked commands still block with a cut input", kept, blockedCommands)
			}
		})
	}
}

// A gateway ignores a field of the evaluation it does not know, so a guard
// newer than the gateway is not refused for it (GAP-0374).
func TestACPGatewayIgnoresEvaluationFieldsItDoesNotKnow(t *testing.T) {
	env := newACPActionEnv(t, "default")
	frame := acpFrameJSON(t, 1, "fs/read_text_file", map[string]any{"sessionId": "s", "path": filepath.Join(env.project, "README.md")})
	body, err := json.Marshal(map[string]any{"profile": "default", "mode": string(env.mode), "agent_id": "kiro", "client_id": "zed",
		"direction": string(acp.AgentToClient), "surface": string(acp.SurfaceFilesystem), "method": "fs/read_text_file",
		"payload": json.RawMessage(frame), "a_field_of_a_later_version": []int{1}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	env.acpAPI.handleACPEvaluate(response, httptest.NewRequest(http.MethodPost, "/api/v1/acp/evaluate", bytes.NewReader(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("an evaluation with a field the gateway does not know: status %d %s", response.Code, response.Body.String())
	}
}

// TestACPUpdateWithAStatusOnlyNamesNoAction: a tool_call_update that carries
// only a status or output is not judged again as the call it belongs to, even
// when the guard keeps the state of that call.
func TestACPUpdateWithAStatusOnlyNamesNoAction(t *testing.T) {
	env := newACPActionEnv(t, "default")
	env.toolCallState = acpMarshal(map[string]any{"kind": "execute", "rawInput": map[string]any{"command": "git status"}})
	for _, update := range []map[string]any{
		{"sessionUpdate": "tool_call_update", "toolCallId": "t", "status": "completed"},
		{"sessionUpdate": "tool_call_update", "toolCallId": "t", "rawOutput": map[string]any{"ETag": "a", "etag": "b"}},
	} {
		action, isAction := acpFrameToolCalls(acp.Evaluation{
			Direction: acp.AgentToClient, ToolCallState: env.toolCallState,
			Payload: acpFrameJSON(t, 0, "session/update", map[string]any{"sessionId": "s", "update": update}),
		}, "linux")
		if isAction {
			t.Errorf("update %v is an action: %+v", update, action)
		}
	}
}

// TestACPMergedToolCallKeepsOwnFields: the permission's own fields replace the
// kept ones, a null does not, and a field left out of the kept state for size
// is a cap hit.
func TestACPMergedToolCallKeepsOwnFields(t *testing.T) {
	merged, trunc := acpMergeToolCall(
		json.RawMessage(`{"kind":"read","title":"Read","rawInput":{"path":"/tmp/x"},"truncated":true}`),
		json.RawMessage(`{"toolCallId":"t","kind":"edit","title":null}`))
	var got map[string]json.RawMessage
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["kind"]) != `"edit"` || string(got["title"]) != `"Read"` || string(got["rawInput"]) != `{"path":"/tmp/x"}` || string(got["toolCallId"]) != `"t"` {
		t.Errorf("merged = %s", merged)
	}
	if !trunc.Any() {
		t.Error("a field left out for size is not a cap hit")
	}
	if kept, trunc := acpMergeToolCall(nil, json.RawMessage(`{"a":1}`)); string(kept) != `{"a":1}` || trunc.Any() {
		t.Errorf("no state: %s, %v", kept, trunc)
	}
}

// TestACPKiroShapedEditInputIsReadAsTheWrite: Kiro's own fs_write and
// str_replace inputs name the text file_text, old_str and new_str. The
// permission and the report of such an edit carry the same text to the rules
// as the Write or Edit the hook judges (review of GAP-0176, P3).
func TestACPKiroShapedEditInputIsReadAsTheWrite(t *testing.T) {
	for _, tc := range []struct {
		name, input, tool string
		want              map[string]string
	}{
		{"create", `{"command":"create","path":"/tmp/x","file_text":"ok"}`, "Write", map[string]string{"file_path": "/tmp/x", "content": "ok"}},
		{"camel case", `{"path":"/tmp/x","fileText":"ok"}`, "Write", map[string]string{"file_path": "/tmp/x", "content": "ok"}},
		{"replace", `{"command":"str_replace","path":"/tmp/x","old_str":"a","new_str":"b"}`, "Edit", map[string]string{"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}},
		{"replace camel case", `{"path":"/tmp/x","oldStr":"a","newStr":"b"}`, "Edit", map[string]string{"file_path": "/tmp/x", "old_string": "a", "new_string": "b"}},
		{"agent-neutral names", `{"path":"/tmp/x","content":"ok"}`, "Write", map[string]string{"file_path": "/tmp/x", "content": "ok"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(`{"kind":"edit","title":"Edit","rawInput":` + tc.input + `}`)
			for _, permission := range []bool{true, false} {
				calls, _, _ := acpToolCallUpdateCalls(raw, "linux", permission, bounded.CapSet{})
				if len(calls) != 1 || calls[0].tool != tc.tool {
					t.Fatalf("permission=%v: calls %+v, want one %s call", permission, calls, tc.tool)
				}
				var got map[string]string
				if err := json.Unmarshal(calls[0].args, &got); err != nil || len(got) != len(tc.want) {
					t.Fatalf("permission=%v: args %s, want %v", permission, calls[0].args, tc.want)
				}
				for key, value := range tc.want {
					if got[key] != value {
						t.Errorf("permission=%v: %s = %q, want %q", permission, key, got[key], value)
					}
				}
			}
		})
	}
}
