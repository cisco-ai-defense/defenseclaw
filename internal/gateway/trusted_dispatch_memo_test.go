package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestTrustedDispatchMemoKeyCoversEveryField: every field of a request that
// refers to state is compared by value or by identity, is a pure cache, an
// out-parameter the memo replays, or a recorder that turns the memo off
// (trustedDispatchMemo). A new such field must be placed here first.
// ShellStartup is a value: the key keeps the pointer and reflect.DeepEqual
// compares the startup it points at (GAP-1296's client header). So are a
// Substrate actor's home places (homePlaceSet, substrate-1 GAP-0758).
// guestWriteClaimOnly and guestByNameOnly are out-parameters the memo does
// not replay: a request that asks for either is judged without the memo
// (TestTrustedDispatchMemoOffFieldsSkipTheMemo, substrate-1 GAP-1048).
func TestTrustedDispatchMemoKeyCoversEveryField(t *testing.T) {
	placed := map[string]string{
		"conflictSource": "value", "parentPatch": "value",
		"ResolvedWriteTargets": "value", "ActiveAgentFileIdentities": "value", "ShellStartup": "value",
		"guestClaimHomePlaces": "value", "guestHomePlaces": "value",
		"budget": "identity", "capFloor": "identity", "generation": "identity", "targetMemo": "identity",
		"windowsTwinHosts": "identity", "windowsPowerShellReading": "identity",
		"simpleMemo": "cache", "guestMemo": "cache",
		"overBudgetOmission": "out", "unresolvedTarget": "out", "resolvedTarget": "out",
		"nonWriteMention": "out", "unprovenTarget": "out", "unknownMention": "out",
		"record": "recorder", "recordTelemetry": "recorder", "recordEffectShadow": "recorder",
		"guestWriteClaimOnly": "off", "guestByNameOnly": "off",
	}
	rt := reflect.TypeOf(trustedActionRequest{})
	for i := range rt.NumField() {
		field := rt.Field(i)
		switch field.Type.Kind() {
		case reflect.Pointer, reflect.Func, reflect.Map, reflect.Chan, reflect.Interface, reflect.Slice, reflect.UnsafePointer:
			if placed[field.Name] == "" {
				t.Errorf("trustedActionRequest.%s (%s) is not placed in the dispatch memo key", field.Name, field.Type)
			}
		}
	}
}

// trustedDispatchMemoRows is the corpus of TestTrustedDispatchMemoSameAnswer:
// the FiveTiers rows (defenseclaw_control.jsonl) and the trusted tool-call
// corpus.
func trustedDispatchMemoRows(t *testing.T) (tiers, toolcalls []string) {
	t.Helper()
	read := func(path string, take func([]byte)) {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		for scanner.Scan() {
			if line := scanner.Bytes(); len(line) > 0 && line[0] == '{' {
				take(line)
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatal(err)
		}
	}
	read("../actionfacts/testdata/defenseclaw_control.jsonl", func(line []byte) {
		var row struct{ Dialect, Command string }
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.Dialect == "" {
			tiers = append(tiers, row.Command)
		}
	})
	read("testdata/security_suite/toolcall/corpus.jsonl", func(line []byte) {
		var row struct{ Command string }
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.Command != "" {
			toolcalls = append(toolcalls, row.Command)
		}
	})
	return tiers, toolcalls
}

// TestTrustedDispatchMemoSameAnswer: the dispatch memo changes no answer. Each
// call of the corpus is judged with the memo on and off, in every pack, with
// no deadline, and the two answers are byte for byte the same; then again
// with a semantic budget small enough that rules are refused for it, so the
// budget a repeat charges is checked too (rel-1-0-10:GAP-1472). The race
// build judges every seventh call.
func TestTrustedDispatchMemoSameAnswer(t *testing.T) {
	tiers, toolcalls := trustedDispatchMemoRows(t)
	step := 1
	if hookAnswerRaceBuild {
		step = 7
	}
	answer := func(a *APIServer, dir, command string, off bool) string {
		trustedDispatchMemoOff.Store(off)
		defer trustedDispatchMemoOff.Store(false)
		raw, _ := json.Marshal(gap0437Inspect(t, a, dir, command))
		return string(raw)
	}
	compare := func(t *testing.T, a *APIServer, where string, commands []string) {
		for i := 0; i < len(commands); i += step {
			dir := t.TempDir()
			on, off := answer(a, dir, commands[i], false), answer(a, dir, commands[i], true)
			if on != off {
				t.Errorf("%s %q: the memo changed the answer\n on: %s\noff: %s", where, commands[i], on, off)
			}
		}
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		a.inspectToolScanTimeout = 10 * time.Minute
		warmDefenseClawControl(t, a.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
			"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": "ls", "workdir": t.TempDir()},
		})
		compare(t, a, p.name+" tiers", tiers)
		if p.name != "default" && p.name != "strict" {
			continue
		}
		compare(t, a, p.name+" toolcalls", toolcalls)
	}
}

// TestTrustedDispatchMemoChargesTheBudget: a repeat the memo answers charges
// the shared budget what its first run charged, so the budget is spent as it
// is without the memo; a repeat the budget has no room for is judged again,
// and is refused for the budget as it is without the memo.
func TestTrustedDispatchMemoChargesTheBudget(t *testing.T) {
	gap0437Server(t, gap0437Packs[1], "openclaw", "action")
	dir := t.TempDir()
	command := "sudo tee /etc/cron.d/x <<< 'defenseclaw-gateway stop'"
	judge := func(off bool, maxCost uint64) (uint64, bool, string) {
		trustedDispatchMemoOff.Store(off)
		defer trustedDispatchMemoOff.Store(false)
		if maxCost > 0 {
			previous := trustedActionDispatchMaxCost
			trustedActionDispatchMaxCost = maxCost
			defer func() { trustedActionDispatchMaxCost = previous }()
		}
		budget := newTrustedActionBudget(false)
		request := trustedActionRequest{
			Input:      actionfacts.Input{Tool: "exec", Command: command, CWD: dir},
			LegacyText: command, Connector: "openclaw", EnforcementCapable: true, StrictPolicy: true, budget: budget,
		}
		ctx := context.WithValue(context.Background(), trustedDispatchMemoKey{}, &trustedDispatchMemo{})
		first := dispatchTrustedAction(ctx, request)
		second := dispatchTrustedAction(ctx, request)
		raw, _ := json.Marshal([][]RuleFinding{first, second})
		return budget.consumed, budget.reached, string(raw)
	}
	onCost, onReached, on := judge(false, 0)
	offCost, offReached, off := judge(true, 0)
	if onCost == 0 || onReached {
		t.Fatalf("the call charged %d (reached %v); the test needs a call that spends the budget within it", onCost, onReached)
	}
	if onCost != offCost || onReached != offReached || on != off {
		t.Fatalf("memo on: cost %d reached %v %s\nmemo off: cost %d reached %v %s", onCost, onReached, on, offCost, offReached, off)
	}
	// Room for one run and a half: the repeat is refused for the budget.
	limit := onCost/2 + onCost/4
	onCost, onReached, on = judge(false, limit)
	offCost, offReached, off = judge(true, limit)
	if !offReached {
		t.Fatalf("a budget of %d was not reached by two runs (cost %d)", limit, offCost)
	}
	if onCost != offCost || onReached != offReached || on != off {
		t.Fatalf("budget %d: memo on: cost %d reached %v %s\nmemo off: cost %d reached %v %s", limit, onCost, onReached, on, offCost, offReached, off)
	}
}

// TestTrustedDispatchMemoOffFieldsSkipTheMemo: a request that asks for an
// out-parameter the memo does not replay (the "off" fields of
// TestTrustedDispatchMemoKeyCoversEveryField) is judged without the memo. A
// stored answer for the very same key is not replayed, so the run still
// tells the out-parameter (the GAP-1022 by-name gate reads guestByNameOnly),
// and the run is not stored for a later repeat (substrate-1 GAP-1048).
func TestTrustedDispatchMemoOffFieldsSkipTheMemo(t *testing.T) {
	gap0437Server(t, gap0437Packs[1], "openclaw", "action")
	dir := t.TempDir()
	command := "sudo tee /etc/cron.d/x <<< 'defenseclaw-gateway stop'"
	for _, name := range []string{"guestWriteClaimOnly", "guestByNameOnly"} {
		t.Run(name, func(t *testing.T) {
			asked := false
			request := trustedActionRequest{
				Input:      actionfacts.Input{Tool: "exec", Command: command, CWD: dir},
				LegacyText: command, Connector: "openclaw", EnforcementCapable: true, StrictPolicy: true,
				budget: newTrustedActionBudget(false),
			}
			switch name {
			case "guestWriteClaimOnly":
				request.guestWriteClaimOnly = &asked
			case "guestByNameOnly":
				request.guestByNameOnly = &asked
			}
			memo := &trustedDispatchMemo{}
			ctx := context.WithValue(context.Background(), trustedDispatchMemoKey{}, memo)
			bucket := request.Input.Tool + "\x00" + request.Input.Command + "\x00" + request.LegacyText
			key, refs := trustedDispatchMemoKeyOf(request)
			state := trustedDispatchStateOf(request)
			poison := []RuleFinding{{RuleID: "GAP-1048-STALE-REPLAY"}}
			memo.store(bucket, &trustedDispatchMemoEntry{ctx: ctx, key: key, refs: refs, state: state, findings: poison})
			if memo.lookup(ctx, bucket, key, refs, state) == nil {
				t.Fatal("the seeded answer is not found for its own key; the test proves nothing")
			}
			got := memo.dispatch(ctx, request)
			for _, finding := range got {
				if finding.RuleID == poison[0].RuleID {
					t.Fatalf("a request that asks for %s was answered from the memo: %v", name, got)
				}
			}
			if n := len(memo.entries[bucket]); n != 1 {
				t.Fatalf("a request that asks for %s was stored in the memo (%d entries)", name, n)
			}
			want := dispatchTrustedActionOnce(context.Background(), trustedActionRequest{
				Input:      actionfacts.Input{Tool: "exec", Command: command, CWD: dir},
				LegacyText: command, Connector: "openclaw", EnforcementCapable: true, StrictPolicy: true,
				budget: newTrustedActionBudget(false),
			})
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Fatalf("%s: through the memo %s, alone %s", name, gotJSON, wantJSON)
			}
		})
	}
}
