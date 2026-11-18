// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// substrate-1 GAP-0577 (RVNF2 F5): an actor's MultiEdit of its registered
// ~/.claude/settings.json whose edits apply to no synthetic copy was judged
// in time that grows with the square of the edits (4,000 edits took 31 s, so
// one call near the 1 MiB body cap held a gateway core for minutes). Past 64
// edits or 64 KB of edit text the call is refused at once, never allowed;
// at the bound it keeps the laptop's verdict.
func TestGAP0577ActorMultiEditBound(t *testing.T) {
	call := func(count int) (ruleID, note string, took time.Duration) {
		edits := make([]any, count)
		for index := range edits {
			if count == 64 {
				edits[index] = map[string]any{"old_string": `"timeout":30`, "new_string": `"timeout":30`}
				continue
			}
			key := fmt.Sprintf(`"k%05d":`, index)
			edits[index] = map[string]any{"old_string": key + "1", "new_string": key + "2"}
		}
		args, err := json.Marshal(map[string]any{"file_path": "~/.claude/settings.json", "edits": edits})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		ruleID, note, _ = sandboxAgentHookConfigChange(context.Background(), trustedActionRequest{
			Connector: "claudecode",
			Input:     actionfacts.Input{Tool: "MultiEdit", Args: args, ActiveHome: "/sandbox", CWD: "/sandbox/work"},
		})
		return ruleID, note, time.Since(start)
	}
	for _, count := range []int{65, 4000, 20000} {
		ruleID, note, took := call(count)
		if ruleID != agentHookConfigDisableRuleID || !strings.Contains(note, "split them") {
			t.Errorf("%d edits: rule %q note %q, want %s with the split note", count, ruleID, note, agentHookConfigDisableRuleID)
		}
		if took > 2*time.Second {
			t.Errorf("%d edits took %v, want the bound to refuse them at once", count, took)
		}
	}
	if ruleID, note, took := call(64); ruleID != "" || took > 2*time.Second {
		t.Errorf("64 member edits: rule %q note %q in %v, want the laptop's allow at once", ruleID, note, took)
	}
}

// RVNF5 F5: applicable edits must not bypass limits, and exponential
// replace_all expansion must be refused BEFORE allocating the next document.
func TestGAP0577SemanticWorkBounds(t *testing.T) {
	base := []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"defenseclaw-hook"}]}]},"model":"ZZ"}`)
	for _, n := range []int{65, 4000} {
		edits := make([]agentHookConfigTextEdit, n)
		for i := range edits {
			edits[i] = agentHookConfigTextEdit{old: "ZZ", new: "ZZ"}
		}
		reason, _ := sandboxAgentHookRegisteredChange(context.Background(), gatewayconnector.AgentHookConfigClaudeSettings, agentHookConfigChange{edits: edits}, [][]byte{base})
		if reason == "" {
			t.Fatalf("%d applicable edits were allowed", n)
		}
	}
	for _, n := range []int{65536, 65537, 131072} {
		reason, _ := sandboxAgentHookRegisteredChange(context.Background(), gatewayconnector.AgentHookConfigClaudeSettings, agentHookConfigChange{edits: []agentHookConfigTextEdit{{old: "ZZ", new: strings.Repeat("x", n)}}}, [][]byte{base})
		if reason == "" {
			t.Fatalf("%d text bytes were allowed", n)
		}
	}
	document := base
	for i := 0; i < 32; i++ {
		after, ok, over := sandboxAgentHookApplyEdit(document, agentHookConfigTextEdit{old: "ZZ", new: "ZZZZ", all: true})
		if over {
			if len(after) != 0 {
				t.Fatal("allocated an oversized result")
			}
			break
		}
		if !ok || i == 31 {
			t.Fatalf("expansion was not bounded at step %d", i)
		}
		document = after
	}
	// Overflow-resistant size arithmetic for many small matches.
	if out, _, over := sandboxAgentHookApplyEdit([]byte(strings.Repeat("a", 65536)), agentHookConfigTextEdit{old: "a", new: strings.Repeat("x", 65536), all: true}); !over || len(out) != 0 {
		t.Fatal("unbounded replace_all product")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reason, _ := sandboxAgentHookRegisteredChange(ctx, gatewayconnector.AgentHookConfigClaudeSettings, agentHookConfigChange{edits: []agentHookConfigTextEdit{{old: "ZZ", new: "YY"}}}, [][]byte{base})
	if !strings.Contains(reason, "canceled") {
		t.Fatalf("cancellation ignored: %s", reason)
	}
}

func TestGAP0577BeforeFactsFailClosed(t *testing.T) {
	target := "/sandbox/.claude/settings.json"
	body := []byte(`{"model":"zzz"}`)
	sum := sha256.Sum256(body)
	valid := SubstrateAttachedFile{Role: "agent_hook_config_before", Path: target, Content: body, Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	for _, kind := range []string{"valid", "truncated", "size", "digest", "duplicate"} {
		file := valid
		switch kind {
		case "truncated":
			file.Truncated = true
		case "size":
			file.Size++
		case "digest":
			file.SHA256 = ""
		}
		files := []SubstrateAttachedFile{file}
		if kind == "duplicate" {
			files = append(files, valid)
		}
		ctx := context.WithValue(context.Background(), substrateEnvelopeKey{}, substrateEnvelope{Facts: &SubstrateFacts{Files: files}})
		got, present := sandboxAgentHookBefore(ctx, target)
		if !present || (kind == "valid") != (len(got) > 0) {
			t.Fatalf("%s accepted invalid facts: %q %v", kind, got, present)
		}
	}
}
