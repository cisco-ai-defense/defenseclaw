// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
			key := fmt.Sprintf(`"k%05d":`, index)
			edits[index] = map[string]any{"old_string": key + "1", "new_string": key + "2"}
		}
		args, err := json.Marshal(map[string]any{"file_path": "~/.claude/settings.json", "edits": edits})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		ruleID, note, _ = sandboxAgentHookConfigChange(trustedActionRequest{
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
