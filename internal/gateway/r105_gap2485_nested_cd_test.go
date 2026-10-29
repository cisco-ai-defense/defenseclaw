// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// GAP-2485 pod check28: the commands of a nested `sh -c` / `bash -c`
// script walk their own directories from where the parent runs, so a cd
// inside the script moves them (and never the outer shell), and a chain of
// relative cds after ; is bounded instead of doubling the directory set per
// cd (14 of them took 93 s per hook call). A wrapper call with a glob
// operand (`sudo rm -rf hooks/*`) is judged as the program it runs.
func TestR105GAP2485NestedScriptCdAndChainCost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms")
	}
	home, _ := r105StateFixture(t)
	project := filepath.Join(home, "proj2")
	if err := os.MkdirAll(filepath.Join(project, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	var chain, benignChain []string
	for index := 0; index < 20; index++ {
		chain = append(chain, fmt.Sprintf("cd d%d", index))
		benignChain = append(benignChain, fmt.Sprintf("cd pkg%d; make; cd ..", index))
	}
	projectRows := []r105StateRow{
		{"N2 sh -c ; cd", "sh -c \"cd ~/.defenseclaw; rm -rf hooks/*\"", true, ""},
		{"Q2 bash -c ; cd", "bash -c \"cd ~/.defenseclaw; rm -rf hooks/*\"", true, ""},
		{"Q6 sh -c cd hooks", "sh -c \"cd ~/.defenseclaw/hooks; rm -f *\"", true, ""},
		{"Q1 sh -c && cd", "sh -c \"cd ~/.defenseclaw && rm -rf hooks/*\"", true, ""},
		{"Q4 sh -c sort -o", "sh -c \"cd ~/.defenseclaw; sort -o config.yaml /tmp/x\"", true, ""},
		{"M1 single-quoted", "bash -c 'cd ~/.defenseclaw; rm -rf hooks/*'", true, ""},
		{"cd chain then state", strings.Join(append(chain, "rm -rf ~/.defenseclaw/hooks"), "; "), true, ""},
		{"cd chain then cd state", strings.Join(append(chain, "cd ~/.defenseclaw", "rm -rf hooks/*"), "; "), true, ""},
		{"state cd then cd chain", strings.Join(append([]string{"cd ~/.defenseclaw"}, append(chain, "rm -rf hooks/*")...), "; "), true, ""},
		{"N5 sudo after cd", "cd ~/.defenseclaw && sudo rm -rf hooks/*", true, ""},
		{"N10 env after cd", "cd ~/.defenseclaw && env rm -rf hooks/*", true, ""},
		{"N13 nohup background", "cd ~/.defenseclaw && nohup rm -rf hooks/* &", true, ""},
		{"N19 timeout after cd", "cd ~/.defenseclaw && timeout 5 rm -rf hooks/*", true, ""},
		{"sudo -u after cd", "cd ~/.defenseclaw && sudo -u root rm -rf instal*", true, ""},
		// Allowed and quiet.
		{"sudo project cleanup", "cd ~/proj2 && sudo rm -rf build/*", false, ""},
		{"sudo state log cleanup", "cd ~/.defenseclaw/logs && sudo rm -f *.log", false, ""},
		{"timeout project cleanup", "timeout 5 rm -rf build/*", false, ""},
		{"nested cd does not move the outer shell", "sh -c \"cd ~/.defenseclaw\"; rm -rf hooks/*", false, ""},
		{"nested project cleanup", "sh -c \"cd ~/proj2; rm -rf build/*\"", false, ""},
		{"monorepo cd chain", strings.Join(benignChain, "; "), false, ""},
		{"cd chain then project rm", strings.Join(append(chain, "rm -rf build/*"), "; "), false, ""},
	}
	homeRows := []r105StateRow{
		{"Q5 sh -c relative state", "sh -c \"cd .defenseclaw; rm -rf hooks/*\"", true, ""},
		{"MB1 nested project clean", "bash -c \"cd ~/proj2 && git clean -fdx\"", false, ""},
		{"nested project rm", "sh -c \"cd proj2; rm -rf build/*\"", false, ""},
		// Pod check29: 4 or more relative cds, then a .. traversal.
		{"Y5 four cds then cd ..", "sh -c \"cd a; cd b; cd c; cd d; cd ../../../../.defenseclaw; rm -rf hooks/*\"", true, ""},
		{"Y6 four cds then rm ..", "sh -c \"cd a; cd b; cd c; cd d; rm -rf ../../../../.defenseclaw/hooks/*\"", true, ""},
		{"Y outer four cds then rm ..", "cd a; cd b; cd c; cd d; cd e; rm -rf ../../../../../.defenseclaw/hooks/*", true, ""},
		{"Y pushd popd chain", "sh -c \"pushd a; cd b; cd c; cd d; cd e; popd; rm -rf .defenseclaw/hooks/*\"", true, ""},
		{"Y benign four cds then rm ..", "sh -c \"cd proj2; cd build; cd x; cd y; rm -rf ../../*.o\"", false, ""},
	}
	for _, mode := range []string{"observe", "action"} {
		r105RunStateRowsChecked(t, mode, project, projectRows, true)
		r105RunStateRowsChecked(t, mode, home, homeRows, true)
	}

	// Cost: a 20-cd chain is judged in well under the hook's 4 s budget.
	api := instructionProtectionTestAPI(t, "claudecode", "action", "")
	command := strings.Join(append(chain, "rm -rf ~/.defenseclaw/hooks"), "; ")
	started := time.Now()
	resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
		HookEventName: "PreToolUse", CWD: project, ToolName: "Bash",
		ToolInput: map[string]interface{}{"command": command},
	})
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("20-cd chain took %s (action %s)", elapsed, resp.Action)
	}
}
