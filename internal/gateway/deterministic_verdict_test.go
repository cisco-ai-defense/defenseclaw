// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestShellCapsAreDeterministicUnderLoad pins GAP-0339: the verdict of a
// shell call is a function of the call, the pack and the files it names,
// never of the load of the box. It runs each call 50 times in every tier with
// every CPU busy and expects one verdict. The calls are generated: a 4 KB
// list of loops over globs of a busy temp directory (the shape of the two
// owner-trace calls that flipped), and, when S7_FLIP_CASES names the file of
// the two calls extracted from the corpus by case id, those calls.
func TestShellCapsAreDeterministicUnderLoad(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	var commands []string
	var unit strings.Builder
	for unit.Len() < 4000 {
		fmt.Fprintf(&unit, "for f in /tmp/dc-flip-%d-*.log; do ls -l \"$f\" 2>/dev/null; done; ", unit.Len())
	}
	commands = append(commands, unit.String())
	if file := os.Getenv("S7_FLIP_CASES"); file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var cases []struct{ ID, Command string }
		if err := json.Unmarshal(raw, &cases); err != nil {
			t.Fatal(err)
		}
		for _, c := range cases {
			commands = append(commands, c.Command)
		}
	}
	home := filepath.Join(t.TempDir(), "alice")
	env := boundedEnv{home: home, cwd: filepath.Join(home, "project")}
	if err := os.MkdirAll(env.cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	var done atomic.Bool
	var wg sync.WaitGroup
	for range 2 * runtime.NumCPU() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; !done.Load(); n++ {
				_ = n * n
			}
		}()
	}
	defer func() { done.Store(true); wg.Wait() }()
	for _, tier := range boundedTestTiers {
		api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", tier.posture)
		for index, command := range commands {
			verdicts := map[string]int{}
			for range 50 {
				action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
				verdicts[action+" "+strings.Join(findings, "|")]++
			}
			if len(verdicts) != 1 {
				t.Errorf("%s: call %d (%d bytes) got %d different verdicts in 50 runs: %v", tier.name, index, len(command), len(verdicts), verdicts)
			}
		}
	}
}
