// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The chain of candidates tests pin that a variable
// bound in a Boolean chain (a && x=v || x=w) and written through after white
// space padding past the 64 KiB command limit is judged as the unpadded
// command is (GAP-1003): a chain whose candidates are all ordinary stays
// allowed in the default and the strict profile, as its unpadded twin is, and
// a chain with a protected candidate still blocks, naming the rule of the
// protected file. Each hook route in each rule pack is four tests, a quarter
// of the rows each, so that no test is longer than the CI budget of one.
func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInCodexPart1(t *testing.T) {
	chainOfCandidates(t, "codex", "", 0)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInCodexPart2(t *testing.T) {
	chainOfCandidates(t, "codex", "", 1)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInCodexPart3(t *testing.T) {
	chainOfCandidates(t, "codex", "", 2)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInCodexPart4(t *testing.T) {
	chainOfCandidates(t, "codex", "", 3)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictCodexPart1(t *testing.T) {
	chainOfCandidates(t, "codex", "strict", 0)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictCodexPart2(t *testing.T) {
	chainOfCandidates(t, "codex", "strict", 1)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictCodexPart3(t *testing.T) {
	chainOfCandidates(t, "codex", "strict", 2)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictCodexPart4(t *testing.T) {
	chainOfCandidates(t, "codex", "strict", 3)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInClaudeCodePart1(t *testing.T) {
	chainOfCandidates(t, "claudecode", "", 0)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInClaudeCodePart2(t *testing.T) {
	chainOfCandidates(t, "claudecode", "", 1)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInClaudeCodePart3(t *testing.T) {
	chainOfCandidates(t, "claudecode", "", 2)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInClaudeCodePart4(t *testing.T) {
	chainOfCandidates(t, "claudecode", "", 3)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictClaudeCodePart1(t *testing.T) {
	chainOfCandidates(t, "claudecode", "strict", 0)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictClaudeCodePart2(t *testing.T) {
	chainOfCandidates(t, "claudecode", "strict", 1)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictClaudeCodePart3(t *testing.T) {
	chainOfCandidates(t, "claudecode", "strict", 2)
}

func TestOverLimitCommandChainOfCandidatesFollowsItsTwinInStrictClaudeCodePart4(t *testing.T) {
	chainOfCandidates(t, "claudecode", "strict", 3)
}

// chainOfCandidates judges a quarter (part of four) of the rows of a hook
// route in a rule pack.
func chainOfCandidates(t *testing.T, connector, rulePack string, part int) {
	home, project := hermesPatchHome(t)
	const lib = "/usr/local/lib/libreview.so"
	hook := func(connector, rulePack, command string) string {
		args := map[string]any{"cmd": command, "workdir": project}
		call := nativeWriteCall{connector, "exec_command", func(string) map[string]any { return args }}
		if connector == "claudecode" {
			call = nativeWriteCall{connector, "Bash", func(string) map[string]any {
				return map[string]any{"command": command}
			}}
		}
		body := call.body(t, project, project)
		return overLimitHostHookInPack(t, connector, rulePack, home, body,
			hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
	}
	benign := map[string]string{
		"two ordinary candidates":   "true && P=/tmp/ok1 || P=/tmp/ok2;%s echo hello >> $P",
		"project candidates":        "true && P=" + project + "/a.txt || P=" + project + "/b.txt;%s echo hello >> $P",
		"three ordinary candidates": "true && P=/tmp/ok1 || P=/tmp/ok2 || P=/tmp/ok3;%s echo hello >> $P",
		"and chain":                 "true && P=/tmp/ok1 && P=/tmp/ok2;%s echo hello >> $P",
		"or binding":                "false || P=/tmp/ok1;%s echo hello >> $P",
		"single binding":            "P=/tmp/ok1;%s echo hello >> $P",
	}
	attacks := map[string]string{
		"protected first candidate":  "true && P=/etc/ld.so.preload || P=/tmp/ok;%s echo " + lib + " >> $P",
		"protected second candidate": "true && P=/tmp/ok || P=/etc/ld.so.preload;%s echo " + lib + " >> $P",
		"protected or binding":       "false || P=/etc/ld.so.preload;%s echo " + lib + " >> $P",
	}
	// padFor is the white space that takes the command of format past the
	// bound named by pad: none, the command limit, or the limit of the
	// argument envelope.
	padFor := func(pad, format string) string {
		base := len(format) - len("%s")
		switch pad {
		case "command":
			return overLimitRun(" ", 0, base)
		case "arguments":
			return overLimitRun(" ", 1, base)
		}
		return ""
	}
	for name, format := range benign {
		for _, pad := range []string{"none", "command", "arguments"} {
			if !overLimitShare("benign/"+name+"/"+pad, part, 4) {
				continue
			}
			t.Run(fmt.Sprintf("benign/%s/%q/%s/pad %s", connector, rulePack, name, pad), func(t *testing.T) {
				t.Parallel()
				command := fmt.Sprintf(format, padFor(pad, format))
				if pad != "none" && !actionfacts.CommandTextOverLimit(command) {
					t.Fatalf("a command of %d bytes is not past the command limit", len(command))
				}
				got := hook(connector, rulePack, command)
				if overLimitHookAction(t, got) == "block" {
					t.Fatalf("ordinary command blocked: %.600s", got)
				}
			})
		}
	}
	for name, format := range attacks {
		for _, pad := range []string{"command", "arguments"} {
			if !overLimitShare("attack/"+name+"/"+pad, part, 4) {
				continue
			}
			t.Run(fmt.Sprintf("attack/%s/%q/%s/pad %s", connector, rulePack, name, pad), func(t *testing.T) {
				t.Parallel()
				command := fmt.Sprintf(format, padFor(pad, format))
				if pad != "none" && !actionfacts.CommandTextOverLimit(command) {
					t.Fatalf("a command of %d bytes is not past the command limit", len(command))
				}
				got := hook(connector, rulePack, command)
				if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
					t.Fatalf("not blocked by the preload rule: %.600s", got)
				}
			})
		}
	}
}
