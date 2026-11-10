// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestOverLimitCommandChainOfCandidatesFollowsItsTwin pins that a variable
// bound in a Boolean chain (a && x=v || x=w) and written through after white
// space padding past the 64 KiB command limit is judged as the unpadded
// command is (GAP-1003): a chain whose candidates are all ordinary stays
// allowed in the default and the strict profile, as its unpadded twin is, and
// a chain with a protected candidate still blocks, naming the rule of the
// protected file.
func TestOverLimitCommandChainOfCandidatesFollowsItsTwin(t *testing.T) {
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
	for _, connector := range []string{"codex", "claudecode"} {
		for _, rulePack := range []string{"", "strict"} {
			for name, format := range benign {
				for _, pad := range []int{0, 70000, 300000} {
					t.Run(fmt.Sprintf("benign/%s/%q/%s/pad %d", connector, rulePack, name, pad), func(t *testing.T) {
						got := hook(connector, rulePack, fmt.Sprintf(format, strings.Repeat(" ", pad)))
						if overLimitHookAction(t, got) == "block" {
							t.Fatalf("ordinary command blocked: %.600s", got)
						}
					})
				}
			}
			for name, format := range attacks {
				for _, pad := range []int{70000, 300000} {
					t.Run(fmt.Sprintf("attack/%s/%q/%s/pad %d", connector, rulePack, name, pad), func(t *testing.T) {
						got := hook(connector, rulePack, fmt.Sprintf(format, strings.Repeat(" ", pad)))
						if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
							t.Fatalf("not blocked by the preload rule: %.600s", got)
						}
					})
				}
			}
		}
	}
}
