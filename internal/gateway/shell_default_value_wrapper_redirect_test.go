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

// TestShellDefaultValueAndWrapperWritesKeepTheirVerdict pins that a write of
// the loader-preload file is blocked when the shell names it through the
// default of an unset variable (P=${P:-FILE}, ${P-FILE}, or the default
// written in the redirect) and when the command that writes it runs behind
// command or builtin, which run the word they are given in the caller shell:
// in the default and the strict profile, unpadded and padded with white space
// past the 64 KiB command limit, for Codex and Claude Code (GAP-0934 twins
// EM31-01, FL31-02). The same shapes aimed at an ordinary file, and a read of
// the protected file, stay allowed.
func TestShellDefaultValueAndWrapperWritesKeepTheirVerdict(t *testing.T) {
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
	attacks := map[string]string{
		"default with colon":      "P=${P:-/etc/ld.so.preload};%s echo " + lib + " >> $P",
		"default without colon":   "P=${P-/etc/ld.so.preload};%s echo " + lib + " >> $P",
		"quoted default":          "P=${P:-\"/etc/ld.so.preload\"};%s echo " + lib + " >> \"$P\"",
		"default in the redirect": "echo " + lib + " >> ${P:-/etc/ld.so.preload}%s",
		"default then command":    "P=${P:-/etc/ld.so.preload};%s command echo " + lib + " >> $P",
		"default then builtin":    "P=${P:-/etc/ld.so.preload};%s builtin -- echo " + lib + " >> $P",
		"command wrapper":         "%s command echo " + lib + " >> /etc/ld.so.preload",
		"command option wrapper":  "%s command -p echo " + lib + " >> /etc/ld.so.preload",
		"builtin wrapper":         "%s builtin echo " + lib + " >> /etc/ld.so.preload",
		"builtin double dash":     "%s builtin -- echo " + lib + " >> /etc/ld.so.preload",
		"command then builtin":    "%s command builtin echo " + lib + " >> /etc/ld.so.preload",
		"bound path then command": "P=/etc/ld.so.preload;%s command echo " + lib + " >> $P",
		"bound path then builtin": "P=/etc/ld.so.preload;%s builtin echo " + lib + " >> $P",
		"wrapped producer to tee": "command echo " + lib + " |%s tee -a /etc/ld.so.preload",
		"producer to wrapped tee": "echo " + lib + " |%s command tee -a /etc/ld.so.preload",
	}
	benign := map[string]string{
		"ordinary default":             "P=${P:-/tmp/ok.txt};%s echo hello >> $P",
		"ordinary default in redirect": "echo hello >> ${P:-/tmp/ok.txt}%s",
		"bound value beats default":    "P=/tmp/ok.txt;%s echo hello >> ${P:-/etc/ld.so.preload}",
		"ordinary command wrapper":     "%s command echo hello >> /tmp/ok.txt",
		"ordinary builtin wrapper":     "%s builtin echo hello >> /tmp/ok.txt",
		"protected default is read":    "P=${P:-/etc/ld.so.preload};%s cat $P",
		"wrapped read":                 "%s command cat /etc/ld.so.preload",
		"builtin directory change":     "%s builtin cd /tmp && echo hello > ok.txt",
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, rulePack := range []string{"", "strict"} {
			for _, pad := range []int{0, 70000, 300000} {
				for name, format := range attacks {
					t.Run(fmt.Sprintf("attack/%s/%q/%s/pad %d", connector, rulePack, name, pad), func(t *testing.T) {
						got := hook(connector, rulePack, fmt.Sprintf(format, strings.Repeat(" ", pad)))
						if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
							t.Fatalf("not blocked by the preload rule: %.600s", got)
						}
					})
				}
				for name, format := range benign {
					t.Run(fmt.Sprintf("benign/%s/%q/%s/pad %d", connector, rulePack, name, pad), func(t *testing.T) {
						got := hook(connector, rulePack, fmt.Sprintf(format, strings.Repeat(" ", pad)))
						if overLimitHookAction(t, got) == "block" {
							t.Fatalf("ordinary command blocked: %.600s", got)
						}
					})
				}
			}
		}
	}
}
