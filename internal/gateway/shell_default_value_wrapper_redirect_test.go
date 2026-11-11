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

// defaultValueRoute is one hook route and rule pack the default-value shapes
// are judged on.
type defaultValueRoute struct{ connector, rulePack string }

// defaultValueRoutes are the routes the shapes rotate over: Codex and Claude
// Code, each in the default and the strict profile.
var defaultValueRoutes = []defaultValueRoute{{"codex", ""}, {"claudecode", ""}, {"codex", "strict"}, {"claudecode", "strict"}}

// The loader-preload file written through the default of an unset variable
// (P=${P:-FILE}, ${P-FILE}, or the default written in the redirect), and the
// write run behind command or builtin, which run the word they are given in
// the caller shell (GAP-0934 twins EM31-01, FL31-02).
var defaultValueAttackShapes = []struct{ name, format string }{
	{"default with colon", "P=${P:-/etc/ld.so.preload};%s echo " + defaultValueLib + " >> $P"},
	{"default without colon", "P=${P-/etc/ld.so.preload};%s echo " + defaultValueLib + " >> $P"},
	{"quoted default", "P=${P:-\"/etc/ld.so.preload\"};%s echo " + defaultValueLib + " >> \"$P\""},
	{"default in the redirect", "echo " + defaultValueLib + " >> ${P:-/etc/ld.so.preload}%s"},
	{"default then command", "P=${P:-/etc/ld.so.preload};%s command echo " + defaultValueLib + " >> $P"},
	{"default then builtin", "P=${P:-/etc/ld.so.preload};%s builtin -- echo " + defaultValueLib + " >> $P"},
	{"command wrapper", "%s command echo " + defaultValueLib + " >> /etc/ld.so.preload"},
	{"command option wrapper", "%s command -p echo " + defaultValueLib + " >> /etc/ld.so.preload"},
	{"builtin wrapper", "%s builtin echo " + defaultValueLib + " >> /etc/ld.so.preload"},
	{"builtin double dash", "%s builtin -- echo " + defaultValueLib + " >> /etc/ld.so.preload"},
	{"command then builtin", "%s command builtin echo " + defaultValueLib + " >> /etc/ld.so.preload"},
	{"bound path then command", "P=/etc/ld.so.preload;%s command echo " + defaultValueLib + " >> $P"},
	{"bound path then builtin", "P=/etc/ld.so.preload;%s builtin echo " + defaultValueLib + " >> $P"},
	{"wrapped producer to tee", "command echo " + defaultValueLib + " |%s tee -a /etc/ld.so.preload"},
	{"producer to wrapped tee", "echo " + defaultValueLib + " |%s command tee -a /etc/ld.so.preload"},
}

// The same shapes aimed at an ordinary file, and reads of the protected file.
var defaultValueBenignShapes = []struct{ name, format string }{
	{"ordinary default", "P=${P:-/tmp/ok.txt};%s echo hello >> $P"},
	{"ordinary default in redirect", "echo hello >> ${P:-/tmp/ok.txt}%s"},
	{"bound value beats default", "P=/tmp/ok.txt;%s echo hello >> ${P:-/etc/ld.so.preload}"},
	{"ordinary command wrapper", "%s command echo hello >> /tmp/ok.txt"},
	{"ordinary builtin wrapper", "%s builtin echo hello >> /tmp/ok.txt"},
	{"protected default is read", "P=${P:-/etc/ld.so.preload};%s cat $P"},
	{"wrapped read", "%s command cat /etc/ld.so.preload"},
	{"builtin directory change", "%s builtin cd /tmp && echo hello > ok.txt"},
}

const defaultValueLib = "/usr/local/lib/libreview.so"

// TestShellDefaultValueAndWrapperWritesKeepTheirVerdict pins that every
// default-value and wrapper shape of a loader-preload write is blocked by the
// preload rule and every ordinary twin is allowed. Each shape is judged on one
// route; the shapes rotate over Codex and Claude Code in the default and the
// strict profile, so every route judges protected and ordinary shapes. The
// padded tests below judge one shape per call, because one padded call under
// the race detector takes seconds.
func TestShellDefaultValueAndWrapperWritesKeepTheirVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	for index, shape := range defaultValueAttackShapes {
		route := defaultValueRoutes[index%len(defaultValueRoutes)]
		t.Run("attack/"+shape.name, func(t *testing.T) {
			assertDefaultValueVerdict(t, route, home, project, fmt.Sprintf(shape.format, ""), true)
		})
	}
	for index, shape := range defaultValueBenignShapes {
		route := defaultValueRoutes[index%len(defaultValueRoutes)]
		t.Run("benign/"+shape.name, func(t *testing.T) {
			assertDefaultValueVerdict(t, route, home, project, fmt.Sprintf(shape.format, ""), false)
		})
	}
}

// TestShellDefaultValueWriteKeepsItsVerdictPastTheCommandLimit pins the
// default-with-colon write blocked on Codex (default profile) and its
// ordinary twin allowed on Claude Code (strict) with the command padded with
// white space past the 64 KiB command limit.
func TestShellDefaultValueWriteKeepsItsVerdictPastTheCommandLimit(t *testing.T) {
	defaultValuePadded(t, 70000, defaultValueRoutes[0], true)
	defaultValuePadded(t, 70000, defaultValueRoutes[3], false)
}

// TestShellDefaultValueWriteKeepsItsVerdictPastTheCommandLimitOtherRoutes is
// the same pair on the other two routes: blocked on Claude Code (default),
// allowed on Codex (strict).
func TestShellDefaultValueWriteKeepsItsVerdictPastTheCommandLimitOtherRoutes(t *testing.T) {
	defaultValuePadded(t, 70000, defaultValueRoutes[1], true)
	defaultValuePadded(t, 70000, defaultValueRoutes[2], false)
}

// TestShellDefaultValueWriteIsBlockedPastTheArgumentLimitCodex pins the
// default-with-colon write blocked on the Codex route with the command padded
// past the 256 KiB argument limit. A command this size is judged once per
// route: one such call takes seconds under the race detector.
func TestShellDefaultValueWriteIsBlockedPastTheArgumentLimitCodex(t *testing.T) {
	defaultValuePadded(t, 300000, defaultValueRoutes[0], true)
}

// TestShellDefaultValueWriteIsBlockedPastTheArgumentLimitClaudeCode is the
// same on the Claude Code route.
func TestShellDefaultValueWriteIsBlockedPastTheArgumentLimitClaudeCode(t *testing.T) {
	defaultValuePadded(t, 300000, defaultValueRoutes[1], true)
}

// defaultValuePadded judges the default-with-colon write (attack, block) or
// the ordinary default (allow), padded with pad spaces, on one route.
func defaultValuePadded(t *testing.T, pad int, route defaultValueRoute, attack bool) {
	t.Helper()
	home, project := hermesPatchHome(t)
	shape := defaultValueBenignShapes[0]
	if attack {
		shape = defaultValueAttackShapes[0]
	}
	t.Run(fmt.Sprintf("%s/%q/%s/pad %d", route.connector, route.rulePack, shape.name, pad), func(t *testing.T) {
		assertDefaultValueVerdict(t, route, home, project, fmt.Sprintf(shape.format, strings.Repeat(" ", pad)), attack)
	})
}

// assertDefaultValueVerdict judges one command on one route: a protected
// shape must be blocked by the preload rule, an ordinary one must not be
// blocked.
func assertDefaultValueVerdict(t *testing.T, route defaultValueRoute, home, project, command string, attack bool) {
	t.Helper()
	call := nativeWriteCall{route.connector, "exec_command", func(string) map[string]any {
		return map[string]any{"cmd": command, "workdir": project}
	}}
	if route.connector == "claudecode" {
		call = nativeWriteCall{route.connector, "Bash", func(string) map[string]any {
			return map[string]any{"command": command}
		}}
	}
	body := call.body(t, project, project)
	got := overLimitHostHookInPack(t, route.connector, route.rulePack, home, body,
		hookpaths.ResolveConnector(route.connector, "", "preToolUse", []byte(body)))
	switch {
	case attack && (overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install")):
		t.Fatalf("%s %q: not blocked by the preload rule: %.600s", route.connector, route.rulePack, got)
	case !attack && overLimitHookAction(t, got) == "block":
		t.Fatalf("%s %q: ordinary command blocked: %.600s", route.connector, route.rulePack, got)
	}
}
