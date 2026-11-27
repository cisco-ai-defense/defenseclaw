// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// withoutOrdinaryChrootStateFinding removes a state-write finding only when
// the complete child script proves every write is an ordinary redirect under
// a literal chroot root. Opaque bodies, dynamic roots and protected targets
// keep the whole call's existing findings.
func withoutOrdinaryChrootStateFinding(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == stateWriteRuleID }) ||
		!ordinaryChrootBodyWrites(request) {
		return findings
	}
	return slices.DeleteFunc(slices.Clone(findings), func(f RuleFinding) bool {
		return f.RuleID == stateWriteRuleID
	})
}

func ordinaryChrootBodyWrites(request trustedActionRequest) bool {
	input := request.Input
	command, known := trustedBashCommandInput(input)
	if !known || input.ActiveHome == "" || input.WindowsHookHost || runtime.GOOS == "windows" ||
		input.DialectHint == actionfacts.DialectPowerShell || input.DialectHint == actionfacts.DialectCMD {
		return false
	}
	input.Tool, input.Command, input.Args, input.Argv = "shell", command, nil, nil
	outer := actionfacts.Analyze(input)
	if len(outer.Commands) != 1 || outer.Parse.Dialect != actionfacts.DialectPOSIX {
		return false
	}
	call := outer.Commands[0]
	if !call.ArgvComplete || call.Program != "chroot" || len(call.Argv) < 3 ||
		call.Argv[0] != "chroot" || call.Argv[2] != "sh" ||
		len(call.Arguments) != len(call.Argv) || len(call.Redirects) != 0 ||
		len(outer.Paths) != 1 || outer.Paths[0].Access != actionfacts.PathAccessRead {
		return false
	}
	root := call.Argv[1]
	// A different literal root may be a link to a protected folder. Keep
	// its current verdict until the hook can prove its physical root.
	if call.Arguments[1].Expands || root != "/" {
		return false
	}
	home := filepath.Clean(input.ActiveHome)
	if root == home || strings.HasPrefix(root, home+string(filepath.Separator)) ||
		root == filepath.Join(home, ".defenseclaw") {
		return false
	}
	var body string
	switch {
	case len(call.Argv) == 3 && call.LiteralStdinComplete && !call.LiteralStdinAmbiguous:
		body = call.LiteralStdin
	case len(call.Argv) == 5 && call.Argv[3] == "-c" && !call.Arguments[4].Expands:
		body = call.Argv[4]
	default:
		return false
	}
	if body == "" || len(body) > 4096 {
		return false
	}
	child := actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: body, CWD: root, ActiveHome: input.ActiveHome,
		DialectHint: actionfacts.DialectPOSIX,
	})
	if child.Parse.Status != actionfacts.StatusComplete || !child.Authoritative() ||
		!child.EnforcementEligible() || len(child.Commands) == 0 || len(child.Commands) > 4 ||
		len(child.Paths) == 0 || len(child.Paths) > 4 {
		return false
	}
	redirects := 0
	for _, command := range child.Commands {
		if !command.ArgvComplete || command.Program != ":" || len(command.Argv) != 1 ||
			len(command.Redirects) == 0 {
			return false
		}
		for _, redirect := range command.Redirects {
			if redirect.Expands || redirect.Access != actionfacts.PathAccessWrite &&
				redirect.Access != actionfacts.PathAccessAppend {
				return false
			}
			redirects++
		}
	}
	if redirects != len(child.Paths) {
		return false
	}
	for _, target := range child.Paths {
		if target.Access != actionfacts.PathAccessWrite &&
			target.Access != actionfacts.PathAccessAppend ||
			target.Absolute || target.Linked || target.Resolved == "" ||
			!filepath.IsAbs(target.Resolved) ||
			target.Resolved == home || strings.HasPrefix(target.Resolved, home+string(filepath.Separator)) {
			return false
		}
	}
	return request.targetMemo.ActionCommandDecisionWithDialectAndGlobFacts(
		body, root, input.ActiveHome, actionfacts.DialectPOSIX, clientGlobFacts(request)) == ""
}
