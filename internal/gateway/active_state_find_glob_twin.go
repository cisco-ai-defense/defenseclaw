// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// findPatternPredicates take a shell pattern as their next word.
var findPatternPredicates = map[string]bool{
	"-name": true, "-iname": true, "-path": true, "-ipath": true,
	"-wholename": true, "-iwholename": true, "-lname": true, "-ilname": true,
}

// findCallWrappers may run find as their program word (`sudo find ...`).
var findCallWrappers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nohup": true, "nice": true,
	"command": true, "exec": true, "time": true, "timeout": true, "stdbuf": true,
}

// findGlobTwinStateMutation judges an action whose find has an unquoted
// -name/-path pattern by its twin with those patterns single-quoted
// (GAP-2498, pod check27). ActionFacts keeps such a find partial with no
// values, so the whole action named no state path, and only a bare find
// with a literal start was re-read (findGlobStateMutation). A writer
// hand-off (`-exec sed -i`, `-exec truncate`, `-exec sh -c`), a pipe to
// xargs, a redirect, sudo and a $HOME start then allowed while the quoted
// spelling blocked. The pattern reaches find as the same word either way
// unless it matches a name in the cwd, so the twin is judged by the whole
// dispatcher, the way its quoted spelling is judged when typed.
func findGlobTwinStateMutation(facts actionfacts.Facts, request trustedActionRequest) bool {
	if facts.Parse.Status == actionfacts.StatusInvalid || !strings.HasPrefix(facts.ActiveHome, "/") {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || len(command) > maxHereStringTwinBytes || !strings.Contains(command, "find") {
		return false
	}
	twin, ok := findGlobQuotedTwin(command)
	if !ok {
		return false
	}
	twinRequest := request
	twinRequest.Input.Tool, twinRequest.Input.Command = "Bash", twin
	twinRequest.Input.Args, twinRequest.Input.Argv = nil, nil
	if actionfacts.Analyze(twinRequest.Input).Parse.Status == actionfacts.StatusInvalid {
		return false
	}
	twinRequest.LegacyText = twin
	twinRequest.conflictSource = nil
	twinRequest.record, twinRequest.recordTelemetry = nil, nil
	for _, finding := range dispatchTrustedAction(context.Background(), twinRequest) {
		if finding.RuleID == "tamper.detector_state_write" && finding.contributesToEnforcement() {
			return true
		}
	}
	return false
}

// findGlobQuotedTwin is command with every unquoted pattern word after a
// find -name/-path style predicate single-quoted; false when there is none.
func findGlobQuotedTwin(command string) (string, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return "", false
	}
	changed := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		start := findProgramIndex(call.Args)
		if start < 0 {
			return true
		}
		for index := start + 2; index < len(call.Args); index++ {
			if !findPatternPredicates[call.Args[index-1].Lit()] {
				continue
			}
			word := call.Args[index]
			if len(word.Parts) != 1 {
				continue
			}
			literal, ok := word.Parts[0].(*syntax.Lit)
			if !ok || !strings.ContainsAny(literal.Value, "*?[") || strings.ContainsAny(literal.Value, `\'"`) {
				continue
			}
			word.Parts = []syntax.WordPart{&syntax.SglQuoted{Value: literal.Value}}
			changed = true
		}
		return true
	})
	if !changed {
		return "", false
	}
	var out strings.Builder
	if err := syntax.NewPrinter().Print(&out, file); err != nil {
		return "", false
	}
	return out.String(), true
}

// findProgramIndex is the index of the find program word of a call (after
// literal wrapper words such as sudo or timeout 5), or -1.
func findProgramIndex(args []*syntax.Word) int {
	for index, word := range args {
		literal := word.Lit()
		switch {
		case literal == "find":
			return index
		case literal == "":
			return -1
		case index == 0 && !findCallWrappers[literal]:
			return -1
		}
	}
	return -1
}
