// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ExactPOSIXDownloadSubstitution proves that an entire shell command body is
// one downloaded stdout substitution. Other expansions or body text are not
// covered by this bounded proof.
func ExactPOSIXDownloadSubstitution(facts Facts, input Input) bool {
	source := input.Command
	if len(input.Args) > 0 {
		if !argsExecutionTool(input.Tool) {
			return false
		}
		extracted := extractArgsForTool(input.Args, input.Tool)
		if extracted.status != StatusComplete || len(extracted.issues) != 0 ||
			len(extracted.argv) != 0 || extracted.command == "" ||
			source != "" && source != extracted.command {
			return false
		}
		source = extracted.command
	}
	if !IsImmediateShellExecutionTool(facts.Tool) || facts.Parse.Dialect != DialectPOSIX ||
		source == "" || len(source) > maxCommandBytes ||
		(facts.Parse.Status != StatusComplete && facts.Parse.Status != StatusPartial) ||
		len(facts.Commands) != 2 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(source), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 ||
		file.Stmts[0].Background || file.Stmts[0].Negated {
		return false
	}
	outer, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(outer.Assigns) != 0 || len(outer.Args) < 2 {
		return false
	}
	program, ok := exactDownloadSubstitutionLiteral(outer.Args[0])
	if !ok {
		return false
	}
	index := -1
	if program == "eval" && len(outer.Args) == 2 {
		index = 1
	} else if oneOfPOSIXShell(program) && len(outer.Args) == 3 {
		option, static := exactDownloadSubstitutionLiteral(outer.Args[1])
		if static && option == "-c" {
			index = 2
		}
	}
	if index < 0 || len(outer.Args[index].Parts) != 1 {
		return false
	}
	quoted, ok := outer.Args[index].Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return false
	}
	substitution, ok := quoted.Parts[0].(*syntax.CmdSubst)
	if !ok || len(substitution.Stmts) != 1 || len(substitution.Stmts[0].Redirs) != 0 ||
		substitution.Stmts[0].Background || substitution.Stmts[0].Negated {
		return false
	}
	inner, ok := substitution.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(inner.Assigns) != 0 || len(inner.Args) < 2 {
		return false
	}
	for _, word := range inner.Args {
		if _, static := exactDownloadSubstitutionLiteral(word); !static {
			return false
		}
	}
	for _, parent := range facts.Commands {
		if parent.ParentCommandID != 0 || parent.Program != program ||
			parent.ControlFlowUncertain || parent.PipelineID != 0 {
			continue
		}
		for _, child := range facts.Commands {
			if child.ParentCommandID != parent.ID || child.ControlFlowUncertain ||
				!ProvesPOSIXPipelineInterpreterSource(child) {
				continue
			}
			for _, network := range facts.Network {
				if network.CommandID == child.ID &&
					(network.Action == NetworkDownload || network.Action == NetworkUpload) &&
					(network.Scheme == "http" || network.Scheme == "https") {
					return true
				}
			}
		}
	}
	return false
}

func exactDownloadSubstitutionLiteral(word *syntax.Word) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return literal.Value, true
}

func oneOfPOSIXShell(program string) bool {
	switch program {
	case "sh", "bash", "dash", "ksh", "zsh", "/bin/sh", "/bin/bash":
		return true
	default:
		return false
	}
}
