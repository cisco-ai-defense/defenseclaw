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
	"net/netip"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// ExactPOSIXInteractiveDevTCPShell proves a single interactive Bash command
// whose output is sent to a literal nonlocal TCP endpoint. The optional
// ordered 0>&1 also sends its input there. The general POSIX projection keeps
// these Bash redirects partial, so this proof checks the original syntax.
func ExactPOSIXInteractiveDevTCPShell(source string, facts Facts) bool {
	if !IsImmediateShellExecutionTool(facts.Tool) ||
		facts.Parse.Dialect != DialectPOSIX || facts.Parse.Status != StatusPartial ||
		len(facts.Commands) != 1 || len(source) > maxCommandBytes {
		return false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueOpaqueArtifact && issue != IssueUnsupportedConstruct {
			return false
		}
	}
	command := facts.Commands[0]
	if command.Program != "bash" || len(command.Argv) != 2 ||
		command.Argv[0] != "bash" || command.Argv[1] != "-i" ||
		!ProvesPOSIXInteractiveShell(command) ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.Background || command.ControlFlowUncertain ||
		len(command.Wrappers) != 0 ||
		!hasLiteralDevTCPPrefix(source) {
		return false
	}
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(shellparse.Reader(source), "")
	if err != nil || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	if stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown ||
		len(stmt.Redirs) < 1 || len(stmt.Redirs) > 2 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 2 {
		return false
	}
	program, option := projectPOSIXWord(call.Args[0]), projectPOSIXWord(call.Args[1])
	if program.Expands || program.Value != "bash" ||
		option.Expands || option.Value != "-i" {
		return false
	}
	output := stmt.Redirs[0]
	if output.Op != syntax.DplOut || output.N != nil || output.Word == nil {
		return false
	}
	target := projectPOSIXWord(output.Word)
	// Bash treats only the case-sensitive /dev/tcp/ spelling as a network
	// redirect. The shared network projection accepts other casing, so the
	// exact shell proof must check the target before using that projection.
	if target.Expands || !strings.HasPrefix(target.Value, "/dev/tcp/") {
		return false
	}
	network, ok := devNetworkRedirect(command.ID, target.Value)
	if !ok || network.Scheme != "tcp" {
		return false
	}
	host, ok := canonicalNetworkHost(network.Host)
	if !ok || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		if address.IsLoopback() || address.IsUnspecified() ||
			address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
			return false
		}
	}
	if len(stmt.Redirs) == 1 {
		return true
	}
	input := stmt.Redirs[1]
	if input.Op != syntax.DplOut || input.N == nil || input.N.Value != "0" ||
		input.Word == nil {
		return false
	}
	sourceFD := projectPOSIXWord(input.Word)
	return !sourceFD.Expands && sourceFD.Value == "1"
}

// hasLiteralDevTCPPrefix rejects ordinary redirects before building a Bash
// syntax tree. Quotes and backslashes can split a literal network path, so
// this scan is only a candidate check; the parsed target is checked above.
func hasLiteralDevTCPPrefix(source string) bool {
	const prefix = "/dev/tcp/"
	if strings.Contains(source, prefix) {
		return true
	}
	for start := 0; start < len(source); start++ {
		if source[start] != '/' {
			continue
		}
		i, j := 0, start
		for i < len(prefix) && j < len(source) {
			switch source[j] {
			case '\\':
				j++
				if j < len(source) && source[j] == '\n' {
					j++
				}
				continue
			case '\'', '"':
				j++
				continue
			}
			if source[j] != prefix[i] {
				break
			}
			i++
			j++
		}
		if i == len(prefix) {
			return true
		}
	}
	return false
}

// ExactPOSIXDescriptorFeedbackShell proves a closed descriptor-to-shell
// feedback loop after the parser resolves literal descriptor duplications.
func ExactPOSIXDescriptorFeedbackShell(facts Facts) bool {
	if !IsImmediateShellExecutionTool(facts.Tool) || facts.Parse.Dialect != DialectPOSIX ||
		facts.Parse.Status != StatusPartial ||
		len(facts.Commands) != 3 {
		return false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueOpaqueArtifact && issue != IssueUnsupportedConstruct {
			return false
		}
	}
	opener, reader, shell := facts.Commands[0], facts.Commands[1], facts.Commands[2]
	if opener.Program != "exec" || len(opener.Argv) != 1 ||
		reader.Program != "cat" || len(reader.Argv) != 1 ||
		!oneOfPOSIXShell(shell.Program) || len(shell.Argv) != 1 ||
		!opener.ArgvComplete || !reader.ArgvComplete || !shell.ArgvComplete ||
		opener.Effect != EffectExecute || reader.Effect != EffectExecute || shell.Effect != EffectExecute ||
		opener.PipelineID != 0 || opener.Background ||
		reader.PipelineID == 0 || reader.PipelineID != shell.PipelineID ||
		opener.ControlFlowUncertain || reader.ControlFlowUncertain || shell.ControlFlowUncertain {
		return false
	}
	for _, network := range facts.Network {
		if network.CommandID != opener.ID || network.Action != NetworkConnect || network.Scheme != "tcp" {
			continue
		}
		address, err := netip.ParseAddr(network.Host)
		if err != nil || address.IsLoopback() || address.IsUnspecified() ||
			address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
			continue
		}
		for _, opened := range opener.Redirects {
			if opened.FD < 3 || opened.Access != PathAccessRead || opened.Target == "" {
				continue
			}
			for _, input := range reader.Redirects {
				if input.FD != 0 || input.Access != PathAccessRead || input.Target != opened.Target {
					continue
				}
				for _, output := range shell.Redirects {
					if output.FD == 1 && output.Access == PathAccessWrite && output.Target == opened.Target {
						for _, flow := range facts.DataFlows {
							if flow.FromCommandID == reader.ID && flow.ToCommandID == shell.ID &&
								flow.From == DataStdout && flow.To == DataStdin {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}
