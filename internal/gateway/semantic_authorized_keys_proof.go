// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// These bounded proofs reuse ActionFacts and the shell syntax tree for
// authorized-keys writes whose complete action remains partially parsed.
// A proof adds only a positive finding; a failed proof leaves the original
// action and its fallback handling unchanged.

var (
	trustedPathlibAuthorizedKeysWrite = regexp.MustCompile(`^import pathlib; p = pathlib\.Path\.home\(\) / "\.ssh" / "authorized_keys"; p\.write_text\(p\.read_text\(\) \+ "[^"\\]*(?:\\n)?"\)$`)
	trustedPerlAuthorizedKeysWrite    = regexp.MustCompile(`^open\(F, ">>", "\$ENV\{HOME\}/\.ssh/authorized_keys"\); print F "[^"\\]*(?:\\n)?"; close\(F\)$`)
)

func trustedInlineAuthorizedKeysWrite(facts actionfacts.Facts) bool {
	if len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || len(command.Argv) != 3 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
		return false
	}
	switch command.Program {
	case "python3":
		return command.Argv[1] == "-c" &&
			trustedPathlibAuthorizedKeysWrite.MatchString(command.Argv[2]) &&
			facts.ActiveHome != ""
	case "perl":
		return command.Argv[1] == "-e" &&
			trustedPerlAuthorizedKeysWrite.MatchString(command.Argv[2]) &&
			facts.ActiveHome != ""
	default:
		return false
	}
}

func trustedFindExecAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 || input.ActiveHome == "" {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 11 {
		return false
	}
	word := func(index int) string {
		if len(call.Args[index].Parts) != 1 {
			return ""
		}
		literal, ok := call.Args[index].Parts[0].(*syntax.Lit)
		if !ok {
			return ""
		}
		return literal.Value
	}
	for index, expected := range map[int]string{
		0: "find", 1: "~/.ssh", 2: "-name", 3: "authorized_keys",
		4: "-exec", 5: "sh", 6: "-c", 8: "_", 9: "{}",
	} {
		if word(index) != expected {
			return false
		}
	}
	terminator := call.Args[10]
	startTerminator, endTerminator := int(terminator.Pos().Offset()), int(terminator.End().Offset())
	if startTerminator < 0 || endTerminator > len(input.Command) ||
		input.Command[startTerminator:endTerminator] != `\;` {
		return false
	}
	if len(call.Args[7].Parts) != 1 {
		return false
	}
	quoted, ok := call.Args[7].Parts[0].(*syntax.SglQuoted)
	if !ok || len(quoted.Value) > 16<<10 {
		return false
	}
	script, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(quoted.Value), "")
	if err != nil || len(script.Stmts) != 1 || len(script.Stmts[0].Redirs) != 1 {
		return false
	}
	redirect := script.Stmts[0].Redirs[0]
	if redirect.Word == nil || redirect.Op != syntax.AppOut {
		return false
	}
	start, end := int(redirect.Word.Pos().Offset()), int(redirect.Word.End().Offset())
	if start < 0 || end > len(quoted.Value) || quoted.Value[start:end] != `"$1"` {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = quoted.Value[:start] +
		"'" + strings.TrimRight(input.ActiveHome, "/") + "/.ssh/authorized_keys'" +
		quoted.Value[end:]
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement)
}

func trustedAuthorizedKeysSymlinkWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 || input.ActiveHome == "" {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 {
		return false
	}
	sequence, ok := file.Stmts[0].Cmd.(*syntax.BinaryCmd)
	if !ok || sequence.Op != syntax.AndStmt {
		return false
	}
	link, ok := sequence.X.Cmd.(*syntax.CallExpr)
	if !ok || len(link.Assigns) != 0 || len(link.Args) != 4 ||
		len(sequence.X.Redirs) != 0 {
		return false
	}
	word := func(value *syntax.Word) string {
		if len(value.Parts) != 1 {
			return ""
		}
		literal, ok := value.Parts[0].(*syntax.Lit)
		if !ok {
			return ""
		}
		return literal.Value
	}
	if word(link.Args[0]) != "ln" || word(link.Args[1]) != "-sf" ||
		word(link.Args[2]) != "~/.ssh/authorized_keys" ||
		word(link.Args[3]) != "./keys.link" {
		return false
	}
	write := sequence.Y
	if _, ok := write.Cmd.(*syntax.CallExpr); !ok || len(write.Redirs) != 1 ||
		word(write.Redirs[0].Word) != "./keys.link" {
		return false
	}
	start, end := int(write.Redirs[0].Word.Pos().Offset()), int(write.Redirs[0].Word.End().Offset())
	writeStart, writeEnd := int(write.Pos().Offset()), int(write.End().Offset())
	if start < writeStart || end > writeEnd || writeEnd > len(input.Command) {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = input.Command[writeStart:start] +
		"'" + strings.TrimRight(input.ActiveHome, "/") + "/.ssh/authorized_keys'" +
		input.Command[end:writeEnd]
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement)
}

func trustedBase64ShellAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	if facts.Parse.Status != actionfacts.StatusComplete ||
		facts.Parse.Dialect != actionfacts.DialectPOSIX || len(facts.Commands) != 3 {
		return false
	}
	echo, decode, shell := facts.Commands[0], facts.Commands[1], facts.Commands[2]
	if echo.Program != "echo" || decode.Program != "base64" || shell.Program != "sh" ||
		len(echo.Argv) != 2 || len(decode.Argv) != 2 || decode.Argv[1] != "-d" ||
		len(shell.Argv) != 1 || echo.PipelineID == 0 ||
		echo.PipelineID != decode.PipelineID || decode.PipelineID != shell.PipelineID {
		return false
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete || len(command.Redirects) != 0 ||
			len(command.Wrappers) != 0 {
			return false
		}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(echo.Argv[1])
	if err != nil || len(decoded) == 0 || len(decoded) > 64<<10 || !utf8.Valid(decoded) {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = string(decoded)
	inner.Tool = "Bash"
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement) ||
		homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite)
}

func trustedStaticStatementAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) < 2 || len(file.Stmts) > 16 {
		return false
	}
	for _, stmt := range file.Stmts {
		if stmt.Background || stmt.Negated {
			continue
		}
		if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok {
			continue
		}
		var rendered bytes.Buffer
		if syntax.NewPrinter().Print(&rendered, stmt) != nil {
			continue
		}
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Command = rendered.String()
		inner.DialectHint = actionfacts.DialectPOSIX
		parsed := actionfacts.Analyze(inner)
		enforcement := parsed.EnforcementProjection()
		if enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement) ||
			homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite) {
			return true
		}
	}
	return false
}

func trustedAuthorizedKeysGlobWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
	if err != nil {
		return false
	}
	matched := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) != 3 {
			return true
		}
		literal := func(word *syntax.Word, value string) bool {
			if len(word.Parts) != 1 {
				return false
			}
			part, ok := word.Parts[0].(*syntax.Lit)
			return ok && part.Value == value
		}
		if !literal(call.Args[0], "tee") || !literal(call.Args[1], "-a") {
			return true
		}
		start, end := int(call.Args[2].Pos().Offset()), int(call.Args[2].End().Offset())
		if start < 0 || end > len(input.Command) ||
			input.Command[start:end] != "~/.ssh/authorized_k*" {
			return true
		}
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Command = input.Command[:start] + "~/.ssh/authorized_keys" + input.Command[end:]
		inner.DialectHint = actionfacts.DialectPOSIX
		parsed := actionfacts.Analyze(inner)
		proof := parsed.EnforcementProjection()
		matched = proof.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(proof) ||
			homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite)
		return !matched
	})
	return matched
}

func trustedAssignedAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 || input.ActiveHome == "" {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) != 2 {
		return false
	}
	assignmentCall, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(assignmentCall.Args) != 0 || len(assignmentCall.Assigns) != 1 {
		return false
	}
	assignment := assignmentCall.Assigns[0]
	if assignment.Name == nil || assignment.Name.Value != "D" ||
		assignment.Value == nil || len(assignment.Value.Parts) != 1 {
		return false
	}
	root, ok := assignment.Value.Parts[0].(*syntax.Lit)
	if !ok || root.Value != "~/.ssh" {
		return false
	}
	write := file.Stmts[1]
	if _, ok := write.Cmd.(*syntax.CallExpr); !ok || len(write.Redirs) != 1 {
		return false
	}
	target := write.Redirs[0].Word
	if target == nil {
		return false
	}
	start, end := int(target.Pos().Offset()), int(target.End().Offset())
	writeStart, writeEnd := int(write.Pos().Offset()), int(write.End().Offset())
	if start < writeStart || end > writeEnd || writeEnd > len(input.Command) ||
		input.Command[start:end] != `"$D/authorized_keys"` {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = input.Command[writeStart:start] +
		"'" + strings.TrimRight(input.ActiveHome, "/") + "/.ssh/authorized_keys'" +
		input.Command[end:writeEnd]
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement)
}

func trustedSedInPlaceAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 4 {
		return false
	}
	static := func(word *syntax.Word, expected string) bool {
		return len(word.Parts) == 1 && func() bool {
			literal, ok := word.Parts[0].(*syntax.Lit)
			return ok && literal.Value == expected
		}()
	}
	if !static(call.Args[0], "sed") || !static(call.Args[1], "-i") {
		return false
	}
	last := call.Args[3]
	start, end := int(last.Pos().Offset()), int(last.End().Offset())
	if start < 0 || end <= start || end > len(input.Command) {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = "sed -i 's/a/b/' " + input.Command[start:end]
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement) ||
		homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite)
}

func trustedShellWrapperAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.Effect != actionfacts.EffectExecute ||
			!command.ArgvComplete ||
			len(command.Argv) != 3 || command.Argv[1] != "-c" {
			continue
		}
		switch command.Program {
		case "sh", "bash":
		default:
			continue
		}
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Tool = "Bash"
		inner.Command = command.Argv[2]
		inner.DialectHint = actionfacts.DialectPOSIX
		parsed := actionfacts.Analyze(inner)
		enforcement := parsed.EnforcementProjection()
		if enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement) ||
			homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite) {
			return true
		}
	}
	return false
}

// trustedHomeDirectoryAuthorizedKeysWrite checks a static directory change
// followed by a separately parsed write. The shell parser supplies the
// statement boundaries; the ordinary action analyzer supplies the write fact.
func trustedHomeDirectoryAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || input.ActiveHome == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(input.Command), "")
	if err != nil {
		return false
	}
	var statements []*syntax.Stmt
	var collect func(*syntax.Stmt) bool
	collect = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated {
			return false
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			return binary.Op == syntax.AndStmt && collect(binary.X) && collect(binary.Y)
		}
		if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok {
			return false
		}
		statements = append(statements, stmt)
		return true
	}
	for _, stmt := range file.Stmts {
		if !collect(stmt) {
			return false
		}
	}
	if len(statements) < 2 || len(statements) > 16 {
		return false
	}
	workingDirectory := ""
	for _, stmt := range statements {
		call := stmt.Cmd.(*syntax.CallExpr)
		if len(call.Args) == 0 {
			return false
		}
		word := func(value *syntax.Word) (string, bool) {
			if len(value.Parts) != 1 {
				return "", false
			}
			literal, ok := value.Parts[0].(*syntax.Lit)
			return literal.Value, ok
		}
		program, static := word(call.Args[0])
		if static && (program == "cd" || program == "pushd") {
			if len(call.Args) > 2 {
				return false
			}
			directory := "~"
			if len(call.Args) == 2 {
				var ok bool
				directory, ok = word(call.Args[1])
				if !ok {
					return false
				}
			}
			switch directory {
			case "~":
				workingDirectory = input.ActiveHome
			case "~/.ssh":
				workingDirectory = strings.TrimRight(input.ActiveHome, "/") + "/.ssh"
			default:
				return false
			}
			continue
		}
		if workingDirectory == "" {
			return false
		}
		var rendered bytes.Buffer
		if syntax.NewPrinter().Print(&rendered, stmt) != nil {
			return false
		}
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Command = rendered.String()
		inner.CWD = workingDirectory
		inner.DialectHint = actionfacts.DialectPOSIX
		parsed := actionfacts.Analyze(inner)
		enforcement := parsed.EnforcementProjection()
		if enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement) ||
			homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite) {
			return true
		}
	}
	return false
}

func trustedPOSIXPowerShellAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	for _, inner := range actionfacts.POSIXPowerShellCommandFacts(input, facts) {
		if inner.EnforcementEligible() &&
			sshAuthorizedKeysCommandPrerequisite(inner.EnforcementProjection()) ||
			trustedPowerShellOutFileAuthorizedKeysWrite(inner) {
			return true
		}
	}
	return false
}

func trustedPowerShellOutFileAuthorizedKeysWrite(facts actionfacts.Facts) bool {
	if facts.Parse.Status != actionfacts.StatusPartial ||
		facts.Parse.Dialect != actionfacts.DialectPowerShell ||
		len(facts.Parse.Issues) != 1 ||
		facts.Parse.Issues[0] != actionfacts.IssueUnknownOperandGrammar ||
		len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.Program != "out-file" || command.Effect != actionfacts.EffectExecute ||
		!command.ArgvComplete || len(command.Argv) != 3 ||
		!strings.EqualFold(command.Argv[1], "-Append") {
		return false
	}
	for _, candidate := range facts.Paths {
		if candidate.CommandID == command.ID &&
			candidate.Access == actionfacts.PathAccessWrite &&
			matchesAuthorizedKeys(facts, candidate) {
			return true
		}
	}
	return false
}

func trustedNestedAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	for _, nested := range trustedNestedExecutionActions(input, facts) {
		if nested.rawFallback {
			continue
		}
		enforcement := nested.facts.EnforcementProjection()
		if enforcement.EnforcementEligible() &&
			sshAuthorizedKeysCommandPrerequisite(enforcement) ||
			homeResolvedTwinProves(nested.input, nested.facts, sshAuthorizedKeysCommandPrerequisite) {
			return true
		}
	}
	return false
}
