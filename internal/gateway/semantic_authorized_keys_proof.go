// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// These bounded proofs reuse ActionFacts and the shell syntax tree for
// authorized-keys writes whose complete action remains partially parsed.
// A proof adds only a positive finding; a failed proof leaves the original
// action and its fallback handling unchanged.

var (
	trustedPathlibAuthorizedKeysWrite    = regexp.MustCompile(`\bp\s*=\s*(?:pathlib\.)?Path\.home\(\)\s*/\s*['"]\.ssh['"]\s*/\s*['"]authorized_keys['"]`)
	trustedPathlibWriteText              = regexp.MustCompile(`\bp\.write_text\s*\(`)
	trustedPathlibSafeReassignment       = regexp.MustCompile(`^\s*;\s*p\s*=\s*(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*;\s*$`)
	trustedPythonSimpleChdir             = regexp.MustCompile(`^os\.chdir\s*\(\s*(?:Path\.home\(\)\s*/\s*['"]\.ssh['"]|['"][^'"\\]*['"])\s*\)$`)
	trustedPythonPathAuthorizedKeysWrite = regexp.MustCompile(`(?s)\bPath\s*\(\s*['"]~/\.ssh/authorized_keys['"]\s*\)\.expanduser\s*\(\s*\)\.write_text\s*\(`)
	trustedPerlAuthorizedKeysWrite       = regexp.MustCompile(`^open\(F,\s*">>",\s*"\$ENV\{HOME\}/\.ssh/authorized_keys"\);\s*print F "[^"\\]*(?:\\n)?";?(?:\s*close\(F\))?$`)
	trustedCMDInvoke                     = regexp.MustCompile(`(?is)^cmd(?:\.exe)?\s+(?://?d\s+)?//?c\s+(.+)$`)
	trustedSoleCMDInvoke                 = regexp.MustCompile("^(?i:cmd(?:\\.exe)?)[ \t]+(?i://?d[ \t]+)?(?i://?c)[ \t]+\"[^\"$`\r\n]*\"[ \t]*$")
	trustedOutFileAppend                 = regexp.MustCompile(`(?is)^\s*(?:"[^"\r\n]*"|'[^'\r\n]*')\s*\|\s*out-file\s+-append\s+-filepath\s+(.+?)\s*$`)
	trustedInterpreterKeysPath           = regexp.MustCompile(`(?:~|\$HOME|\$ENV\{HOME\}|/[A-Za-z0-9_./ -]+)/\.ssh/authorized_keys(?:2)?`)
	trustedInterpreterOpenCall           = regexp.MustCompile(`\b(?:open|File\.open|fs\.openSync)\s*\(`)
	trustedInterpreterWriteMode          = regexp.MustCompile(`['"](?:[awx](?:[bt]?\+?|\+[bt]?)|r(?:[bt]?\+|\+[bt]?)|>>|>)['"]`)
	trustedInterpreterWriteCall          = regexp.MustCompile(`\b(?:appendFileSync|writeFileSync|File\.write|File\.binwrite)\s*\(`)
)

// soleCMDInvocation reports a PowerShell command line that is nothing but one
// cmd /c call with one double-quoted body. PowerShell hands that body to
// cmd.exe unchanged only when it holds no $ or backtick expansion; anything
// after the closing quote (a statement, pipeline or redirect) is PowerShell
// code. PowerShell also closes a double-quoted string at a typographic
// quote, so a non-ASCII rune keeps PowerShell grammar.
func soleCMDInvocation(command string) bool {
	command = strings.TrimSpace(command)
	for i := 0; i < len(command); i++ {
		if command[i] >= utf8.RuneSelf {
			return false
		}
	}
	return trustedSoleCMDInvoke.MatchString(command)
}

func trustedCMDBody(input actionfacts.Input) (string, bool) {
	if len(input.Command) > 64<<10 || input.Command == "" ||
		!windowsLocationAbsolute(input.ActiveHome) {
		return "", false
	}
	parts := trustedCMDInvoke.FindStringSubmatch(strings.TrimSpace(input.Command))
	if len(parts) != 2 {
		return "", false
	}
	body := strings.TrimSpace(parts[1])
	if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
		body = body[1 : len(body)-1]
	}
	if body == "" || strings.ContainsAny(body, "\r\n") {
		return "", false
	}
	return body, true
}

func trustedWindowsHomeOperand(operand, home, file string) bool {
	operand = strings.TrimSpace(operand)
	if len(operand) >= 2 && operand[0] == '"' && operand[len(operand)-1] == '"' {
		operand = operand[1 : len(operand)-1]
	}
	if strings.ContainsAny(operand, "`\r\n;|&<>") {
		return false
	}
	value := strings.ToLower(strings.ReplaceAll(operand, `\`, "/"))
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$home", "${home}", "$env:userprofile", "${env:userprofile}", "~"} {
		if strings.HasPrefix(value, prefix+"/") {
			value = strings.ToLower(home) + value[len(prefix):]
			break
		}
	}
	return canonicalSemanticPath(value) == canonicalSemanticPath(home+"/.ssh/"+file)
}

func trustedCMDAuthorizedKeysWrite(input actionfacts.Input) bool {
	body, ok := trustedCMDBody(input)
	if !ok {
		return false
	}
	index := strings.LastIndex(body, ">")
	if index < 0 || index+1 >= len(body) {
		return false
	}
	return trustedWindowsHomeOperand(body[index+1:], input.ActiveHome, "authorized_keys")
}

func trustedCMDPrivateKeyRead(input actionfacts.Input) bool {
	body, ok := trustedCMDBody(input)
	if !ok || !strings.HasPrefix(strings.ToLower(body), "type ") {
		return false
	}
	operand := strings.TrimSpace(body[len("type "):])
	for _, key := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"} {
		if trustedWindowsHomeOperand(operand, input.ActiveHome, key) {
			return true
		}
	}
	return false
}

func appendTrustedCMDPrivateKeyReadFinding(
	findings []RuleFinding,
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	input actionfacts.Input,
) []RuleFinding {
	if !trustedCMDPrivateKeyRead(input) {
		return findings
	}
	for _, finding := range findings {
		if finding.RuleID == "PATH-SSH-KEY" || finding.RuleID == "PATH-WIN-SSH-KEY" {
			return findings
		}
	}
	_, rule, ok := trustedActionCatalogRule(generation, "PATH-SSH-KEY")
	if !ok {
		return findings
	}
	enforcement := findingEnforcementDetectionOnly
	if request.EnforcementCapable {
		enforcement = findingEnforcementAllowed
	}
	return append(findings, adjustConfidence(input.Tool, RuleFinding{
		RuleID: rule.ID, Title: rule.Title, Severity: rule.Severity,
		Confidence: rule.Confidence, Evidence: trustedActionInputText(input, ""),
		Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
		enforcement: enforcement,
	}))
}

func trustedNamedOutFileAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.DialectHint != actionfacts.DialectPowerShell || len(input.Command) > 64<<10 {
		return false
	}
	parts := trustedOutFileAppend.FindStringSubmatch(input.Command)
	return len(parts) == 2 && trustedWindowsHomeOperand(parts[1], input.ActiveHome, "authorized_keys")
}

func trustedGitBashAuthorizedKeysWrite(input actionfacts.Input) bool {
	home := strings.ReplaceAll(input.ActiveHome, `\`, "/")
	if len(home) < 3 || home[1] != ':' || home[2] != '/' ||
		input.DialectHint != actionfacts.DialectPOSIX {
		return false
	}
	gitHome := "/" + strings.ToLower(home[:1]) + home[2:]
	operand := gitHome + "/.ssh/authorized_keys"
	if !strings.Contains(input.Command, operand) {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = strings.ReplaceAll(input.Command, operand, home+"/.ssh/authorized_keys")
	parsed := actionfacts.Analyze(inner).EnforcementProjection()
	return parsed.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(parsed)
}

// trustedInlineAuthorizedKeysWrite proves the write of one inline
// interpreter program (python -c, perl/ruby/node -e).
//
// A python -c program is read whole, its comments, docstrings and string
// text included. Whether a string runs depends on the modules the program
// loads, and the interpreter imports on its own at start-up (site and
// sitecustomize, a codec): a module that the import path of the shell running
// the command supplies (its PYTHONPATH, PYTHONHOME or user site, a module of
// its working directory) can run __main__.__doc__ or any string of
// sys.orig_argv. The gateway does not see that shell's environment (an
// export of an earlier call in a persistent shell, a profile, a function
// standing in for python3), and its own environment is not the shell's, so
// no string of the program is proven inert.
func trustedInlineAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	if len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.Effect != actionfacts.EffectExecute ||
		command.ParentCommandID != 0 || len(command.Argv) != 3 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
		return false
	}
	switch command.Program {
	case "python", "python3":
		if command.Argv[1] != "-c" || facts.ActiveHome == "" ||
			(!command.ArgvComplete && !trustedPythonAssignedArgv(input, command.Argv)) {
			return false
		}
		return trustedPathlibAuthorizedKeysWriteProof(command.Argv[2], facts.ActiveHome, facts.CWD) ||
			trustedPythonPathAuthorizedKeysWriteProof(command.Argv[2]) ||
			trustedInterpreterAuthorizedKeysWrite(command.Argv[2], facts.ActiveHome, "python")
	case "perl":
		return command.ArgvComplete && command.Argv[1] == "-e" && facts.ActiveHome != "" &&
			(trustedPerlAuthorizedKeysWrite.MatchString(command.Argv[2]) ||
				trustedInterpreterAuthorizedKeysWrite(command.Argv[2], facts.ActiveHome, "perl"))
	case "ruby", "node":
		return command.ArgvComplete && command.Argv[1] == "-e" && facts.ActiveHome != "" &&
			trustedInterpreterAuthorizedKeysWrite(command.Argv[2], facts.ActiveHome, command.Program)
	default:
		return false
	}
}

// trustedPythonAssignedArgv reports whether the shell syntax of the one
// Python invocation proves its argv when PYTHONPATH or PYTHONHOME
// assignments prefix it (PYTHONPATH=/x python3 -c '...'). A sole such
// assignment makes ActionFacts leave ArgvComplete false; the AST can still
// prove the exact three arguments of the call.
func trustedPythonAssignedArgv(input actionfacts.Input, argv []string) bool {
	command, ok := trustedBashCommandInput(input)
	if !ok || len(command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(command), "")
	if err != nil || len(file.Stmts) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) == 0 || stmt.Negated || stmt.Background ||
		len(stmt.Redirs) != 0 || len(call.Args) != len(argv) {
		return false
	}
	for _, assignment := range call.Assigns {
		if assignment.Name == nil ||
			assignment.Name.Value != "PYTHONPATH" && assignment.Name.Value != "PYTHONHOME" {
			return false
		}
	}
	fields, ok := trustedBashStaticFields(call)
	return ok && slices.Equal(fields, argv)
}

// trustedPathlibAuthorizedKeysWriteProof matches the protected Path and its
// write_text call anywhere in the code, string text included: exec, eval, an
// f-string field, getattr or an agent-controlled sitecustomize or import can
// run text that the Python lexer reads as data, so string position is not a
// proof that the write cannot run.
func trustedPathlibAuthorizedKeysWriteProof(code, home, cwd string) bool {
	for _, assignment := range trustedPathlibAuthorizedKeysWrite.FindAllStringIndex(code, -1) {
		for _, write := range trustedPathlibWriteText.FindAllStringIndex(code, -1) {
			if write[0] < assignment[1] {
				continue
			}
			between := code[assignment[1]:write[0]]
			if safe := trustedPathlibSafeReassignment.FindStringSubmatch(between); len(safe) == 2 &&
				trustedPythonPathStablePrefix(code[:assignment[0]], filepath.IsAbs(safe[1])) &&
				trustedOrdinaryPathReassignment(safe[1], home, cwd) {
				continue
			}
			return true
		}
	}
	return false
}

// trustedPythonPathAuthorizedKeysWriteProof also matches string text, for the
// reason given at trustedPathlibAuthorizedKeysWriteProof.
func trustedPythonPathAuthorizedKeysWriteProof(code string) bool {
	return trustedPythonPathAuthorizedKeysWrite.MatchString(code)
}

// A module docstring is inert to Python itself, but an agent-controlled
// sitecustomize or imported module can execute __main__.__doc__. Other string
// literals are data unless a separate executable effect refers to them.
func trustedPythonCodeOrModuleDocstring(code string, position int) bool {
	return interpreterCodePosition(code, position, "python") ||
		trustedPythonModuleDocstringContains(code, position)
}

func trustedPythonModuleDocstringContains(code string, position int) bool {
	i := 0
	for i < len(code) {
		switch code[i] {
		case ' ', '\t', '\r', '\n':
			i++
		case '#':
			for i < len(code) && code[i] != '\n' {
				i++
			}
		default:
			goto literal
		}
	}
literal:
	if i >= len(code) {
		return false
	}
	start := i
	for i < len(code) && (code[i] == 'r' || code[i] == 'R' || code[i] == 'u' || code[i] == 'U') {
		i++
	}
	if i+3 > len(code) || code[i:i+3] != `"""` && code[i:i+3] != `'''` {
		return false
	}
	quote := code[i : i+3]
	i += 3
	for i+3 <= len(code) {
		if code[i] == '\\' {
			i += 2
			continue
		}
		if code[i:i+3] == quote {
			return position >= start && position < i
		}
		i++
	}
	return position >= start && position < len(code)
}

// A relative Path is resolved when write_text runs, and any Path can be
// redirected by an in-process link or rename. Only imports may precede this
// narrow waiver. A simple chdir is also safe for an absolute reassignment.
func trustedPythonPathStablePrefix(prefix string, absolute bool) bool {
	for _, statement := range strings.Split(prefix, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		switch statement {
		case "from pathlib import Path", "import pathlib", "import os", "from os import path":
		default:
			if !absolute || !trustedPythonSimpleChdir.MatchString(statement) {
				return false
			}
		}
	}
	return true
}

func trustedOrdinaryPathReassignment(name, home, cwd string) bool {
	if name == "" || strings.ContainsAny(name, "\x00\r\n$`*?[") {
		return false
	}
	if !filepath.IsAbs(name) {
		if !filepath.IsAbs(cwd) {
			return false
		}
		name = filepath.Join(cwd, name)
	}
	resolved, ok := hookpaths.ResolveWriteTarget(name)
	if !ok {
		return false
	}
	entry, entryErr := os.Stat(resolved)
	if entryErr != nil && !os.IsNotExist(entryErr) {
		return false
	}
	for _, protected := range hookpaths.ProtectedAuthorizedKeysPaths(home) {
		if canonicalSemanticPath(resolved) == canonicalSemanticPath(protected) {
			return false
		}
		guarded, err := os.Stat(protected)
		if err != nil && !os.IsNotExist(err) {
			return false
		}
		if entryErr == nil && err == nil && os.SameFile(entry, guarded) {
			return false
		}
	}
	return true
}

// A static shell redirect writes its target independently of the program's
// operand grammar. Check every parsed statement, including unmodeled programs
// and redirects on commands with assignment prefixes or in shell lists.
func trustedStaticRedirectAuthorizedKeysWrite(input actionfacts.Input, facts actionfacts.Facts) bool {
	if input.Command == "" || len(input.Command) > 64<<10 ||
		facts.Parse.Dialect != actionfacts.DialectPOSIX {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(input.Command), "")
	if err != nil {
		return false
	}
	// A direct cd && prefix changes the base for a relative redirect.
	var cdRight *syntax.Stmt
	cdCWD := ""
	if len(file.Stmts) == 1 {
		if list, ok := file.Stmts[0].Cmd.(*syntax.BinaryCmd); ok && list.Op == syntax.AndStmt {
			if call, ok := list.X.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) == 0 &&
				len(call.Args) == 2 && len(call.Args[0].Parts) == 1 {
				if program, ok := call.Args[0].Parts[0].(*syntax.Lit); ok && program.Value == "cd" {
					cdRight = list.Y
					cdCWD = trustedStaticRedirectDirectory(input, call.Args[1])
				}
			}
		}
	}
	matched := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if matched {
			return false
		}
		if _, declaration := node.(*syntax.FuncDecl); declaration {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		redirectInput := input
		if stmt == cdRight {
			// An unresolved directory cannot make a relative target definite.
			redirectInput.CWD = cdCWD
		}
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.RdrClob, syntax.AppOut, syntax.AppClob,
				syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
				if trustedActiveAuthorizedKeysRedirectTarget(redirectInput, redirect.Word) {
					matched = true
					return false
				}
			}
		}
		return true
	})
	return matched
}

func trustedStaticRedirectDirectory(input actionfacts.Input, target *syntax.Word) string {
	if target == nil {
		return ""
	}
	start, end := int(target.Pos().Offset()), int(target.End().Offset())
	if start < 0 || end <= start || end > len(input.Command) {
		return ""
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = "true > " + input.Command[start:end]
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	if !parsed.Authoritative() {
		var ok bool
		parsed, ok = actionfacts.HomeResolvedTwin(inner)
		if !ok {
			return ""
		}
	}
	for _, path := range parsed.Paths {
		if path.Access == actionfacts.PathAccessWrite && isAbsoluteSemanticPath(path.Resolved) {
			return path.Resolved
		}
	}
	return ""
}

func trustedActiveAuthorizedKeysRedirectTarget(input actionfacts.Input, target *syntax.Word) bool {
	if target == nil {
		return false
	}
	start, end := int(target.Pos().Offset()), int(target.End().Offset())
	if start < 0 || end <= start || end > len(input.Command) {
		return false
	}
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = "true > " + input.Command[start:end]
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	check := func(facts actionfacts.Facts) bool {
		for _, path := range facts.Paths {
			if path.Access != actionfacts.PathAccessWrite && path.Access != actionfacts.PathAccessAppend {
				continue
			}
			relative, ok := activeHomeRelative(facts, path)
			if ok && authorizedKeysRelative(relative) {
				return true
			}
		}
		return false
	}
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && check(enforcement) ||
		homeResolvedTwinProves(inner, parsed, check)
}

func trustedHereStringAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 2 {
		return false
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || stmt.Background || stmt.Negated || len(call.Assigns) != 0 ||
		len(call.Args) != 1 || len(call.Args[0].Parts) != 1 {
		return false
	}
	program, ok := call.Args[0].Parts[0].(*syntax.Lit)
	if !ok || program.Value != "cat" {
		return false
	}
	var output *syntax.Word
	for _, redirect := range stmt.Redirs {
		if redirect.Op == syntax.RdrOut || redirect.Op == syntax.AppOut {
			output = redirect.Word
		} else if redirect.Op != syntax.WordHdoc {
			return false
		}
	}
	return trustedAuthorizedKeysRedirectTarget(input, output)
}

func trustedDDOutputAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 {
		return false
	}
	var output string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 ||
			len(call.Args[0].Parts) != 1 {
			return true
		}
		program, ok := call.Args[0].Parts[0].(*syntax.Lit)
		if !ok || program.Value != "dd" {
			return true
		}
		for _, word := range call.Args[1:] {
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < 0 || end > len(input.Command) || end-start <= 3 {
				continue
			}
			if candidate := input.Command[start:end]; strings.HasPrefix(candidate, "of=") {
				output = candidate[3:]
				return false
			}
		}
		return false
	})
	return output != "" && trustedAuthorizedKeysRedirectText(input, output)
}

func trustedAuthorizedKeysRedirectTarget(input actionfacts.Input, target *syntax.Word) bool {
	if target == nil {
		return false
	}
	start, end := int(target.Pos().Offset()), int(target.End().Offset())
	if start < 0 || end <= start || end > len(input.Command) {
		return false
	}
	return trustedAuthorizedKeysRedirectText(input, input.Command[start:end])
}

func trustedAuthorizedKeysRedirectText(input actionfacts.Input, target string) bool {
	inner := input
	inner.Args, inner.Argv = nil, nil
	inner.Command = "true > " + target
	inner.DialectHint = actionfacts.DialectPOSIX
	parsed := actionfacts.Analyze(inner)
	enforcement := parsed.EnforcementProjection()
	return enforcement.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(enforcement) ||
		homeResolvedTwinProves(inner, parsed, sshAuthorizedKeysCommandPrerequisite)
}

func trustedInterpreterAuthorizedKeysWrite(code, activeHome, language string) bool {
	if len(code) == 0 || len(code) > 16<<10 ||
		!trustedAuthorizedKeysPathInText(code, activeHome) {
		return false
	}
	for _, location := range trustedInterpreterOpenCall.FindAllStringIndex(code, -1) {
		if language == "python" && !trustedPythonCodeOrModuleDocstring(code, location[0]) ||
			language != "python" && !interpreterCodePosition(code, location[0], language) {
			continue
		}
		call, ok := boundedInterpreterCall(code, location[1]-1)
		args := interpreterCallArgs(call)
		if ok && len(args) >= 2 &&
			trustedAuthorizedKeysPathInText(args[0], activeHome) &&
			trustedInterpreterWriteMode.MatchString(args[1]) {
			return true
		}
		// Perl's three-argument open puts the mode before the target.
		if ok && len(args) >= 3 && strings.TrimSpace(code[location[0]:location[1]-1]) == "open" &&
			trustedInterpreterWriteMode.MatchString(args[1]) &&
			trustedAuthorizedKeysPathInText(args[2], activeHome) {
			return true
		}
	}
	for _, location := range trustedInterpreterWriteCall.FindAllStringIndex(code, -1) {
		if language == "python" && !trustedPythonCodeOrModuleDocstring(code, location[0]) ||
			language != "python" && !interpreterCodePosition(code, location[0], language) {
			continue
		}
		if call, ok := boundedInterpreterCall(code, location[1]-1); ok {
			args := interpreterCallArgs(call)
			if len(args) > 0 && trustedAuthorizedKeysPathInText(args[0], activeHome) {
				return true
			}
		}
	}
	return false
}

// interpreterCallArgs separates only top-level arguments. Nested path helpers
// remain in the target argument, while a path in write data cannot prove a
// mutation of that path.
func interpreterCallArgs(call string) []string {
	open := strings.IndexByte(call, '(')
	if open < 0 || !strings.HasSuffix(call, ")") {
		return nil
	}
	var args []string
	start, depth := open+1, 0
	var quote byte
	for i := start; i < len(call)-1; i++ {
		c := call[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(call[start:i]))
				start = i + 1
			}
		}
	}
	return append(args, strings.TrimSpace(call[start:len(call)-1]))
}

func interpreterCodePosition(code string, position int, language string) bool {
	var quote byte
	comment := false
	perlHashDelimiters := 0
	for i := 0; i < position; i++ {
		c := code[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		} else if c == '#' {
			if language == "perl" && perlHashDelimiters > 0 {
				perlHashDelimiters--
			} else if language == "perl" && interpreterPerlHashRegexpStart(code, i) > 0 {
				perlHashDelimiters = interpreterPerlHashRegexpStart(code, i)
			} else if interpreterCommentStart(code, i, language) {
				comment = true
			}
		}
	}
	return quote == 0 && !comment
}

func interpreterPerlHashRegexpStart(code string, i int) int {
	for _, operator := range []string{"s", "m", "qr", "tr", "y"} {
		start := i - len(operator)
		if start < 0 || code[start:i] != operator ||
			start > 0 && !strings.ContainsRune(" \t\n;=~(", rune(code[start-1])) {
			continue
		}
		if operator == "m" || operator == "qr" {
			return 1
		}
		return 2
	}
	return 0
}

func trustedAuthorizedKeysPathInText(text, activeHome string) bool {
	for _, location := range trustedInterpreterKeysPath.FindAllStringIndex(text, -1) {
		if location[0] > 0 && strings.ContainsRune("/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_", rune(text[location[0]-1])) {
			continue
		}
		value := text[location[0]:location[1]]
		if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, "$HOME/") ||
			strings.HasPrefix(value, "$ENV{HOME}/") {
			return true
		}
		if relative, ok := liveHomeRelative(value); ok && authorizedKeysRelative(relative) {
			return true
		}
		if activeHome != "" && strings.HasPrefix(value, strings.TrimRight(activeHome, "/")+"/") &&
			authorizedKeysRelative(strings.TrimPrefix(value, strings.TrimRight(activeHome, "/")+"/")) {
			return true
		}
	}
	return false
}

// boundedInterpreterCall keeps a path and its mode within the same call.
func boundedInterpreterCall(code string, open int) (string, bool) {
	depth := 0
	var quote byte
	for i := open; i < len(code); i++ {
		c := code[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return code[open : i+1], true
			}
		}
	}
	return "", false
}

func trustedFindExecAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 || input.ActiveHome == "" {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
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
	script, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(quoted.Value), "")
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
	if err != nil {
		return false
	}
	var boundWord *syntax.Word
	boundValue := ""
	if len(file.Stmts) == 2 {
		assignment, assignmentOK := file.Stmts[0].Cmd.(*syntax.CallExpr)
		second := file.Stmts[1]
		if binary, ok := second.Cmd.(*syntax.BinaryCmd); ok && binary.Op == syntax.AndStmt {
			second = binary.X
		}
		child, childOK := second.Cmd.(*syntax.CallExpr)
		if assignmentOK && childOK && len(assignment.Args) == 0 && len(assignment.Assigns) == 1 &&
			len(file.Stmts[0].Redirs) == 0 && len(child.Args) > 0 {
			item := assignment.Assigns[0]
			if item.Name != nil && item.Value != nil {
				if value, static := hookpaths.StaticWord(item.Value, input.ActiveHome); static && value == "ln" {
					candidate := child.Args[0]
					start, end := int(candidate.Pos().Offset()), int(candidate.End().Offset())
					if start >= 0 && end <= len(input.Command) && end > start {
						for _, spelling := range []string{"$" + item.Name.Value, "${" + item.Name.Value + "}",
							`"$` + item.Name.Value + `"`, `"${` + item.Name.Value + `}"`} {
							if input.Command[start:end] == spelling {
								boundWord, boundValue = candidate, value
								break
							}
						}
					}
				}
			}
		}
	}
	word := func(value *syntax.Word) string {
		if value == boundWord {
			return boundValue
		}
		text, ok := hookpaths.StaticWord(value, input.ActiveHome)
		if !ok {
			return ""
		}
		return text
	}
	sourceWord := func(value *syntax.Word) string {
		if value == nil {
			return ""
		}
		start, end := int(value.Pos().Offset()), int(value.End().Offset())
		if start < 0 || end > len(input.Command) || end <= start {
			return ""
		}
		return input.Command[start:end]
	}
	links := make(map[string]struct{})
	replacedBySed := hookpaths.SedReplacedOperands(input.Command, input.CWD, input.ActiveHome)
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		if _, declaration := node.(*syntax.FuncDecl); declaration {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 {
			return true
		}
		if len(call.Args) == 4 && len(stmt.Redirs) == 0 &&
			word(call.Args[0]) == "ln" &&
			(word(call.Args[1]) == "-s" || word(call.Args[1]) == "-sf") &&
			trustedAuthorizedKeysPathInText(sourceWord(call.Args[2]), input.ActiveHome) {
			if name := word(call.Args[3]); name != "" && !strings.ContainsAny(name, "*?[") {
				links[trustedSymlinkName(input, name)] = struct{}{}
			}
			return true
		}
		if len(links) == 0 {
			return true
		}
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start < 0 || end > len(input.Command) || end <= start {
			return true
		}
		var edits [][2]int
		syntax.Walk(stmt, func(child syntax.Node) bool {
			value, ok := child.(*syntax.Word)
			if !ok {
				return true
			}
			operand := word(value)
			prefix := 0
			if strings.HasPrefix(operand, "of=") {
				operand, prefix = operand[3:], 3
			}
			if operand != "" && !replacedBySed[trustedSymlinkName(input, operand)] {
				if _, linked := links[trustedSymlinkName(input, operand)]; linked {
					edits = append(edits, [2]int{int(value.Pos().Offset()) + prefix, int(value.End().Offset())})
				}
			}
			return true
		})
		if len(edits) == 0 {
			return true
		}
		// Replace only literal operands from the later statement. ActionFacts
		// then proves that the replaced operand is actually written.
		var rebuilt strings.Builder
		cursor := start
		for _, edit := range edits {
			if edit[0] < cursor || edit[1] > end {
				continue
			}
			rebuilt.WriteString(input.Command[cursor:edit[0]])
			rebuilt.WriteString("'" + strings.TrimRight(input.ActiveHome, "/") + "/.ssh/authorized_keys'")
			cursor = edit[1]
		}
		rebuilt.WriteString(input.Command[cursor:end])
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Command = rebuilt.String()
		inner.DialectHint = actionfacts.DialectPOSIX
		parsed := actionfacts.Analyze(inner).EnforcementProjection()
		found = parsed.EnforcementEligible() && sshAuthorizedKeysCommandPrerequisite(parsed) ||
			trustedDDOutputAuthorizedKeysWrite(inner)
		return !found
	})
	return found
}

// authorizedKeysRelative reports a home-relative path that names one of the
// hookpaths.AuthorizedKeysFiles under .ssh.
func authorizedKeysRelative(relative string) bool {
	for _, name := range hookpaths.AuthorizedKeysFiles {
		if relative == ".ssh/"+name {
			return true
		}
	}
	return false
}

func trustedSymlinkName(input actionfacts.Input, name string) string {
	if strings.HasPrefix(name, "~/") || strings.HasPrefix(name, "$HOME/") {
		name = strings.TrimRight(input.ActiveHome, "/") + name[strings.IndexByte(name, '/'):]
	}
	if !filepath.IsAbs(name) && filepath.IsAbs(input.CWD) {
		name = filepath.Join(input.CWD, name)
	}
	return filepath.Clean(name)
}

func trustedExistingAuthorizedKeysSymlinkWrite(request trustedActionRequest, facts actionfacts.Facts) bool {
	if facts.ActiveHome == "" || !filepath.IsAbs(facts.ActiveHome) {
		return false
	}
	// One list for the path, hard-link and missing-final-file checks, the
	// same files the direct-write rule protects (GAP-1370).
	protectedPaths := hookpaths.ProtectedAuthorizedKeysPaths(facts.ActiveHome)
	protected := make(map[string]struct{}, len(protectedPaths))
	for _, path := range protectedPaths {
		protected[canonicalSemanticPath(path)] = struct{}{}
	}
	isProtected := func(path string) bool {
		_, ok := protected[canonicalSemanticPath(path)]
		return ok
	}
	// The client's opaque-scope facts stand in only for the link-scope walk;
	// every other check sees the map as before.
	globFacts := clientGlobFacts(request)
	var opaqueFacts map[string]string
	request.ResolvedWriteTargets, opaqueFacts = hookpaths.SplitOpaqueScopeFacts(request.ResolvedWriteTargets)
	// The operands the client described, before any connector scoping. A
	// bounded or incomplete map omits the others; scoping below drops entries
	// the client did describe, and does not make them omitted.
	clientTargets := request.ResolvedWriteTargets
	truncated := clientTargets[hookpaths.TruncatedKey] == "1"
	if request.Connector == "claudecode" && request.ProtectedHomeHook &&
		len(request.ResolvedWriteTargets) != 0 {
		// Keep the client's positive protected-path evidence and inspected copy
		// sources. A directory proof is relevant once the hook observed a
		// different logical directory or a protected starting directory.
		// Generic ordinary or unknown write targets do not override the
		// established shell-ordering decision. The process-cwd alias needs
		// its own client target to be provable.
		changedDirectory := false
		for key := range request.ResolvedWriteTargets {
			if strings.HasPrefix(key, hookpaths.DirectoryFactPrefix) &&
				key != hookpaths.DirectoryFactPrefix+facts.CWD {
				changedDirectory = true
				break
			}
		}
		home := filepath.Clean(facts.ActiveHome)
		external := func(target string) bool {
			return filepath.IsAbs(target) && filepath.Clean(target) != os.DevNull && target != home &&
				!strings.HasPrefix(filepath.Clean(target), home+string(filepath.Separator))
		}
		// An incomplete map keeps its marker and the client's cwd, so an
		// operand the client omitted is placed and denied as it is for Codex.
		var scoped map[string]string
		// A plain move onto an existing link to a file replaces the link:
		// the client described that entry, which decides it (GAP-2558).
		var plainMoves map[string]bool
		for operand, resolved := range request.ResolvedWriteTargets {
			directoryFact := strings.HasPrefix(operand, hookpaths.DirectoryFactPrefix)
			if resolved != "" && !directoryFact && request.ResolvedWriteTargets[hookpaths.ReplacedLinkFactPrefix+operand] == "1" {
				if plainMoves == nil {
					plainMoves = hookpaths.PlainMoveDestinations(facts)
				}
				if plainMoves[operand] {
					if scoped == nil {
						scoped = make(map[string]string)
					}
					scoped[operand] = resolved
					continue
				}
			}
			if strings.HasPrefix(operand, "/proc/self/cwd/") ||
				strings.HasPrefix(operand, hookpaths.SourceLinkFactPrefix) ||
				directoryFact && (changedDirectory ||
					canonicalSemanticPath(resolved) == canonicalSemanticPath(filepath.Join(facts.ActiveHome, ".ssh"))) ||
				operand == hookpaths.CWDKey && (changedDirectory || truncated) ||
				operand == hookpaths.LinksStableKey ||
				operand == hookpaths.TruncatedKey ||
				resolved == "" && external(operand) && !truncated ||
				isProtected(resolved) {
				if scoped == nil {
					scoped = make(map[string]string)
				}
				scoped[operand] = resolved
			}
		}
		request.ResolvedWriteTargets = scoped
	}
	clientCWD := facts.CWD
	if !filepath.IsAbs(clientCWD) {
		if filepath.IsAbs(request.evidenceCWD) {
			// A simple command after a static cd, in the directory the
			// client keyed it in (trustedSimpleCommandEvidenceCWDs).
			clientCWD = request.evidenceCWD
		} else if cwd := request.ResolvedWriteTargets[hookpaths.CWDKey]; filepath.IsAbs(cwd) {
			clientCWD = filepath.Clean(cwd)
		}
	}
	cannotResolveLocally := request.ProtectedHomeHook || request.SkipLocalFilesystemResolution
	if !request.ProtectedHomeHook {
		// Only the managed hook client walks the user's home for the gateway.
		opaqueFacts = nil
	}
	// The links the command creates, read as the hook reads them; set once
	// the command is known, before the first writeTarget call.
	var links hookpaths.Links
	var safeRedirects []hookpaths.RedirectOccurrence
	// A plain mv onto an existing link to a file replaces the link entry
	// and writes neither file (GAP-2559); a gateway that reads the file
	// system judges that destination by its entry. Behind ProtectHome the
	// client map decides it (GAP-2558).
	var movedOntoLinks map[string]bool
	if !cannotResolveLocally {
		movedOntoLinks = hookpaths.MovedOntoLinkEntries(facts)
	}
	writeTarget := func(target string, safeRedirect, ownCopy bool) bool {
		if !filepath.IsAbs(target) && (target == "" || !filepath.IsAbs(clientCWD)) {
			// No directory places this operand: the gateway cannot see the
			// caller's cwd and the client evidence that would carry it is
			// incomplete or was rejected as malformed. Such evidence never
			// proves a write ordinary, so a gateway that cannot resolve the
			// operand itself fails closed, as for an absolute operand the
			// bounded map omits. A path fact with no name adds nothing once
			// the shell operands are placed in a known cwd.
			return truncated && cannotResolveLocally && !filepath.IsAbs(clientCWD)
		}
		// A relative path fact (the gateway could not validate the event
		// cwd) is placed in the client's cwd, as the client keyed it.
		target = hookpaths.OperandPath(target, clientCWD)
		if request.patchTarget && (request.SandboxGuestCWD == "" || request.patchHostView) {
			if _, ok := hookpaths.ResolvePatchWriteTarget(target); !ok {
				return true
			}
		}
		// Only the event cwd can interpret the process-dependent alias.
		if hookpaths.ProcCWDWriteOperand(target) {
			if !strings.HasPrefix(target, "/proc/self/cwd/") {
				return true
			}
			if resolved, present := request.ResolvedWriteTargets[target]; present {
				return resolved == "" || isProtected(resolved)
			}
			if cannotResolveLocally {
				return true
			}
			mapped, ok := hookpaths.ResolveProcSelfCWDTarget(target, clientCWD)
			if !ok {
				return true
			}
			target = mapped
		}
		if isProtected(target) {
			return true
		}
		if movedOntoLinks[target] {
			parent, ok := hookpaths.ResolveWriteTarget(filepath.Dir(target))
			return !ok || isProtected(filepath.Join(parent, filepath.Base(target)))
		}
		if physicalCWD := request.ResolvedWriteTargets[hookpaths.DirectoryFactPrefix+clientCWD]; filepath.IsAbs(physicalCWD) &&
			strings.HasPrefix(target, clientCWD+string(filepath.Separator)) {
			relative := strings.TrimPrefix(target, clientCWD+string(filepath.Separator))
			if isProtected(hookpaths.OperandPath(relative, physicalCWD)) {
				return true
			}
		}
		// An unreadable link operation makes later writes at its destination
		// unknown, including where the gateway resolves targets itself and
		// the link does not exist yet (GAP-1522). A character device such as
		// /dev/null is not a link the command can replace; a link to one is,
		// so the device is read without following links. A managed gateway
		// cannot walk the user's home (ProtectHome); the hook client's walk of
		// the same operand replaces only that missing view (GAP-0278).
		if !safeRedirect && links.OpaqueTargetWithFacts(target, ownCopy, opaqueFacts) {
			if info, err := os.Lstat(target); err != nil || info.Mode()&os.ModeCharDevice == 0 {
				return true
			}
		}
		// On a static reading of a call with a runtime-expanded operand
		// word, the client answer of that reading decides an operand the
		// call as written left unknown (GAP-2477).
		if reading := clientTargets[hookpaths.ReadingTargetPrefix+target]; request.staticOperandReading && reading != "" {
			return isProtected(reading)
		}
		if request.ResolvedWriteTargets != nil {
			resolved, present := request.ResolvedWriteTargets[target]
			switch {
			case present && resolved != "":
				return isProtected(resolved)
			case present:
				// The user's hook could not resolve the operand (a link
				// loop, a chain past the kernel limit or an unreadable
				// component). Resolve it here, or fail closed.
				if cannotResolveLocally {
					return !windowsLocationOrdinaryWriteTarget(target)
				}
			case truncated && cannotResolveLocally:
				// The bounded map omits this operand, which may be a link
				// into the protected home, in or outside the home. Its target
				// is unknown, so fail closed. An operand the client did list,
				// which connector scoping removed, keeps the local checks.
				if _, described := clientTargets[target]; !described {
					return !windowsLocationOrdinaryWriteTarget(target)
				}
			}
		}
		if request.SkipLocalFilesystemResolution {
			return false
		}
		// A name that a link earlier in the command makes an alias of a
		// protected file (GAP-1505).
		if linked, ok := links.Target(target); !ok || isProtected(linked) {
			// Behind ProtectHome the gateway cannot walk a link the command
			// creates in the user's home. The managed hook client walked the
			// same links as the user and keyed its answer by this operand; a
			// resolved answer decides it, so an ordinary hard link is not a
			// key write (GAP-1440). An empty answer stays unknown.
			if !ok && request.ProtectedHomeHook && links.Known() {
				if resolved := clientTargets[target]; resolved != "" {
					return isProtected(resolved)
				}
				if resolved := clientTargets[hookpaths.ReadingTargetPrefix+target]; request.staticOperandReading && resolved != "" {
					return isProtected(resolved)
				}
			}
			return true
		}
		info, err := os.Lstat(target)
		if err != nil && !os.IsNotExist(err) {
			return false
		}
		if err == nil && info.Mode()&os.ModeSymlink == 0 {
			// A hard link names a protected file under another path.
			if !info.Mode().IsRegular() {
				return false
			}
			for _, path := range protectedPaths {
				if file, err := os.Stat(path); err == nil && os.SameFile(info, file) {
					return true
				}
			}
			return false
		}
		// Resolve as the hook client does, so a link to a missing final
		// file that the redirect would create is covered as well.
		resolved, ok := hookpaths.ResolveWriteTarget(target)
		// An existing link whose target cannot be resolved is still a
		// possible write into the protected home. The client and gateway
		// must both fail closed on a linked component before "..".
		return isProtected(resolved) || !ok && !windowsLocationOrdinaryWriteTarget(target)
	}
	// Partial command projections can omit a redirect PathFact. The shell AST
	// still gives an exact write operand, which the user's hook resolved.
	input := request.Input
	input.CWD = clientCWD
	if input.Command == "" {
		input.Command, _ = trustedBashCommandInput(input)
	}
	if input.Command == "" && trustedBashExecutionTool(input.Tool) {
		var args struct {
			Cmd string `json:"cmd"`
		}
		if json.Unmarshal(input.Args, &args) == nil {
			input.Command = args.Cmd
		}
	}
	decision := hookpaths.ActionCommandDecisionInShell(input.Command, input.CWD, facts.ActiveHome, globFacts, trustedPOSIXShellCall(input, facts))
	if input.DialectHint != "" {
		decision = hookpaths.ActionCommandDecisionWithDialectAndGlobFacts(input.Command, input.CWD, facts.ActiveHome, input.DialectHint, globFacts)
	}
	if decision != "" {
		return true
	}
	if request.ProtectedHomeHook && clientTargets[hookpaths.ActionDecisionKey] == hookpaths.ProtectedTargetDecision {
		// Behind ProtectHome the walk above cannot follow the user's links;
		// the user's hook ran the same decision on the same command and
		// found a protected target, as a per-user gateway does (GAP-2514,
		// GAP-2515).
		return true
	}
	if hookpaths.DynamicCopyProtectedBasename(input.Command, facts.ActiveHome) {
		return true
	}
	links = hookpaths.CommandLinksWithFacts(request.Input.Tool, input.Command, input.CWD, facts.ActiveHome, request.ResolvedWriteTargets)
	safeRedirects = hookpaths.SafeShellRedirectOccurrencesWithFacts(input.Command, input.CWD, facts.ActiveHome, request.ResolvedWriteTargets)
	replacedBySed := hookpaths.SedReplacedOperands(input.Command, input.CWD, facts.ActiveHome)
	var operands []string
	if input.Command != "" {
		var dynamic bool
		operands, _, dynamic = hookpaths.ShellWriteOperands(input.Command, input.CWD, input.ActiveHome)
		if dynamic && request.Connector == "claudecode" && request.ProtectedHomeHook &&
			request.ResolvedWriteTargets != nil {
			// A physical-directory fact can resolve a static write after cd,
			// but it cannot prove a dynamic redirect target is ordinary.
			// Preserve the conservative decision from the header-free walk.
			_, unknown := hookpaths.ShellDirectoryWriteOperands(
				input.Command, input.CWD, input.ActiveHome, nil, false, cannotResolveLocally,
			)
			if unknown {
				return true
			}
		}
		for i, operand := range operands {
			safe := i < len(safeRedirects) && safeRedirects[i].Safe
			if writeTarget(operand, safe, false) {
				return true
			}
		}
		for _, operand := range hookpaths.LiteralWriteOperands(input.Command, input.CWD, input.ActiveHome) {
			if writeTarget(operand, false, false) {
				return true
			}
		}
		if cannotResolveLocally && clientTargets != nil && hookpaths.AWKReadsProgramFile(input.Command) {
			// An awk program file in the user's home this gateway cannot
			// read: the user's hook read it and listed each print target,
			// resolved (GAP-2178, GAP-0508). Facts keys start with NUL.
			for operand, resolved := range clientTargets {
				if !strings.HasPrefix(operand, "\x00") && (isProtected(operand) || isProtected(resolved)) {
					return true
				}
			}
		}
		for _, operand := range hookpaths.AdjacentAssignedWriteOperands(input.Command, input.CWD, input.ActiveHome) {
			if writeTarget(operand, false, false) {
				return true
			}
		}
		boundedOperands, boundedPattern := hookpaths.BoundedShellWriteOperands(input.Command, input.CWD, input.ActiveHome)
		if boundedPattern {
			// Bash expands the bound redirect as a pathname pattern at run
			// time, which may select a link to the protected file. The opened
			// file is unknown, so fail closed.
			return true
		}
		for _, operand := range boundedOperands {
			if writeTarget(operand, false, false) {
				return true
			}
		}
		for _, operand := range hookpaths.QuotedDynamicCopyDestinations(input.Command, input.CWD, input.ActiveHome) {
			if writeTarget(operand, false, true) {
				return true
			}
		}
		directoryOperands, directoryUnknown := hookpaths.ShellDirectoryWriteOperands(
			input.Command, input.CWD, input.ActiveHome, request.ResolvedWriteTargets, false, cannotResolveLocally,
		)
		if directoryUnknown {
			return true
		}
		for _, operand := range directoryOperands {
			if writeTarget(operand.Path, operand.Safe, false) {
				return true
			}
		}
		if cannotResolveLocally {
			// A managed gateway cannot place a command operand or an output
			// option in the user's home (install and dd of= destinations,
			// find -fprint, git config -f, gawk -i inplace, uniq and sort -o
			// outputs), so a write through an existing link to the keys
			// file was never judged. The user's hook lists every write
			// operand it found with the file it reaches; one that reaches a
			// protected file is a write to it, as a per-user gateway decides
			// from its own walk (GAP-2428). Facts keys start with NUL.
			for operand, resolved := range clientTargets {
				if !strings.HasPrefix(operand, "\x00") && isProtected(resolved) {
					return true
				}
			}
		}
	}
	// A native write call with a key outside its reviewed schema stays
	// partial and names no path; the harness still writes the file its
	// target key names (actionfacts.UnknownKeyWriteTargetViews), which the
	// hook's write evidence lists, so each such target is judged as well.
	views := append([]actionfacts.Facts{facts}, actionfacts.UnknownKeyWriteTargetViews(request.Input, facts)...)
	for _, view := range views {
		for _, candidate := range view.Paths {
			if candidate.Access != actionfacts.PathAccessWrite &&
				candidate.Access != actionfacts.PathAccessAppend {
				continue
			}
			command, ok := integrityCommandByID(view, candidate.CommandID)
			if !ok || !integrityCommandMutatesPath(command, candidate) ||
				((!(integrityExplicitCommandMutator(command, candidate)) && (command.Program != "dd" || !(command.ArgvComplete))) && !(integrityStructuredFileMutator(view, command))) {
				continue
			}
			target := candidate.Resolved
			// A POSIX shell running on Windows can leave a relative path
			// unresolved because ActionFacts does not reinterpret the Windows CWD
			// as a POSIX root. The owned, literal redirect still names a local
			// file relative to that CWD.
			if target == "" && command.Dialect == actionfacts.DialectPOSIX &&
				candidate.Flavor == actionfacts.PathFlavorPOSIX &&
				candidate.Normalized != "" && !isAbsoluteSemanticPath(candidate.Normalized) &&
				!strings.ContainsAny(candidate.Value, "*?[]$`\\") &&
				!strings.HasPrefix(candidate.Value, "~") &&
				integrityCommandOwnsStaticRedirect(command, candidate) {
				target = filepath.Join(view.CWD, filepath.FromSlash(candidate.Normalized))
			}
			// A structured write names its target from the event cwd. A
			// gateway that could not validate that cwd (ProtectHome) has no
			// resolved path for a relative target: place it in the client's
			// cwd, as the hook keyed it (hookpaths.ResolveConnector), or the
			// write through a link there was never judged.
			if target == "" && candidate.Normalized != "" && integrityStructuredFileMutator(view, command) &&
				!strings.ContainsAny(candidate.Normalized, "*?[]$`") && !strings.HasPrefix(candidate.Normalized, "~") {
				target = candidate.Normalized
			}
			if raw, ok := hookpaths.RawDotDotOperand(candidate.Value, clientCWD); ok {
				target = raw
			}
			ownCopy := hookpaths.IsCopyProgram(command.Argv) &&
				target == hookpaths.CopyDestination(command.Argv, clientCWD)
			if slices.Contains(operands, target) && integrityCommandOwnsStaticRedirect(command, candidate) {
				continue
			}
			if replacedBySed[target] && !isProtected(target) {
				continue
			}
			if writeTarget(target, false, ownCopy) {
				return true
			}
		}
	}
	// An apply_patch edit (its own tool or a shell wrapper) names its files
	// in the envelope. Its targets get the same decision as a redirect
	// operand; when they are unknown, the protected file may be one of them.
	patchTargets, patchKnown := hookpaths.ApplyPatchWriteTargets(
		request.Input.Tool, request.Input.Args, input.Command, clientCWD, facts.ActiveHome,
	)
	if !patchKnown && request.parentPatch != nil {
		// A pipeline stage that reads the envelope of its parent call
		// (@'...'@ | apply_patch). Every directive of the parent is placed in
		// this stage's directory and judged below; an apply_patch of the
		// parent that reads no literal envelope keeps the targets unknown.
		parent := *request.parentPatch
		patchTargets, patchKnown = hookpaths.ApplyPatchWriteTargets(
			parent.Tool, parent.Args, parent.Command, clientCWD, facts.ActiveHome,
		)
	}
	if !patchKnown && request.Connector == "copilot" && request.ProtectedHomeHook && input.Command == "" {
		// A managed gateway cannot traverse the user's private project, but
		// the native hook resolved every path before it sent the request.
		patchTargets, patchKnown = copilotClientProvedPatchTargets(
			request.Input.Tool, request.Input.Args, clientCWD, facts.ActiveHome, request.ResolvedWriteTargets,
		)
	}
	if !patchKnown && cannotResolveLocally && clientTargets != nil && !truncated {
		// Behind ProtectHome the gateway cannot resolve an envelope's
		// targets in the user's home; the user's hook resolved each one
		// (GAP-1106). A target the hook did not resolve stays unknown.
		if lexical, parsed := hookpaths.ApplyPatchLexicalCommandTargets(
			request.Input.Tool, request.Input.Args, input.Command, clientCWD, facts.ActiveHome,
		); parsed && filepath.IsAbs(clientCWD) {
			for _, target := range lexical {
				resolved := clientTargets[hookpaths.OperandPath(target, clientCWD)]
				if !filepath.IsAbs(resolved) || isProtected(resolved) || isProtected(target) {
					return true
				}
			}
			return false
		}
	}
	if !patchKnown && cannotResolveLocally && clientTargets != nil && !truncated &&
		hookpaths.ApplyPatchStagedFeed(request.Input.Args, input.Command) {
		// A staged patch file this gateway cannot read: the user's hook read
		// it and listed each directive target, resolved (classifier refix 1).
		for operand, resolved := range clientTargets {
			if isProtected(operand) || isProtected(resolved) {
				return true
			}
		}
	}
	if !patchKnown {
		// Unknown targets (no readable envelope, apply_patch --help, a
		// lookup of the program) reach the rule only when the call names a
		// protected target: no protected-named word is never blocked
		// (TGT-0194; GAP-0781, GAP-1106, GAP-1741, GAP-1872). A staged patch
		// file is read above; only one that cannot be read reaches here. An apply_patch
		// tool call that reaches here with no patch text (a connector
		// refused or bounded it) stays unknown.
		if hookpaths.ApplyPatchToolWithoutText(request.Input.Tool, request.Input.Args) {
			return true
		}
		return hookpaths.PatchCallNamesProtectedTarget(
			request.Input.Tool, request.Input.Args, input.Command, clientCWD, facts.ActiveHome, clientTargets,
		) || hookpaths.PatchCallNamesProtectedTarget("", nil, request.LegacyText, clientCWD, facts.ActiveHome, clientTargets)
	}
	for _, target := range patchTargets {
		if writeTarget(target, false, false) {
			return true
		}
	}
	return false
}

// trustedPOSIXShellCall reports a call a POSIX shell runs (Bash tool,
// POSIX dialect), which Git Bash runs on a Windows host.
func trustedPOSIXShellCall(input actionfacts.Input, facts actionfacts.Facts) bool {
	return input.DialectHint == actionfacts.DialectPOSIX || input.DialectHint == "" && facts.Parse.Dialect == actionfacts.DialectPOSIX
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
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

type authorizedKeysDirectoryPaths struct {
	isAbs func(string) bool
	join  func(...string) string
	clean func(string) string
}

// resolveAuthorizedKeysShellDirectory uses the command dialect for path
// syntax. A POSIX shell can report /home paths to a gateway running on Windows.
func resolveAuthorizedKeysShellDirectory(input actionfacts.Input, current, directory string) (string, bool) {
	native := authorizedKeysDirectoryPaths{filepath.IsAbs, filepath.Join, filepath.Clean}
	return resolveAuthorizedKeysShellDirectoryWithNative(input, current, directory, native)
}

func resolveAuthorizedKeysShellDirectoryWithNative(
	input actionfacts.Input, current, directory string, native authorizedKeysDirectoryPaths,
) (string, bool) {
	posix := authorizedKeysDirectoryPaths{path.IsAbs, path.Join, path.Clean}
	// The anchor path picks the syntax. A POSIX command on Windows can still
	// start from the native home or working directory (C:\Users\alice).
	syntaxFor := func(anchor string) authorizedKeysDirectoryPaths {
		if input.DialectHint == actionfacts.DialectCMD || input.DialectHint == actionfacts.DialectPowerShell ||
			!posix.isAbs(anchor) && native.isAbs(anchor) {
			return native
		}
		return posix
	}
	var paths authorizedKeysDirectoryPaths
	switch {
	case directory == "~":
		directory = input.ActiveHome
		paths = syntaxFor(directory)
	case strings.HasPrefix(directory, "~/"):
		paths = syntaxFor(input.ActiveHome)
		directory = paths.join(input.ActiveHome, directory[2:])
	default:
		paths = syntaxFor(directory)
		if !paths.isAbs(directory) {
			base := current
			if base == "" {
				base = input.CWD
			}
			paths = syntaxFor(base)
			if !paths.isAbs(base) {
				return "", false
			}
			directory = paths.join(base, directory)
		}
	}
	return paths.clean(directory), true
}

// trustedHomeDirectoryAuthorizedKeysWrite checks a static directory change
// followed by a separately parsed write. The shell parser supplies the
// statement boundaries; the ordinary action analyzer supplies the write fact.
func trustedHomeDirectoryAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || input.ActiveHome == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(input.Command), "")
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
			// cd ~/.ssh || exit 1 is read as the cd taking effect.
			return (binary.Op == syntax.AndStmt || binary.Op == syntax.OrStmt) &&
				collect(binary.X) && collect(binary.Y)
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
		program, static := hookpaths.StaticWord(call.Args[0], input.ActiveHome)
		directoryArg := 1
		if static && (program == "builtin" || program == "command") && len(call.Args) > 1 {
			program, static = hookpaths.StaticWord(call.Args[1], input.ActiveHome)
			directoryArg = 2
		}
		if static && (program == "cd" || program == "pushd") {
			// cd -P, -L, -e and -- change how links in the path are read, not
			// which directory it names.
			for directoryArg < len(call.Args) {
				option, ok := hookpaths.StaticWord(call.Args[directoryArg], input.ActiveHome)
				if !ok || option != "--" && (len(option) < 2 || option[0] != '-' ||
					strings.Trim(option[1:], "PLe@") != "") {
					break
				}
				directoryArg++
				if option == "--" {
					break
				}
			}
			if len(call.Args) > directoryArg+1 {
				return false
			}
			directory := input.ActiveHome
			if len(call.Args) == directoryArg+1 {
				var ok bool
				directory, ok = hookpaths.StaticWord(call.Args[directoryArg], input.ActiveHome)
				if !ok || directory == "-" {
					return false
				}
			}
			var ok bool
			workingDirectory, ok = resolveAuthorizedKeysShellDirectory(input, workingDirectory, directory)
			if !ok {
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

func interpreterCommentStart(code string, i int, language string) bool {
	switch language {
	case "python", "ruby":
		return true
	case "perl":
		return i == 0 || code[i-1] != '$'
	default:
		return false
	}
}
