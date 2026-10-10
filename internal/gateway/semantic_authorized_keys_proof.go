// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"mvdan.cc/sh/v3/syntax"
)

// These bounded proofs reuse ActionFacts and the shell syntax tree for
// authorized-keys writes whose complete action remains partially parsed.
// A proof adds only a positive finding; a failed proof leaves the original
// action and its fallback handling unchanged.

var (
	trustedPathlibAuthorizedKeysWrite    = regexp.MustCompile(`(?s)\bp\s*=\s*(?:pathlib\.)?Path\.home\(\)\s*/\s*['"]\.ssh['"]\s*/\s*['"]authorized_keys['"];.*\bp\.write_text\(`)
	trustedPythonPathAuthorizedKeysWrite = regexp.MustCompile(`(?s)\bPath\s*\(\s*['"]~/\.ssh/authorized_keys['"]\s*\)\.expanduser\s*\(\s*\)\.write_text\s*\(`)
	trustedPerlAuthorizedKeysWrite       = regexp.MustCompile(`^open\(F,\s*">>",\s*"\$ENV\{HOME\}/\.ssh/authorized_keys"\);\s*print F "[^"\\]*(?:\\n)?";?(?:\s*close\(F\))?$`)
	trustedCMDInvoke                     = regexp.MustCompile(`(?is)^cmd(?:\.exe)?\s+/c\s+(.+)$`)
	trustedOutFileAppend                 = regexp.MustCompile(`(?is)^\s*(?:"[^"\r\n]*"|'[^'\r\n]*')\s*\|\s*out-file\s+-append\s+-filepath\s+(.+?)\s*$`)
	trustedInterpreterKeysPath           = regexp.MustCompile(`(?:~|\$HOME|\$ENV\{HOME\}|/[A-Za-z0-9_./ -]+)/\.ssh/authorized_keys(?:2)?`)
	trustedInterpreterOpenCall           = regexp.MustCompile(`\b(?:open|File\.open|fs\.openSync)\s*\(`)
	trustedInterpreterWriteMode          = regexp.MustCompile(`['"](?:[awx](?:[bt]?\+?|\+[bt]?)|r(?:[bt]?\+|\+[bt]?)|>>|>)['"]`)
	trustedInterpreterWriteCall          = regexp.MustCompile(`\b(?:appendFileSync|writeFileSync|File\.write|File\.binwrite)\s*\(`)
)

func trustedCMDBody(input actionfacts.Input) (string, bool) {
	if len(input.Command) > 64<<10 || input.Command == "" ||
		!strings.Contains(input.ActiveHome, ":/") {
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
	case "python", "python3":
		return command.Argv[1] == "-c" && facts.ActiveHome != "" &&
			(trustedPathlibAuthorizedKeysWrite.MatchString(command.Argv[2]) ||
				trustedPythonPathAuthorizedKeysWrite.MatchString(command.Argv[2]) ||
				trustedInterpreterAuthorizedKeysWrite(command.Argv[2], facts.ActiveHome))
	case "perl":
		return command.Argv[1] == "-e" && facts.ActiveHome != "" &&
			(trustedPerlAuthorizedKeysWrite.MatchString(command.Argv[2]) ||
				trustedInterpreterAuthorizedKeysWrite(command.Argv[2], facts.ActiveHome))
	case "ruby", "node":
		return command.Argv[1] == "-e" && facts.ActiveHome != "" &&
			trustedInterpreterAuthorizedKeysWrite(command.Argv[2], facts.ActiveHome)
	default:
		return false
	}
}

// A redirection truncates its target before the command runs. In particular,
// a shell no-op (or a redirect without a command) still changes the file.
func trustedNoOpAuthorizedKeysRedirect(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 1 {
		return false
	}
	stmt := file.Stmts[0]
	if stmt.Background || stmt.Negated || stmt.Redirs[0].Op != syntax.RdrOut {
		return false
	}
	if stmt.Cmd != nil {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) != 1 ||
			len(call.Args[0].Parts) != 1 {
			return false
		}
		literal, ok := call.Args[0].Parts[0].(*syntax.Lit)
		if !ok || literal.Value != ":" {
			return false
		}
	}
	return trustedAuthorizedKeysRedirectTarget(input, stmt.Redirs[0].Word)
}

func trustedHereStringAuthorizedKeysWrite(input actionfacts.Input) bool {
	if input.Command == "" || len(input.Command) > 64<<10 {
		return false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(input.Command), "")
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
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), "")
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

func trustedInterpreterAuthorizedKeysWrite(code, activeHome string) bool {
	if len(code) == 0 || len(code) > 16<<10 ||
		!trustedAuthorizedKeysPathInText(code, activeHome) {
		return false
	}
	for _, location := range trustedInterpreterOpenCall.FindAllStringIndex(code, -1) {
		if !interpreterCodePosition(code, location[0]) {
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
		if !interpreterCodePosition(code, location[0]) {
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
			if c == '\\' {
				i++
			} else if c == quote {
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

func interpreterCodePosition(code string, position int) bool {
	var quote byte
	for i := 0; i < position; i++ {
		c := code[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		}
	}
	return quote == 0
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
		if relative, ok := liveHomeRelative(value); ok &&
			(relative == ".ssh/authorized_keys" || relative == ".ssh/authorized_keys2") {
			return true
		}
		if activeHome != "" &&
			(value == strings.TrimRight(activeHome, "/")+"/.ssh/authorized_keys" ||
				value == strings.TrimRight(activeHome, "/")+"/.ssh/authorized_keys2") {
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
			if c == '\\' {
				i++
			} else if c == quote {
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
	if err != nil {
		return false
	}
	word := func(value *syntax.Word) string {
		if value == nil {
			return ""
		}
		if len(value.Parts) != 1 {
			return ""
		}
		switch part := value.Parts[0].(type) {
		case *syntax.Lit:
			return part.Value
		case *syntax.SglQuoted:
			return part.Value
		case *syntax.DblQuoted:
			if len(part.Parts) == 1 {
				if literal, ok := part.Parts[0].(*syntax.Lit); ok {
					return literal.Value
				}
			}
		}
		return ""
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
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
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
			if operand != "" {
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
	active := canonicalSemanticPath(filepath.Join(facts.ActiveHome, ".ssh", "authorized_keys"))
	clientCWD := facts.CWD
	if !filepath.IsAbs(clientCWD) {
		if cwd := request.ResolvedWriteTargets[hookpaths.CWDKey]; filepath.IsAbs(cwd) {
			clientCWD = filepath.Clean(cwd)
		}
	}
	writeTarget := func(target string) bool {
		if !filepath.IsAbs(target) {
			return false
		}
		target = filepath.Clean(target)
		underHome := false
		if relative, err := filepath.Rel(facts.ActiveHome, target); err == nil {
			underHome = relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
		}
		if request.ResolvedWriteTargets != nil {
			resolved, present := request.ResolvedWriteTargets[target]
			return present && canonicalSemanticPath(resolved) == active ||
				underHome && (!present || resolved == "")
		}
		if request.SkipLocalFilesystemResolution {
			return false
		}
		info, err := os.Lstat(target)
		if err != nil {
			return underHome && request.ProtectedHomeHook
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return false
		}
		resolved, err := filepath.EvalSymlinks(target)
		return err == nil && canonicalSemanticPath(resolved) == active ||
			err != nil && underHome && request.ProtectedHomeHook
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
	if input.Command != "" && len(input.Command) <= 64<<10 {
		if file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(strings.NewReader(input.Command), ""); err == nil {
			matched := false
			syntax.Walk(file, func(node syntax.Node) bool {
				redirect, ok := node.(*syntax.Redirect)
				if !ok || redirect.Word == nil ||
					(redirect.Op != syntax.RdrOut && redirect.Op != syntax.AppOut) {
					return true
				}
				start, end := int(redirect.Word.Pos().Offset()), int(redirect.Word.End().Offset())
				if start < 0 || end > len(input.Command) || end <= start {
					return true
				}
				name := strings.Trim(input.Command[start:end], `"'`)
				if name == "" || strings.ContainsAny(name, "*?[]`") ||
					strings.Contains(name, "$") && !strings.HasPrefix(name, "$HOME/") {
					return true
				}
				matched = matched || writeTarget(trustedSymlinkName(input, name))
				return !matched
			})
			if matched {
				return true
			}
		}
	}
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite &&
			candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		command, ok := integrityCommandByID(facts, candidate.CommandID)
		if !ok || !integrityCommandMutatesPath(command, candidate) ||
			!(integrityExplicitCommandMutator(command, candidate) ||
				integrityStructuredFileMutator(facts, command)) {
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
			target = filepath.Join(facts.CWD, filepath.FromSlash(candidate.Normalized))
		}
		if writeTarget(target) {
			return true
		}
	}
	return false
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
