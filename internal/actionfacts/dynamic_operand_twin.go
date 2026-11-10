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
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// DynamicOperandPlaceholder is the name a runtime-expanded operand word of
// cp, mv, install or ln is read as in DynamicOperandTwins: an existing file
// that is never protected state, so as a source or a destination it adds no
// target of its own (a made-up name would be an unknown target to a hook
// client map behind ProtectHome).
const DynamicOperandPlaceholder = "/dev/null"

// DynamicOperandTwins returns POSIX readings of command in which every cp,
// mv, install, ln, dd and tee call (also by a path such as /bin/cp, or run
// through command, env, sudo, exec or nohup) that has a runtime-expanded
// operand word has only static operands, so the role of each literal operand
// is known (GAP-2477). A key=value operand keeps its key (dd if=$SRC is read
// as dd if=/dev/null).
// One runtime-expanded word makes the whole argv partial and ties no path to
// the call, so "cp a.txt ~/.defenseclaw/config.yaml $(true)" and
// "cp $SRC ~/.defenseclaw/config.yaml" named no write at all.
//
// Words that the shell expands from a parameter, a command or arithmetic
// count, and a filename pattern, brace or tilde word that is a source of cp,
// mv, install or ln (patternSourceWord): what such a word expands to never
// changes which operand is the destination, so it is read as one plain name
// too (GAP-1053). A call with a pattern word in a destination or option-value
// position keeps the readings the glob resolver already gives it, and has no
// twin. The first reading has each expanded word as one plain
// name. The second,
// returned only when some call ends in unquoted words that are a lone
// command substitution or plain parameter expansion (which expand to no
// word at all when empty), drops those trailing words, so the last literal
// operand is the destination, as it is when the shell runs it. Home-anchored
// words (~/, $HOME/, ${HOME}/) are first written as the active home when the
// source rewrite of HomeResolvedTwin accepts the command. Each reading is
// one way the command can run, so a caller may count a block proven on a
// reading as a block of the command; nothing else counts.
func DynamicOperandTwins(command, activeHome string) (twins []string) {
	defer func() {
		if recover() != nil {
			twins = nil
		}
	}()
	source, userHome := command, ""
	if home, _ := normalizeActiveHome(activeHome); home != "" {
		home = strings.TrimRight(home, "/")
		if posixShellHome(home) && !strings.ContainsAny(home, "\x00\r\n") {
			if resolved, ok := homeResolvedSource(source, home); ok {
				source = resolved
			}
			if strings.HasPrefix(home, "/") {
				userHome = home
			}
		}
	}
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return nil
	}
	type edit struct {
		start, end int
		text       string
	}
	var plain, vanished []edit
	trailingCall := false
	invalid := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if invalid {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		first, known := dynamicOperandProgram(call.Args)
		if !known {
			return true
		}
		last, respelled, replaced := -1, map[int]string{}, false
		for index := first; index < len(call.Args); index++ {
			word := call.Args[index]
			if !projectPOSIXWord(word).Expands {
				last = index
			} else if below, user := userHomeRewriteWord(word, userHome); userHome != "" && user {
				// A path below the home spelled through USER or LOGNAME
				// (/home/$USER/f) is the home path: it keeps its role as a
				// destination in the reading (GAP-1053).
				respelled[index], last = userHome+below, index
			} else if !runtimeExpansionWord(word) && !patternSourceWord(call.Args, first, index) {
				return false
			} else {
				replaced = true
			}
		}
		if !replaced {
			return false
		}
		trailing := last >= first && last < len(call.Args)-1
		var callPlain, callVanished []edit
		for index := first; index < len(call.Args); index++ {
			word := call.Args[index]
			if !projectPOSIXWord(word).Expands {
				continue
			}
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < 0 || end <= start || end > len(source) {
				invalid = true
				return false
			}
			text := operandKeyPrefix(word) + DynamicOperandPlaceholder
			if path, user := respelled[index]; user {
				text = path
			}
			rewrite := edit{start: start, end: end, text: text}
			callPlain = append(callPlain, rewrite)
			if index > last {
				if !vanishingWord(word) {
					trailing = false
				}
				rewrite.text = ""
			}
			callVanished = append(callVanished, rewrite)
		}
		plain = append(plain, callPlain...)
		if trailing {
			trailingCall = true
			vanished = append(vanished, callVanished...)
		} else {
			vanished = append(vanished, callPlain...)
		}
		// The call is rewritten as a whole: a call nested in one of its
		// words is replaced with that word.
		return false
	})
	if invalid || len(plain) == 0 {
		return nil
	}
	apply := func(edits []edit) (string, bool) {
		sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
		var out strings.Builder
		last := 0
		for _, change := range edits {
			if change.start < last {
				return "", false
			}
			out.WriteString(source[last:change.start])
			out.WriteString(change.text)
			last = change.end
		}
		out.WriteString(source[last:])
		return out.String(), true
	}
	if twin, ok := apply(plain); ok {
		twins = append(twins, twin)
	}
	if trailingCall {
		if twin, ok := apply(vanished); ok {
			twins = append(twins, twin)
		}
	}
	return twins
}

// patternSourceWord reports a filename pattern, brace or tilde word of a cp,
// mv, install or ln call (operands from first) that is a source operand
// whatever it expands to: not an option and not the value of one, and not
// the last operand, which names the destination, unless a target-directory
// option names the destination and so makes every operand a source.
func patternSourceWord(args []*syntax.Word, first, index int) bool {
	if first < 1 || index < first || index >= len(args) {
		return false
	}
	name := projectPOSIXWord(args[first-1]).Value
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		name = name[slash+1:]
	}
	switch name {
	case "cp", "mv", "install", "ln":
	default:
		return false
	}
	if len(args[index].Parts) > 0 && partStartsWithDash(args[index].Parts[0]) {
		return false
	}
	targetDirectory := false
	for before := first; before < index; before++ {
		option := projectPOSIXWord(args[before])
		if option.Expands || !strings.HasPrefix(option.Value, "-") || option.Value == "-" {
			continue
		}
		if targetDirectoryOption(option.Value) {
			targetDirectory = true
		}
		if before == index-1 && optionTakesNextWord(option.Value) {
			return false
		}
	}
	return index < len(args)-1 || targetDirectory
}

func partStartsWithDash(part syntax.WordPart) bool {
	lit, ok := part.(*syntax.Lit)
	return ok && strings.HasPrefix(lit.Value, "-")
}

// targetDirectoryOption reports a cp, mv, install or ln option word that
// names the target directory: -t (also joined or inside a cluster) or any
// abbreviation of --target-directory.
func targetDirectoryOption(option string) bool {
	if name, ok := strings.CutPrefix(option, "--"); ok {
		name, _, _ = strings.Cut(name, "=")
		return len(name) >= 2 && strings.HasPrefix("target-directory", name)
	}
	return strings.ContainsRune(option[1:], 't')
}

// optionTakesNextWord reports an option word that, as the word before an
// operand, may take it as its value: anything but a known cluster of switches
// or a long option with its value attached.
func optionTakesNextWord(option string) bool {
	if name, ok := strings.CutPrefix(option, "--"); ok {
		if strings.Contains(name, "=") {
			return false
		}
		switch name {
		case "force", "recursive", "archive", "verbose", "no-clobber", "interactive", "preserve",
			"parents", "update", "link", "symbolic-link", "symbolic", "dereference", "no-dereference",
			"remove-destination", "no-target-directory", "strip-trailing-slashes", "one-file-system",
			"attributes-only", "copy-contents", "relative", "logical", "physical", "directory", "":
			return false
		}
		return true
	}
	for _, letter := range option[1:] {
		if !strings.ContainsRune("abcCdDfHilLnpPrRsTuvx", letter) {
			return true
		}
	}
	return false
}

// runtimeExpansionWord reports a word whose expansion comes from a
// parameter, a command substitution or arithmetic (not only from a filename
// pattern, brace or tilde), with no unquoted pattern character beside it.
func runtimeExpansionWord(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	runtime := false
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(typed.Value, "*?[{~") {
				return false
			}
		case *syntax.SglQuoted:
		case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
			runtime = true
		case *syntax.DblQuoted:
			for _, inner := range typed.Parts {
				switch inner.(type) {
				case *syntax.Lit:
				case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp:
					runtime = true
				default:
					return false
				}
			}
		default:
			return false
		}
	}
	return runtime
}

// vanishingWord reports an unquoted word that is only a command substitution
// or a plain parameter expansion: when its value is empty the shell drops
// the word, so the argv has one word fewer.
func vanishingWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	switch part := word.Parts[0].(type) {
	case *syntax.CmdSubst:
		return true
	case *syntax.ParamExp:
		return part.Param != nil && part.Exp == nil && part.Repl == nil && part.Slice == nil &&
			part.Index == nil && !part.Length && !part.Width && !part.Excl && !part.IsSet &&
			part.Names == 0 && part.NestedParam == nil && len(part.Modifiers) == 0
	}
	return false
}

// dynamicOperandPrograms are the file-writing programs whose operands
// DynamicOperandTwins reads.
var dynamicOperandPrograms = map[string]bool{
	"cp": true, "mv": true, "install": true, "ln": true, "dd": true, "tee": true,
}

// dynamicOperandProgram returns the index of the first operand of a
// dynamicOperandPrograms call: the program may be named by a path
// (/usr/bin/cp) and run through command, env (with NAME=value words), sudo,
// exec or nohup with no options of their own. Any other wrapper form, or a
// program word the shell expands, is not read.
func dynamicOperandProgram(args []*syntax.Word) (int, bool) {
	env := false
	for index := 0; index < len(args)-1; index++ {
		word := projectPOSIXWord(args[index])
		if word.Expands || word.Value == "" {
			return 0, false
		}
		if env && strings.Contains(word.Value, "=") && !strings.HasPrefix(word.Value, "=") {
			// A NAME=value word of env.
			continue
		}
		name := word.Value
		if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
			name = name[slash+1:]
		}
		if dynamicOperandPrograms[name] {
			return index + 1, true
		}
		switch name {
		case "command", "sudo", "exec", "nohup", "env":
			env = name == "env"
		default:
			return 0, false
		}
		if next := projectPOSIXWord(args[index+1]); next.Expands || strings.HasPrefix(next.Value, "-") {
			return 0, false
		}
	}
	return 0, false
}

// operandKeyPrefix returns the literal key= at the start of a word (if= of
// dd if=$SRC, --target-directory= of cp), which the reading keeps.
func operandKeyPrefix(word *syntax.Word) string {
	if word == nil || len(word.Parts) == 0 {
		return ""
	}
	lit, ok := word.Parts[0].(*syntax.Lit)
	if !ok {
		return ""
	}
	key, _, found := strings.Cut(lit.Value, "=")
	if !found || key == "" || strings.ContainsAny(key, "/\\") {
		return ""
	}
	return key + "="
}
