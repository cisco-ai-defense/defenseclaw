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
// mv, install and ln call that has a runtime-expanded operand word has only
// static operands, so the role of each literal operand is known (GAP-2477).
// One runtime-expanded word makes the whole argv partial and ties no path to
// the call, so "cp a.txt ~/.defenseclaw/config.yaml $(true)" and
// "cp $SRC ~/.defenseclaw/config.yaml" named no write at all.
//
// Only words that the shell expands from a parameter, a command or
// arithmetic count; a call with a filename pattern, brace or tilde word that
// is not home-anchored keeps the readings the glob resolver already gives it,
// and has no twin. The first reading has each expanded word as one plain
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
	source := command
	if home, _ := normalizeActiveHome(activeHome); home != "" {
		home = strings.TrimRight(home, "/")
		if posixShellHome(home) && !strings.ContainsAny(home, "\x00\r\n") {
			if resolved, ok := homeResolvedSource(source, home); ok {
				source = resolved
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
		program := projectPOSIXWord(call.Args[0])
		if program.Expands {
			return true
		}
		switch program.Value {
		case "cp", "mv", "install", "ln":
		default:
			return true
		}
		last := -1
		for index := 1; index < len(call.Args); index++ {
			word := call.Args[index]
			if !projectPOSIXWord(word).Expands {
				last = index
			} else if !runtimeExpansionWord(word) {
				return false
			}
		}
		trailing := last > 0 && last < len(call.Args)-1
		var callPlain, callVanished []edit
		for index := 1; index < len(call.Args); index++ {
			word := call.Args[index]
			if !projectPOSIXWord(word).Expands {
				continue
			}
			start, end := int(word.Pos().Offset()), int(word.End().Offset())
			if start < 0 || end <= start || end > len(source) {
				invalid = true
				return false
			}
			replaced := edit{start: start, end: end, text: DynamicOperandPlaceholder}
			callPlain = append(callPlain, replaced)
			if index > last {
				if !vanishingWord(word) {
					trailing = false
				}
				replaced.text = ""
			}
			callVanished = append(callVanished, replaced)
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
