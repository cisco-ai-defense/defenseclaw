// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// maxCopyBraceWords bounds the argv a copy call with brace words is read
// as: the brace budget every reader checks first (shellparse.TooDeep), so a
// command this reader sees is read in full, and one past the budget takes
// the evaluation limit before any reader expands it (GAP-0187).
const maxCopyBraceWords = shellparse.MaxBraceFields

// braceOperandPrograms are the writers whose plain brace operands the
// literal write reader expands before it lists their targets: the copy
// programs (GAP-0202) and the writers that name a target file as an
// operand (GAP-0228). A brace operand of any of them is several fixed
// words bash expands before the program runs.
var braceOperandPrograms = []string{
	"cp", "gcp", "tee", "gtee", "dd", "gdd", "sed", "gsed", "truncate", "gtruncate",
	"install", "ginstall", "mv", "gmv", "ln", "gln",
}

// copyBraceWordFields returns, by argv index, the words bash makes of each
// copy operand spelled as a brace expansion of plain text (cp a.txt{,.orig},
// cp {a.txt,b.txt} dir): bash expands such a word to several fixed words
// before cp runs, so the call is read with them, the way the hook client
// and ActionCommandDecision judge the real targets (rel-1-0-6 GAP-0202).
// The shell expands a leading ~/ of a field to the home, as Fields does,
// and removes the quotes of a quoted part ("key"{s,x}, key{"s",x}) and a
// $HOME the reader knows. An empty field is dropped, as bash drops it
// ({,keylink} is keylink; GAP-0228). A word with another parameter, a
// substitution or an unquoted pattern stays dynamic, and a field that keeps
// a tilde (~user) or a call past maxCopyBraceWords words keeps the dynamic
// reading of the call (nil); a range that alone takes the call past it is
// refused before it is expanded (GAP-0568).
func copyBraceWordFields(args []*syntax.Word, static []bool, env expand.Environ) map[int][]string {
	var fields map[int][]string
	total := len(args)
	for i, arg := range args {
		if i == 0 || static[i] || arg == nil || len(arg.Parts) == 0 {
			continue
		}
		braced := *arg
		if !braceWordFixed(arg.Parts, env) || !syntax.SplitBraces(&braced) {
			continue
		}
		// A brace range already past the cap is refused before it is
		// expanded (rel-1-0-2 GAP-0568). MinBraceFields never exceeds the
		// non-empty fields the range makes (each range element is a
		// non-empty literal), so this is the cap check below done early,
		// with the same answer: the dynamic reading of the call (nil).
		if uint64(total)+shellparse.MinBraceFields(arg) > maxCopyBraceWords+1 {
			return nil
		}
		expanded, err := expand.Fields(&expand.Config{Env: env}, arg)
		if err != nil {
			return nil
		}
		words := make([]string, 0, len(expanded))
		for _, word := range expanded {
			if strings.HasPrefix(word, "~") {
				return nil
			}
			if word != "" {
				words = append(words, word)
			}
		}
		total += len(words) - 1
		if total > maxCopyBraceWords {
			return nil
		}
		if fields == nil {
			fields = make(map[int][]string)
		}
		fields[i] = words
	}
	return fields
}

// braceWordFixed reports whether parts expand to fixed text: unquoted
// literals without a pattern, quoted literals, and $HOME or ${HOME} when env
// knows the home.
func braceWordFixed(parts []syntax.WordPart, env expand.Environ) bool {
	haveHome := env.Get("HOME").String() != ""
	for _, part := range parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return false
			}
		case *syntax.SglQuoted:
			if part.Dollar {
				return false
			}
		case *syntax.DblQuoted:
			if part.Dollar {
				return false
			}
			for _, inner := range part.Parts {
				switch inner := inner.(type) {
				case *syntax.Lit:
				case *syntax.ParamExp:
					if !homeParam(inner, haveHome) {
						return false
					}
				default:
					return false
				}
			}
		case *syntax.ParamExp:
			if !homeParam(part, haveHome) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// spliceCopyBraceWords returns args, words and static with each word that
// fields lists replaced by its words, as plain literal words at the place of
// the word they come from.
func spliceCopyBraceWords(args []*syntax.Word, words []string, static []bool, fields map[int][]string) ([]*syntax.Word, []string, []bool) {
	if len(fields) == 0 {
		return args, words, static
	}
	outArgs := make([]*syntax.Word, 0, len(args)+len(fields))
	outWords := make([]string, 0, cap(outArgs))
	outStatic := make([]bool, 0, cap(outArgs))
	for i, arg := range args {
		expanded, ok := fields[i]
		if !ok {
			outArgs, outWords, outStatic = append(outArgs, arg), append(outWords, words[i]), append(outStatic, static[i])
			continue
		}
		for _, word := range expanded {
			lit := &syntax.Lit{ValuePos: arg.Pos(), ValueEnd: arg.End(), Value: word}
			outArgs = append(outArgs, &syntax.Word{Parts: []syntax.WordPart{lit}})
			outWords, outStatic = append(outWords, word), append(outStatic, true)
		}
	}
	return outArgs, outWords, outStatic
}

// maxMentionBraceFields bounds the words the target scan reads of one brace
// word. A word whose ranges alone make more is not expanded, so a long
// benign range stays inside the hook deadline (GAP-0568).
const maxMentionBraceFields = 256

// actionMentionBraceFields returns the words bash makes of a brace word of
// fixed text (copyBraceWordFields: plain or quoted literals and a known
// $HOME, empty fields dropped), for the target scan to judge each one as if
// it were spelled out: a brace word whose expansion names the keys file
// (touch <keys>{s,x}, a substitution that prints <keys>{s..s}) was read as
// its unexpanded text and named no file (rel-1-0-6:GAP-0233, GAP-0255).
// It returns nil for a word with no brace, a dynamic word, or one past
// maxMentionBraceFields words.
func actionMentionBraceFields(word *syntax.Word, home string) []string {
	if word == nil || !actionWordHasBraceText(word) || shellparse.MinBraceFields(word) > maxMentionBraceFields {
		return nil
	}
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	fields := copyBraceWordFields([]*syntax.Word{nil, word}, []bool{true, false}, env)[1]
	if len(fields) > maxMentionBraceFields {
		return nil
	}
	return fields
}

// A touch range just past the shared 256-field cap is still cheap enough
// to read exactly. The same fields feed the client and gateway decisions.
func actionExactOversizedTouchFields(word *syntax.Word, home string) []string {
	if word == nil || !actionWordHasBraceText(word) || shellparse.MinBraceFields(word) <= maxMentionBraceFields ||
		shellparse.MinBraceFields(word) > 1024 {
		return nil
	}
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	fields := copyBraceWordFields([]*syntax.Word{nil, word}, []bool{true, false}, env)[1]
	if len(fields) > 1024 {
		return nil
	}
	return fields
}

// actionWordHasBraceText reports an unquoted literal part with a {.
func actionWordHasBraceText(word *syntax.Word) bool {
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, "{") {
			return true
		}
	}
	return false
}

// touchBraceWriteOperands returns the words bash makes of each brace file
// operand of a touch (or gtouch) call, for the concrete-write decision the
// hook client sends as ActionDecisionKey: a brace touch onto the keys file,
// or onto a project link to it, updates that file as the plain touch does
// (rel-1-0-6:GAP-0233). They are not listed in the client target map, so a
// long benign touch cannot overflow it (GAP-0151). The values of -d, -r and
// -t (and --date, --reference, --time) are not files touch writes.
func touchBraceWriteOperands(command, home string) []string {
	if !strings.Contains(command, "touch") || !strings.Contains(command, "{") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var operands []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return true
		}
		touchBraceFileOperands(call, home, func(word *syntax.Word) bool {
			fields := actionMentionBraceFields(word, home)
			if len(fields) == 0 {
				fields = actionExactOversizedTouchFields(word, home)
			}
			operands = append(operands, fields...)
			return true
		})
		return true
	})
	return operands
}

// touchBraceFileOperands visits file operands once per touch call. Both the
// concrete brace reader and the over-cap target reader use this option scan.
func touchBraceFileOperands(call *syntax.CallExpr, home string, visit func(*syntax.Word) bool) {
	if call == nil || len(call.Args) < 2 {
		return
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || programBase(program) != "touch" && programBase(program) != "gtouch" {
		return
	}
	options := true
	for i := 1; i < len(call.Args); i++ {
		word := call.Args[i]
		if options {
			if value, fixed := StaticWord(word, home); fixed && strings.HasPrefix(value, "-") && value != "-" {
				switch value {
				case "--":
					options = false
				case "-d", "-r", "-t", "--date", "--reference", "--time":
					i++
				}
				continue
			}
		}
		if !visit(word) {
			return
		}
	}
}
