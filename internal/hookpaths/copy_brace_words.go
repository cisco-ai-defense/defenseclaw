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
// reading of the call (nil).
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
