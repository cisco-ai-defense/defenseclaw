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

// copyBraceWordFields returns, by argv index, the words bash makes of each
// copy operand spelled as a brace expansion of plain text (cp a.txt{,.orig},
// cp {a.txt,b.txt} dir): bash expands such a word to several fixed words
// before cp runs, so the call is read with them, the way the hook client
// and ActionCommandDecision judge the real targets (rel-1-0-6 GAP-0202).
// The shell expands a leading ~/ of a field to the home, as Fields does. A
// word with a quote, parameter, substitution or pattern, a field that is
// empty or keeps a tilde (~user), and a call past maxCopyBraceWords words
// keep the dynamic reading (nil).
func copyBraceWordFields(args []*syntax.Word, static []bool, env expand.Environ) map[int][]string {
	var fields map[int][]string
	total := len(args)
	for i, arg := range args {
		if i == 0 || static[i] || arg == nil || len(arg.Parts) == 0 {
			continue
		}
		plain := true
		for _, part := range arg.Parts {
			lit, ok := part.(*syntax.Lit)
			if !ok || strings.ContainsAny(lit.Value, "*?[") {
				plain = false
				break
			}
		}
		braced := *arg
		if !plain || !syntax.SplitBraces(&braced) {
			continue
		}
		if uint64(total)+shellparse.MinBraceFields(arg) > maxCopyBraceWords+1 {
			return nil
		}
		words, err := expand.Fields(&expand.Config{Env: env}, arg)
		if err != nil || len(words) < 2 {
			return nil
		}
		total += len(words) - 1
		if total > maxCopyBraceWords {
			return nil
		}
		for _, word := range words {
			if word == "" || strings.HasPrefix(word, "~") {
				return nil
			}
		}
		if fields == nil {
			fields = make(map[int][]string)
		}
		fields[i] = words
	}
	return fields
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
