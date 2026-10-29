// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// xargsStaticInputStateMutation judges `printf '%s\n' WORD... | xargs CMD`
// and `echo WORD... | xargs CMD` (rel-1-0-5 GAP-0052): the input of xargs
// is the static words, so the action is judged as the call xargs makes with
// them (`printf %s\\n ~/.defenseclaw/policies | xargs rm -rf` is
// `rm -rf ~/.defenseclaw/policies`). ActionFacts does not model the xargs
// stdin, so the state delete had no path fact and ran in every mode. The
// twin goes through the whole dispatcher, the way its direct spelling is
// judged when typed, so project forms and reads stay allowed.
func xargsStaticInputStateMutation(facts actionfacts.Facts, request trustedActionRequest) bool {
	if !strings.HasPrefix(facts.ActiveHome, "/") {
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	// The POSIX parse rejects a bash here-string (`cat <<< WORD | xargs`);
	// the twin parses the command as bash itself.
	if facts.Parse.Status == actionfacts.StatusInvalid && !strings.Contains(command, "<<<") {
		return false
	}
	if !known || len(command) > maxHereStringTwinBytes || !strings.Contains(command, "xargs") ||
		!strings.Contains(command, "|") {
		return false
	}
	// Both twins are judged (pod check30): the split twin is what xargs
	// makes of fixed words, the word twin keeps each printed word whole.
	seen := map[string]bool{}
	for _, split := range []bool{true, false} {
		twin, ok := xargsStaticInputTwin(command, facts.ActiveHome, split)
		if !ok || seen[twin] {
			continue
		}
		seen[twin] = true
		if mutates, _ := stateTwinMutates(request, twin); mutates {
			return true
		}
	}
	return false
}

// stateTwinMutates judges twin, a rewritten spelling of the action, through
// the whole dispatcher: mutates when it gets an enforcing state tamper
// finding; judged is false when the twin does not parse.
func stateTwinMutates(request trustedActionRequest, twin string) (mutates, judged bool) {
	twinRequest := request
	twinRequest.Input.Tool, twinRequest.Input.Command = "Bash", twin
	twinRequest.Input.Args, twinRequest.Input.Argv = nil, nil
	if actionfacts.Analyze(twinRequest.Input).Parse.Status == actionfacts.StatusInvalid {
		return false, false
	}
	twinRequest.LegacyText = twin
	twinRequest.conflictSource = nil
	twinRequest.record, twinRequest.recordTelemetry = nil, nil
	for _, finding := range dispatchTrustedAction(context.Background(), twinRequest) {
		if finding.RuleID == "tamper.detector_state_write" && finding.contributesToEnforcement() {
			return true, true
		}
	}
	return false, true
}

// xargsStaticInputTwin rewrites every `printf|echo WORDS | xargs ...` pipe
// of command as the call xargs makes with WORDS; false when there is none.
// With split, when every word is fixed, the printed text is split the way
// xargs splits it (xargsStaticCallTwin); otherwise each word is one item
// (xargsCallTwin).
func xargsStaticInputTwin(command, home string, split bool) (string, bool) {
	return xargsStaticInputTwinAt(command, home, split, 0)
}

// maxXargsTwinScriptDepth bounds the nested shell scripts (`sh -c "..."`)
// the twin rewrites inside.
const maxXargsTwinScriptDepth = 2

func xargsStaticInputTwinAt(command, home string, split bool, depth int) (string, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return "", false
	}
	changed, homeFixed := false, split && xargsHomeFixed(command)
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		// `sh -c "printf %s\\n ~/.defenseclaw/hooks | xargs rm -rf"` (pod
		// check31 W01-W03, W08, W10): the pipe is in a fixed script word,
		// so the script is rewritten and put back as one quoted word; the
		// twin keeps the shell call, which the dispatcher judges as typed.
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if index, ok := shellScriptWordIndex(call); ok && depth < maxXargsTwinScriptDepth {
				if script, ok := staticWordText(call.Args[index]); ok {
					if inner, ok := xargsStaticInputTwinAt(script, home, split, depth+1); ok {
						call.Args[index] = xargsQuotedWord(inner)
						changed = true
					}
				}
			}
			return true
		}
		pipe, ok := stmt.Cmd.(*syntax.BinaryCmd)
		if !ok || pipe.Op != syntax.Pipe || pipe.X.Background || pipe.X.Negated {
			return true
		}
		producer, ok := pipe.X.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		// `cat <<< WORD | xargs ...` prints WORD and a newline (pod check31).
		here := catHereStringWord(pipe.X, producer)
		if len(pipe.X.Redirs) != 0 && here == nil {
			return true
		}
		reader, ok := pipe.Y.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		var direct syntax.Command
		if homeFixed {
			input, ok := staticPrintedText(producer, home)
			if here != nil {
				var value string
				value, ok = xargsStaticValue(here, home)
				input = value + "\n"
			}
			if ok {
				direct, _ = xargsStaticCallTwin(reader, input, home)
			}
		}
		if direct == nil {
			words, ok := staticPrintedWords(producer)
			if here != nil {
				words, ok = []*syntax.Word{here}, true
			}
			if !ok {
				return true
			}
			if direct, ok = xargsCallTwin(reader, words); !ok {
				return true
			}
		}
		stmt.Cmd = direct
		stmt.Redirs = append(stmt.Redirs, pipe.Y.Redirs...)
		changed = true
		return true
	})
	if !changed {
		return "", false
	}
	var out strings.Builder
	if err := syntax.NewPrinter().Print(&out, file); err != nil {
		return "", false
	}
	return out.String(), true
}

// shellScriptWordIndex is the index of the script word of a POSIX shell
// call `sh -c SCRIPT`, `bash -lc SCRIPT`, `bash --norc -c SCRIPT`; false
// for any other call or an option it does not know.
func shellScriptWordIndex(call *syntax.CallExpr) (int, bool) {
	if len(call.Assigns) != 0 || len(call.Args) < 3 {
		return 0, false
	}
	switch path.Base(call.Args[0].Lit()) {
	case "sh", "bash", "dash", "zsh", "ksh":
	default:
		return 0, false
	}
	script := false
	for index := 1; index < len(call.Args); index++ {
		word := call.Args[index].Lit()
		switch {
		case script:
			return index, true
		case word == "--login" || word == "--norc" || word == "--noprofile" || word == "--posix":
		case len(word) > 1 && word[0] == '-' && word[1] != '-' && strings.Trim(word[1:], "abcefhilmnpuvxEBHPT") == "":
			script = strings.ContainsRune(word[1:], 'c')
			if !script {
				continue
			}
		default:
			return 0, false
		}
	}
	return 0, false
}

// catHereStringWord is the word of `cat <<< WORD` (a cat call with no
// arguments and that one redirect), nil otherwise.
func catHereStringWord(stmt *syntax.Stmt, call *syntax.CallExpr) *syntax.Word {
	if len(call.Assigns) != 0 || len(call.Args) != 1 || call.Args[0].Lit() != "cat" ||
		len(stmt.Redirs) != 1 || stmt.Redirs[0].Op != syntax.WordHdoc || stmt.Redirs[0].N != nil {
		return nil
	}
	return stmt.Redirs[0].Word
}

// staticPrintedWords is the argument words a printf or echo call prints
// as items: printf with a format of one %s and only separators (\n, \0,
// \t, space), or echo with -n/-e/-E options only.
func staticPrintedWords(call *syntax.CallExpr) ([]*syntax.Word, bool) {
	if len(call.Assigns) != 0 || len(call.Args) < 2 {
		return nil, false
	}
	switch call.Args[0].Lit() {
	case "printf":
		format, ok := staticWordText(call.Args[1])
		if !ok || strings.Count(format, "%s") != 1 || len(call.Args) < 3 {
			return nil, false
		}
		rest := strings.NewReplacer("%s", "", `\n`, "", `\0`, "", `\t`, "", " ", "").Replace(format)
		if rest != "" {
			return nil, false
		}
		return call.Args[2:], true
	case "echo":
		index := 1
		for index < len(call.Args) {
			if option := call.Args[index].Lit(); option == "-n" || option == "-e" || option == "-E" {
				index++
				continue
			}
			break
		}
		if index >= len(call.Args) {
			return nil, false
		}
		return call.Args[index:], true
	}
	return nil, false
}

// staticWordText is the text of a word made only of literal and quoted
// literal parts (a printf format).
func staticWordText(word *syntax.Word) (string, bool) {
	var text strings.Builder
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			// An unquoted backslash quotes the next character: %s\\n is %s\n.
			for index := 0; index < len(typed.Value); index++ {
				if typed.Value[index] == '\\' && index+1 < len(typed.Value) {
					index++
				}
				text.WriteByte(typed.Value[index])
			}
		case *syntax.SglQuoted:
			if typed.Dollar {
				return "", false
			}
			text.WriteString(typed.Value)
		case *syntax.DblQuoted:
			for _, inner := range typed.Parts {
				literal, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				text.WriteString(literal.Value)
			}
		default:
			return "", false
		}
	}
	return text.String(), true
}
