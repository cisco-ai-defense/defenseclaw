// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Bits of shellGlobOptions.may: an option a statement of the call may turn
// either way before a later word.
const (
	globMayDot uint8 = 1 << iota
	globMayNoCase
	globMayNull
	globMayFail
	globMayNoGlob
	globMayStar
)

// globMayFields maps each bit to its option.
var globMayFields = []struct {
	bit   uint8
	field func(*shellGlobOptions) *bool
}{
	{globMayDot, func(o *shellGlobOptions) *bool { return &o.dotGlob }},
	{globMayNoCase, func(o *shellGlobOptions) *bool { return &o.noCaseGlob }},
	{globMayNull, func(o *shellGlobOptions) *bool { return &o.nullGlob }},
	{globMayFail, func(o *shellGlobOptions) *bool { return &o.failGlob }},
	{globMayNoGlob, func(o *shellGlobOptions) *bool { return &o.noGlob }},
	{globMayStar, func(o *shellGlobOptions) *bool { return &o.globStar }},
}

// shoptGlobNames are the shopt names that change pathname expansion, in the
// order of shoptGlobOrder. One spec string, not a literal per name: the
// GAP-0749 bounded sweep reads every package string literal as a word.
var shoptGlobNames = strings.Fields("dotglob nocaseglob nullglob failglob globstar extglob")

// shoptGlobOrder is the bit of each shoptGlobNames name (extglob changes only
// the parse: an extglob word is never modeled, so it needs no bit).
var shoptGlobOrder = []uint8{globMayDot, globMayNoCase, globMayNull, globMayFail, globMayStar, 0}

// shoptGlobBits are the shopt names that change pathname expansion and the
// bit of each.
var shoptGlobBits = func() map[string]uint8 {
	bits := make(map[string]uint8, len(shoptGlobNames))
	for i, name := range shoptGlobNames {
		bits[name] = shoptGlobOrder[i]
	}
	return bits
}()

// globOptionsInCall reads the statements of command that change the glob
// options of the shell that runs it, wherever they stand (rel-1-0-10:
// GAP-0380): shopt -s/-u with literal names, set -f/+f and -o/+o noglob, an
// assignment, export or declare of GLOBIGNORE. Each option such a
// statement names may be either value at a later word, so the word is read
// under both (may). A GLOBIGNORE value is a filter the resolver does not model
// (globIgnore). Anything that may change the options in a way the call does
// not spell (eval, source or ., an option word that is not a literal, a
// BASHOPTS or SHELLOPTS assignment, a nested shell started with -O, +O or -o,
// a command that does not parse) makes the options unknown.
//
// set -e, -u, -x, -o pipefail and the shopt names that change no expansion
// change nothing (rel-1-0-10:GAP-0350).
func globOptionsInCall(command string, start shellGlobOptions) shellGlobOptions {
	if !globOptionsChangeTextMatches(command) {
		return start
	}
	file, ok := parseShell(command)
	if !ok {
		start.unknown = true
		return start
	}
	o := start
	syntax.Walk(file, func(node syntax.Node) bool {
		if o.unknown {
			return false
		}
		switch node := node.(type) {
		case *syntax.Assign:
			if node.Name != nil {
				switch node.Name.Value {
				case "GLOBIGNORE":
					o.globIgnore = true
				case "BASHOPTS", "SHELLOPTS":
					o.unknown = true
				}
			}
		case *syntax.CallExpr:
			globOptionsCall(node, &o)
		}
		return true
	})
	return o
}

// CallGlobOptionsCoverStatement reports whether the client's whole-call
// reading includes every glob-option state of a gateway's isolated statement.
// A modeled option change is read both on and off. An unmodeled change
// remains distinct and cannot justify a negative answer (GAP-0380, GAP-0415).
func CallGlobOptionsCoverStatement(call, statement string) bool {
	parentOptions := globOptionsInCall(call, shellGlobOptions{})
	childOptions := globOptionsInCall(statement, shellGlobOptions{})
	// A globstar change gives **/ a different folder walk. The client's
	// whole-call reading cannot stand in for an isolated statement's blind
	// walk over that structure (GAP-0415).
	if strings.Contains(statement, "**") &&
		(parentOptions.globStar != childOptions.globStar ||
			parentOptions.may&globMayStar != childOptions.may&globMayStar) {
		return false
	}
	parent := globReadings(parentOptions)
	for _, child := range globReadings(childOptions) {
		covered := false
		for _, reading := range parent {
			if reading == child {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// globOptionsCall applies one simple command to o.
func globOptionsCall(call *syntax.CallExpr, o *shellGlobOptions) {
	var words []string
	for _, arg := range call.Args {
		text, literal := globOptionLiteral(arg)
		if !literal {
			if len(words) == 0 {
				// A program the scan cannot name is not one read here, unless
				// it is an ANSI-C quote whose escapes do not decode: that may
				// be eval or shopt, so the options are unknown
				// (rel-1-0-10:GAP-1629).
				if globOptionUndecodedANSIC(arg) {
					o.unknown = true
				}
				return
			}
			if globOptionProgram(words[0]) {
				o.unknown = true
			}
			return
		}
		words = append(words, text)
	}
	for len(words) > 0 && (words[0] == "builtin" || words[0] == "command") {
		words = words[1:]
	}
	if len(words) == 0 {
		return
	}
	switch name := words[0]; {
	case name == "shopt":
		globOptionsShopt(words[1:], o)
	case name == "set":
		globOptionsSet(words[1:], o)
	case name == "eval", name == "source", name == ".":
		o.unknown = true
	case programBase(name) == "bash" || programBase(name) == "sh":
		for _, word := range words[1:] {
			if word == "-O" || word == "+O" || strings.HasPrefix(word, "-") && !strings.HasPrefix(word, "--") && strings.ContainsRune(word, 'o') {
				o.unknown = true
			}
		}
	}
}

// globOptionProgram reports a program name whose options this reader models
// or that runs text it does not read.
func globOptionProgram(name string) bool {
	switch name {
	case "shopt", "set", "eval", "source", ".", "builtin", "command":
		return true
	}
	return false
}

func globOptionsShopt(args []string, o *shellGlobOptions) {
	turn, setNames := false, false
	var names []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && len(arg) > 1 && len(names) == 0 {
			for _, flag := range arg[1:] {
				switch flag {
				case 's', 'u':
					turn = true
				case 'o':
					setNames = true
				case 'p', 'q':
				default:
					o.unknown = true
					return
				}
			}
			continue
		}
		names = append(names, arg)
	}
	if !turn {
		return // print or query only
	}
	for _, name := range names {
		if setNames {
			if name == "noglob" {
				o.may |= globMayNoGlob
			}
			continue
		}
		if bit, glob := shoptGlobBits[name]; glob {
			o.may |= bit
		}
	}
}

func globOptionsSet(args []string, o *shellGlobOptions) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "+") {
			return // positional parameters
		}
		for _, flag := range arg[1:] {
			switch flag {
			case 'f':
				o.may |= globMayNoGlob
			case 'o':
				if i+1 < len(args) {
					i++
					if args[i] == "noglob" {
						o.may |= globMayNoGlob
					}
				}
			}
		}
	}
}

// globOptionLiteral is the text of a word with no expansion in it (plain,
// single- or double-quoted literal text, an ANSI-C quote with no escape), as
// the shell reads it after quote removal: `s\hopt` is shopt and `"se\t"` is
// se\t (rel-1-0-10:GAP-1614). An unescaped pattern character is no literal.
func globOptionLiteral(word *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			for i := 0; i < len(part.Value); i++ {
				switch character := part.Value[i]; character {
				case '*', '?', '[':
					return "", false
				case '\\':
					if i++; i == len(part.Value) {
						return "", false
					}
					if part.Value[i] != '\n' {
						b.WriteByte(part.Value[i])
					}
				default:
					b.WriteByte(character)
				}
			}
		case *syntax.SglQuoted:
			if part.Dollar && strings.ContainsRune(part.Value, '\\') {
				// ANSI-C escapes, decoded as the shell decodes them:
				// $'\x65val' is eval (rel-1-0-10:GAP-1629).
				text, ok := globOptionANSIC(part)
				if !ok {
					return "", false
				}
				b.WriteString(text)
				continue
			}
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return "", false
				}
				for i := 0; i < len(lit.Value); i++ {
					// In double quotes a backslash escapes only $ ` " \ and a newline.
					if lit.Value[i] == '\\' && i+1 < len(lit.Value) && strings.IndexByte("$`\"\\\n", lit.Value[i+1]) >= 0 {
						if i++; lit.Value[i] == '\n' {
							continue
						}
					}
					b.WriteByte(lit.Value[i])
				}
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// globOptionANSIC decodes an ANSI-C quote ($'...') as the shell does. A
// decoded NUL or an escape the decoder does not take is no literal.
func globOptionANSIC(part *syntax.SglQuoted) (string, bool) {
	text, err := expand.Literal(&expand.Config{}, &syntax.Word{Parts: []syntax.WordPart{part}})
	if err != nil || strings.ContainsRune(text, 0) {
		return "", false
	}
	return text, true
}

// globOptionUndecodedANSIC reports a word holding an ANSI-C quote that
// globOptionANSIC does not decode.
func globOptionUndecodedANSIC(word *syntax.Word) bool {
	for _, part := range word.Parts {
		if q, ok := part.(*syntax.SglQuoted); ok && q.Dollar {
			if _, ok := globOptionANSIC(q); !ok {
				return true
			}
		}
	}
	return false
}

// globReadings are the option states a word is read under: opts with each
// option of opts.may off and on.
func globReadings(opts shellGlobOptions) []shellGlobOptions {
	base := opts
	base.may = 0
	out := []shellGlobOptions{base}
	for _, entry := range globMayFields {
		if opts.may&entry.bit == 0 {
			continue
		}
		for i, n := 0, len(out); i < n; i++ {
			off, on := out[i], out[i]
			*entry.field(&off) = false
			*entry.field(&on) = true
			out[i] = off
			out = append(out, on)
		}
	}
	return out
}

// globOptionsChangeTextMatches is the text gate of globOptionsInCall: the
// call as written, or as the shell reads its words, may change the glob
// options (globOptionsChangeText). The shell removes a line continuation
// (backslash-newline) and the quote and escape characters before it reads a
// name, so `GLOB\<newline>IGNORE=x`, `"shopt" -s dotglob`, `s\hopt`, `'set' -f`,
// `$'eval' x` and `set \<newline>-f` change the options as their plain
// spelling does, and a gate on the raw text alone passed them by with no
// parse (rel-1-0-10:GAP-1614). The gate is a filter only: the parsed walk
// decides, and a call with no quote or backslash is scanned once, as before.
func globOptionsChangeTextMatches(command string) bool {
	if globOptionsChangeScan(command) {
		return true
	}
	if !strings.ContainsAny(command, "\\'\"") {
		return false
	}
	read := strings.ReplaceAll(command, "\\\n", "")
	if strings.Contains(read, "$'") {
		// An ANSI-C quote names a word by its escapes ($'\x65val', $'sh\x6fpt'):
		// the gate reads it decoded (rel-1-0-10:GAP-1629).
		read = globOptionsDecodeANSIC(read)
	}
	read = globOptionsQuoteRemoval.Replace(read)
	return globOptionsChangeScan(read)
}

// globOptionsDecodeANSIC is text with each closed ANSI-C quote replaced by
// its decoded value (an undecodable one is kept as written), for the gate.
func globOptionsDecodeANSIC(text string) string {
	var b strings.Builder
	for {
		i := strings.Index(text, "$'")
		if i < 0 {
			b.WriteString(text)
			return b.String()
		}
		j := i + 2
		for j < len(text) && text[j] != '\'' {
			if text[j] == '\\' {
				j++
			}
			j++
		}
		if j >= len(text) {
			b.WriteString(text)
			return b.String()
		}
		b.WriteString(text[:i])
		if v, ok := globOptionANSIC(&syntax.SglQuoted{Dollar: true, Value: text[i+2 : j]}); ok {
			b.WriteString(v)
		} else {
			b.WriteString(text[i : j+1])
		}
		text = text[j+1:]
	}
}

// globOptionsQuoteRemoval drops the quote and escape characters of a call's
// text for the gate (the $ of $'...' and $"..." with them).
var globOptionsQuoteRemoval = strings.NewReplacer("$'", "", "$\"", "", "\\", "", "'", "", "\"", "")
