// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

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
	if !globOptionsChangeTextMayMatch(command) || !globOptionsChangeText.MatchString(command) {
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
				return // a program the scan cannot name: not one read here
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
// single- or double-quoted literal text).
func globOptionLiteral(word *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "\\*?[") {
				return "", false
			}
			b.WriteString(part.Value)
		case *syntax.SglQuoted:
			if part.Dollar {
				return "", false
			}
			b.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok || strings.ContainsRune(lit.Value, '\\') {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
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

// globOptionsChangeLiterals holds a literal of each alternative of
// globOptionsChangeText; the "." alternative is a dot before a \s character.
var globOptionsChangeLiterals = []string{
	"shopt", "GLOBIGNORE", "BASHOPTS", "SHELLOPTS", "set", "eval", "source", "bash",
	". ", ".\t", ".\n", ".\f", ".\r",
}

// globOptionsChangeTextMayMatch reports whether command holds one of the
// literals every match of globOptionsChangeText holds: a command with none
// of them cannot match, and the scan of the expression over a long call (it
// has no literal prefix) is left out (rel-1-0-10:GAP-1613).
func globOptionsChangeTextMayMatch(command string) bool {
	for _, literal := range globOptionsChangeLiterals {
		if strings.Contains(command, literal) {
			return true
		}
	}
	return false
}
