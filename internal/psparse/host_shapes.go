// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import "strings"

// Host-call shapes: the allowlist behind a Static host nested script.
//
// A powershell / pwsh / cmd invocation may yield a Static nested script only if
// its argv matches one of the shapes below. Everything else (padded or empty
// words, a --% tail, colon forms, splats and other dynamic words, stdin reads,
// switch spellings or abbreviations outside the table, positional commands,
// extra words after an encoded command, ...) is NotStatic with a reason code
// that names why the shape is outside the table. A newly found spelling is a
// corpus row, not a new rule: it is NotStatic until a shape (and its oracle
// rows in host_shape_test.go) is added here.
//
// Tested shapes (each has pwsh 7.7 differential rows; see host_shape_test.go
// TestHostShapeCLIOracle for the powershell shapes and the nested golden for
// the cmd shape):
//
//	ps-command  [host-option]* (-c|-command) word+
//	ps-encoded  [host-option]* (-e|-ec|-enc|-encodedcommand) base64
//	cmd-run     [cmd-option]*  (/c|/k|/r) word+
//
// where every word is a whole static word (never padded, empty, colon-glued or
// part of a --% tail) and the option spellings come from the fixed lists below.
// A positional command is deliberately not a shape: pwsh 7 reads a positional
// word as a script file, Windows PowerShell 5.1 as a command.
const (
	shapePSCommand = "ps-command"
	shapePSEncoded = "ps-encoded"
	shapeCmdRun    = "cmd-run"
)

// psHostOpts are the tested host switches, lower-case whole words, mapped to
// whether they take one value word. -Version/-v (pwsh 7 prints its version and
// exits), -File (its own mode), -noexit (interactive) and abbreviations beyond
// these spellings are not in the table.
var psHostOpts = map[string]bool{
	"-noprofile": false, "-nop": false,
	"-noninteractive": false, "-noni": false,
	"-nologo": false, "-nol": false,
	"-sta": false, "-mta": false,
	"-executionpolicy": true, "-ep": true, "-exec": true,
	"-windowstyle": true, "-w": true,
	"-inputformat": true, "-if": true,
	"-outputformat": true, "-of": true,
	"-workingdirectory": true, "-wd": true,
}

var psCommandSwitches = map[string]bool{"-c": true, "-command": true}

var psEncodedSwitches = map[string]bool{"-e": true, "-ec": true, "-enc": true, "-encodedcommand": true}

// cmdHostOpts are the tested cmd.exe switches that may precede /c, /k or /r.
var cmdHostOpts = map[string]bool{
	"/q": true, "/d": true, "/s": true, "/a": true, "/u": true, "/x": true, "/y": true,
	"/e:on": true, "/e:off": true, "/v:on": true, "/v:off": true, "/f:on": true, "/f:off": true,
}

// matchPSHostShape reports which tested shape a powershell / pwsh invocation's
// argv matches and the index of its command / encoded switch. When none does,
// shape is "" and reason names why.
func matchPSHostShape(c *Command, words []hostWord) (shape string, idx int, reason string) {
	if hostHasStopParse(c, words) {
		return "", 0, ReasonStopParsing
	}
	for _, w := range words {
		if !w.static {
			return "", 0, ReasonNonLiteral
		}
		if w.colon {
			return "", 0, ReasonHostOption
		}
	}
	for i := 0; i < len(words); {
		w := words[i].text
		if w == "" || w != strings.TrimSpace(w) {
			return "", 0, ReasonHostOption
		}
		lw := strings.ToLower(w)
		if takesValue, ok := psHostOpts[lw]; ok {
			if !takesValue {
				i++
				continue
			}
			if i+1 >= len(words) {
				return "", 0, ReasonHostShape
			}
			v := words[i+1].text
			if v == "" || v != strings.TrimSpace(v) || dashLed(v) {
				return "", 0, ReasonHostOption
			}
			i += 2
			continue
		}
		switch {
		case psCommandSwitches[lw]:
			rest := words[i+1:]
			if len(rest) == 0 {
				return "", 0, ReasonHostShape
			}
			if len(rest) == 1 && rest[0].text == "-" {
				return "", 0, ReasonStdin
			}
			return shapePSCommand, i, ""
		case psEncodedSwitches[lw]:
			if i+2 != len(words) {
				return "", 0, ReasonHostShape
			}
			b := words[i+1].text
			if b != strings.TrimSpace(b) {
				return "", 0, ReasonNonLiteral
			}
			if _, ok := DecodeEncodedCommand(b); !ok {
				return "", 0, ReasonNonLiteral
			}
			return shapePSEncoded, i, ""
		}
		if dashLed(w) || strings.HasPrefix(w, "/") {
			return "", 0, ReasonHostOption // a switch outside the tested list
		}
		return "", 0, ReasonHostShape // positional word: not a tested shape
	}
	return "", 0, ReasonHostShape // no command switch
}

// psHostNested is the only producer of nested scripts for a powershell / pwsh
// host call. The tested shapes are Static; anything else is NotStatic with the
// reason that names why it is outside the table. The switch-by-switch parser is
// kept only to decide whether a non-table call hides a script at all (a -File
// call has none) and to keep its specific stdin reason.
func psHostNested(c *Command) []NestedScript {
	words := hostWords(c)
	shape, idx, reason := matchPSHostShape(c, words)
	switch shape {
	case shapePSCommand:
		return []NestedScript{joinRest(words[idx+1:], KindPowerShellCommand, "powershell", c)}
	case shapePSEncoded:
		return []NestedScript{decodeWord(words[idx+1], c)}
	}
	out := powerShellHostScripts(c, words)
	for i := range out {
		legacy := out[i].Reason
		out[i].Static, out[i].Text = false, ""
		switch {
		case legacy == ReasonStdin:
			out[i].Reason = ReasonStdin
		case reason != "":
			out[i].Reason = reason
		case legacy != "":
			out[i].Reason = legacy
		default:
			out[i].Reason = ReasonHostShape
		}
	}
	return out
}

// cmdShapeReject returns "" when a cmd invocation's argv is the cmd-run shape,
// else the reason code that names why it is not.
func cmdShapeReject(c *Command) string {
	stop := c.StopParsing != ""
	for _, el := range c.Elements {
		if a, ok := el.(*Arg); ok {
			if v, ok := LiteralString(a.Value); ok && v == "--%" {
				stop = true
			}
		}
	}
	if stop {
		return ReasonStopParsing
	}
	for _, el := range c.Elements {
		a, ok := el.(*Arg)
		if !ok {
			return ReasonCmdArgv
		}
		s, ok := LiteralString(a.Value)
		if !ok || s == "" || s != strings.TrimSpace(s) {
			return ReasonCmdArgv
		}
		l := strings.ToLower(s)
		if l == "/c" || l == "/k" || l == "/r" {
			// the payload words after the switch must all be whole static words
			return cmdPayloadReject(c, el)
		}
		if !cmdHostOpts[l] {
			return ReasonCmdArgv
		}
	}
	return ReasonCmdArgv // no run switch
}

func cmdPayloadReject(c *Command, sw CommandElement) string {
	seen := false
	n := 0
	for _, el := range c.Elements {
		if el == sw {
			seen = true
			continue
		}
		if !seen {
			continue
		}
		a, ok := el.(*Arg)
		if !ok {
			return ReasonCmdArgv
		}
		if _, ok := LiteralString(a.Value); !ok {
			return ReasonCmdArgv
		}
		n++
	}
	if n == 0 {
		return ReasonCmdArgv
	}
	return ""
}
