// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"unicode"
)

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
//	cmd-run     [cmd-option]*  (/c|/k|/r) word+   (each word one plain argv word)
//	cmd-run-q   [cmd-option]*  (/c|/k|/r) "payload with spaces"  (see cmdQuotedPayload)
//
// where every word is a whole static word (never empty, colon-glued or part of
// a --% tail) and the option spellings come from the fixed lists below. A
// switch word may carry leading or trailing blanks: pwsh 7 and Windows
// PowerShell 5.1 trim every host argument before they match it as a switch
// (GetSwitchKey: args[i].Trim()), so " -ec" is -ec and the script after it
// runs (rel-1-0-10:GAP-0155). Option values are never padded: the host does
// not trim those. The base64 word is read as the host decodes it (HostBase64,
// rel-1-0-10:GAP-1197): the tab, CR and LF it skips may stand in a quoted
// base64 word too (GAP-1199), though they keep every other word non-static.
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
	// -WorkingDirectory starts the script in another folder; its value is any
	// one plain word (a reader of the script reads it from that folder,
	// rel-1-0-10:GAP-0198).
	"-workingdirectory": true, "-wd": true,
}

// psFolderOpts are the host switches whose value may also be a folder word
// built from the caller's home or environment (folderValueWord): the value is
// not part of the script, so the script stays one static text.
var psFolderOpts = map[string]bool{"-workingdirectory": true, "-wd": true}

// psOptValues are the values pwsh accepts for the value options above, by
// lower-case spelling. pwsh 7.7 rejects any other value and runs nothing, so a
// call with another value is outside the table (review 9 R9-5); the Linux
// oracle checks every entry (TestHostOptionValuesOracle) except the Windows-only
// window styles.
var psOptValues = func() map[string]map[string]bool {
	set := func(vs ...string) map[string]bool {
		m := map[string]bool{}
		for _, v := range vs {
			m[v] = true
		}
		return m
	}
	policy := set("bypass", "unrestricted", "remotesigned", "allsigned", "restricted", "default", "undefined")
	format := set("text", "xml")
	style := set("normal", "minimized", "maximized", "hidden")
	return map[string]map[string]bool{
		"-executionpolicy": policy, "-ep": policy, "-exec": policy,
		"-inputformat": format, "-if": format, "-outputformat": format, "-of": format,
		"-windowstyle": style, "-w": style,
	}
}()

var psCommandSwitches = map[string]bool{"-c": true, "-command": true}

var psEncodedSwitches = map[string]bool{"-e": true, "-ec": true, "-enc": true, "-encodedcommand": true}

// CmdStartupSwitch reports a cmd.exe startup switch that may precede /c, /k
// or /r and changes nothing about how the body after it is read: /q /d /s /a
// /u, /x and /y (the old names of /e:on and /e:off), /e:on|off, /f:on|off,
// /v:on|off and /t:<one or two hex digits>. option is compared without case.
// It is the one cmd switch set: the psparse host reading and the actionfacts
// launcher reading both take it, so the two cannot read a different cmd body
// (rel-1-0-10:GAP-1708). Any other word before the run switch is not read.
func CmdStartupSwitch(option string) bool {
	option = strings.ToLower(option)
	switch option {
	case "/q", "/d", "/s", "/a", "/u", "/x", "/y",
		"/e:on", "/e:off", "/f:on", "/f:off", "/v:on", "/v:off":
		return true
	}
	if len(option) < 4 || len(option) > 5 || !strings.HasPrefix(option, "/t:") {
		return false
	}
	for _, r := range option[3:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// matchPSHostShape reports which tested shape a powershell / pwsh invocation's
// argv matches and the index of its command / encoded switch. When none does,
// shape is "" and reason names why.
func matchPSHostShape(c *Command, words []hostWord) (shape string, idx int, reason string) {
	if hostHasStopParse(c, words) {
		return "", 0, ReasonStopParsing
	}
	for i, w := range words {
		prev := ""
		if i > 0 && words[i-1].static {
			prev = strings.ToLower(strings.TrimSpace(words[i-1].text))
		}
		if !w.static && (!w.folder || !psFolderOpts[prev]) && (w.enc == "" || !psEncodedSwitches[prev]) {
			return "", 0, ReasonNonLiteral
		}
		if w.colon {
			return "", 0, ReasonHostOption
		}
	}
	for i := 0; i < len(words); {
		// The host trims a switch word (see the table above); an empty or blank
		// word is no switch: pwsh 7 rejects it and 5.1 drops it from argv.
		w := strings.TrimSpace(words[i].text)
		if w == "" {
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
			if words[i+1].folder && psFolderOpts[lw] {
				i += 2
				continue
			}
			if values, fixed := psOptValues[lw]; v == "" || v != strings.TrimSpace(v) || dashLed(v) ||
				fixed && !values[strings.ToLower(v)] {
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
			if rest[0].text == "-" {
				if len(rest) == 1 {
					return "", 0, ReasonStdin
				}
				return "", 0, ReasonHostOption // pwsh rejects -c - with more words (review 9 R9-5)
			}
			return shapePSCommand, i, ""
		case psEncodedSwitches[lw]:
			if i+2 != len(words) {
				return "", 0, ReasonHostShape
			}
			// The base64 word is read as the host reads it (HostBase64): a blank
			// in it is skipped by the host, so it is no reason to leave the
			// script unread (GAP-1197).
			text, _ := words[i+1].encodedText()
			if _, ok := DecodeEncodedCommand(text); !ok {
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

// matchCmdShape reports whether a cmd invocation is the cmd-run shape and, when
// it is, the index of its run switch; otherwise the reason names why not. The
// payload words must each be one native argv word with no whitespace and no
// quote character, so joining them with spaces is provably the command line cmd
// receives: the PowerShell caller wraps a word that holds whitespace in quotes
// and cmd /c keeps them (review 9 R9-2), which the join would lose.
func matchCmdShape(c *Command, words []hostWord) (idx int, reason string) {
	if hostHasStopParse(c, words) {
		return 0, ReasonStopParsing
	}
	for i := 0; i < len(words); i++ {
		w := words[i]
		if !w.static || w.colon {
			return 0, ReasonCmdArgv
		}
		if w.text == "" || w.text != strings.TrimSpace(w.text) {
			return 0, ReasonCmdArgv
		}
		l := strings.ToLower(w.text)
		if l == "/c" || l == "/k" || l == "/r" {
			rest := words[i+1:]
			if len(rest) == 0 {
				return 0, ReasonCmdArgv
			}
			if len(rest) == 1 && rest[0].static && !rest[0].colon && cmdQuotedPayload(words[:i], rest[0].text) {
				return i, ""
			}
			for _, r := range rest {
				if !r.static || r.colon {
					return 0, ReasonNonLiteral
				}
				if r.text == "" || strings.ContainsAny(r.text, "\"'") || strings.IndexFunc(r.text, unicode.IsSpace) >= 0 {
					return 0, ReasonCmdArgv
				}
			}
			return i, ""
		}
		if !CmdStartupSwitch(l) {
			return 0, ReasonCmdArgv
		}
	}
	return 0, ReasonCmdArgv // no run switch
}

// cmdQuotedPayload reports whether a single payload word that holds spaces is
// the quoted cmd-run shape `cmd /c "<payload>"`. The PowerShell caller (Windows
// PowerShell 5.1 and pwsh 7 alike, confirmed on dc-win2: WQ01, WQ02, WQ04, WQ05)
// hands cmd.exe `/c "<payload>"`, and cmd then strips the outer quotes except in
// one case: no /s switch, exactly two quotes, no special character (& < > ( ) @ ^
// |) between them, and the text between them names an executable file. That last
// condition depends on the file system, so the payload is Static only when the
// exception provably cannot apply: the payload holds a special character, or
// /s is among the options (which always strips). Then cmd runs the payload text
// exactly. The payload must also hold no quote character (the caller would
// escape it), no whitespace other than the plain space, and must not end in a
// backslash (5.1 does not double it before the closing quote).
func cmdQuotedPayload(opts []hostWord, w string) bool {
	if w == "" || !strings.Contains(w, " ") || strings.ContainsAny(w, "\"'") || strings.HasSuffix(w, `\`) {
		return false
	}
	for _, r := range w {
		if r != ' ' && unicode.IsSpace(r) {
			return false
		}
	}
	if strings.ContainsAny(w, "&<>()@^|") {
		return true
	}
	for _, o := range opts {
		if strings.EqualFold(o.text, "/s") {
			return true
		}
	}
	return false
}

// cmdHostNested is the only producer of nested scripts for a cmd host call: the
// cmd-run shape is Static, anything else NotStatic with the reason from the
// table. cmdCScript only decides whether a non-table call hides a payload.
func cmdHostNested(c *Command) []NestedScript {
	words := hostWords(c)
	idx, reason := matchCmdShape(c, words)
	if reason == "" {
		parts := make([]string, 0, len(words)-idx-1)
		for _, w := range words[idx+1:] {
			parts = append(parts, w.text)
		}
		return []NestedScript{{Kind: KindCmdC, Dialect: "cmd", Source: c, Static: true, Text: strings.Join(parts, " ")}}
	}
	if ns, ok := cmdCScript(c); ok {
		ns.Static, ns.Text, ns.Reason = false, "", reason
		return []NestedScript{ns}
	}
	return nil
}
