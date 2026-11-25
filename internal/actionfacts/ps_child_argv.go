// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// powerShellChildArgvTexts adds to out, for every command of script that
// hands a native program an argv PowerShell itself does not read
// (powerShellChildArgvCall), that program's bare call: a nested reading
// judged as the call typed at the prompt, so a program classifier (NetExec,
// rel-1-0-10:GAP-0201) reads it as it reads the bare call. The bounds are the
// nested readings' own (maxHostMidListBody, maxListReadings).
func powerShellChildArgvTexts(script *psparse.Script, out []nestedText, caps bounded.CapSet) ([]nestedText, bounded.CapSet) {
	full := false
	psparse.WalkCommands(script, func(command *psparse.Command) {
		if full {
			return
		}
		text, ok := powerShellChildArgvCall(command)
		if !ok {
			return
		}
		switch {
		case len(text) > maxHostMidListBody:
			caps = caps.Union(bounded.Of(bounded.Bytes))
		case len(out) >= maxListReadings:
			caps = caps.Union(bounded.Of(bounded.Items))
			full = true
		default:
			out = append(out, nestedText{text: text, dialect: DialectPowerShell})
		}
	})
	return out, caps
}

// powerShellChildArgvCall is the bare PowerShell call of the argv a command
// hands a native program without PowerShell reading it:
//
//   - Start-Process <program> -ArgumentList <literal line or list>: the
//     child's argv as the effects binder reads it
//     (effects.StartProcessChildArgv);
//   - <program> [literal words] --% <rest>: the words before --%, then the
//     rest split as the program splits its command line
//     (effects.WindowsCommandLineArgv). A rest with a % (cmd-style variables
//     PowerShell expands there) has no static spelling and is not read.
//
// A powershell, pwsh or cmd child, at any path, is not read here: the
// launcher readings read it. ok is false for any other command.
func powerShellChildArgvCall(command *psparse.Command) (string, bool) {
	name, named := psparse.LiteralString(command.Name)
	if !named || strings.TrimSpace(name) == "" {
		return "", false
	}
	var argv []string
	switch strings.ToLower(name) {
	case "start-process", "saps", "start":
		child, ok := effects.StartProcessChildArgv(command)
		if !ok || len(child) < 2 {
			return "", false
		}
		argv = child
	default:
		if command.StopParsing == "" || strings.Contains(command.StopParsing, "%") || command.InvokeOp == "." {
			return "", false
		}
		argv = []string{name}
	words:
		for _, element := range command.Elements {
			var word string
			switch typed := element.(type) {
			case *psparse.Parameter:
				if typed.HasColon {
					return "", false
				}
				word = typed.Raw
			case *psparse.Arg:
				text, static := psparse.LiteralString(typed.Value)
				if !static {
					return "", false
				}
				word = text
			default:
				return "", false
			}
			if word == "--%" {
				break words
			}
			argv = append(argv, word)
		}
		argv = append(argv, effects.WindowsCommandLineArgv(command.StopParsing)...)
		if len(argv) < 2 {
			return "", false
		}
	}
	switch program := strings.ToLower(argv[0][strings.LastIndexAny(argv[0], `\/`)+1:]); strings.TrimSuffix(program, ".exe") {
	case "powershell", "pwsh", "cmd":
		// A host child at any path: the launcher readings decide whether it
		// is read (one that is not the system's is not).
		return "", false
	}
	line := make([]string, len(argv))
	for index, word := range argv {
		line[index] = powerShellArgvWord(word)
	}
	if line[0] != argv[0] {
		// A program path that needs quotes is run with the call operator.
		line[0] = "& " + line[0]
	}
	return strings.Join(line, " "), true
}

// powerShellArgvWord is word as a PowerShell argument that hands a native
// program exactly word: as written when it holds only characters PowerShell
// passes through unread (an option such as -u or --shares included),
// otherwise a single-quoted literal, which expands nothing.
func powerShellArgvWord(word string) string {
	if word != "" && strings.IndexFunc(word, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') &&
			!strings.ContainsRune(`_./\:=+-`, r)
	}) < 0 {
		return word
	}
	return "'" + strings.ReplaceAll(word, "'", "''") + "'"
}

// onlyStopParsingDiagnostics reports a psparse script whose only diagnostics
// are --% remainders: the rest of the tree is read in full.
func onlyStopParsingDiagnostics(script *psparse.Script) bool {
	for _, diagnostic := range script.Diagnostics {
		if diagnostic.Reason != psparse.ReasonStopParsing {
			return false
		}
	}
	return len(script.Diagnostics) > 0
}
