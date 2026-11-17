// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// posixLauncherHomeSource returns a POSIX call of a PowerShell launcher with
// each plain $HOME or ${HOME} the shell expands before the launcher runs
// (one followed by "/", inside double quotes or not) written as the trusted
// ActiveHome, false when there is none, the home is not a Linux or macOS
// trustedPOSIXHomeLiteral, or the
// call mentions HOME anywhere else (an assignment, export or other
// expansion could change it). pwsh -Command "Add-Content -Path
// $HOME/.codex/config.toml -Value x" runs with the home spelled out, but the
// expanded word left the launcher unread, so the body had no PowerShell
// reading at all (rel-1-0-10:GAP-1134). The result is read as any other
// static launcher call (posixSoleHostCallSource): another expansion in it
// still leaves it unread.
func posixLauncherHomeSource(source, activeHome string) (string, bool) {
	home, _ := normalizeActiveHome(activeHome)
	home = strings.TrimRight(home, "/")
	lower := strings.ToLower(source)
	if !strings.Contains(source, "HOME") || !strings.HasPrefix(home, "/") || !trustedPOSIXHomeLiteral.MatchString(home) ||
		!strings.Contains(lower, "pwsh") && !strings.Contains(lower, "powershell") {
		return "", false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(source), "")
	if err != nil {
		return "", false
	}
	type span struct{ start, end int }
	var spans []span
	anchored := func(parts []syntax.WordPart) {
		for index, part := range parts {
			if !plainHomeParameter(part) || index+1 >= len(parts) {
				continue
			}
			if next, ok := parts[index+1].(*syntax.Lit); ok && strings.HasPrefix(next.Value, "/") {
				spans = append(spans, span{int(part.Pos().Offset()), int(part.End().Offset())})
			}
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.Word:
			anchored(typed.Parts)
		case *syntax.DblQuoted:
			anchored(typed.Parts)
		}
		return true
	})
	if len(spans) == 0 {
		return "", false
	}
	var out, rest strings.Builder
	last := 0
	for _, at := range spans {
		if at.start < last || at.end > len(source) || at.end <= at.start {
			return "", false
		}
		out.WriteString(source[last:at.start])
		rest.WriteString(source[last:at.start])
		out.WriteString(home)
		last = at.end
	}
	out.WriteString(source[last:])
	rest.WriteString(source[last:])
	if strings.Contains(rest.String(), "HOME") {
		return "", false
	}
	return out.String(), true
}

// PowerShellLauncherScripts returns the scripts the PowerShell launchers
// (pwsh or powershell -NoProfile -Command BODY) of a POSIX call on Linux or
// macOS run, as the parser nests them (nestedCommand), with the home the
// shell expands in the launcher's words spelled out
// (posixLauncherHomeSource). The PowerShell write reader of the gateway and
// the hook client read each script for the files it writes: a .NET file
// method (psparse never trusts its bracketed text as static, so the script
// had no reading of its own) and New-Item -Value (rel-1-0-10:GAP-1134). A
// call of a Windows home is read in PowerShell as a whole instead.
func PowerShellLauncherScripts(input Input) []string {
	home, _ := normalizeActiveHome(input.ActiveHome)
	source := shellCommandText(input)
	lower := strings.ToLower(source)
	if !strings.HasPrefix(home, "/") || source == "" || len(source) > maxCommandBytes ||
		!strings.Contains(lower, "pwsh") && !strings.Contains(lower, "powershell") {
		return nil
	}
	switch input.DialectHint {
	case "", DialectPOSIX:
	default:
		return nil
	}
	if homed, spelled := posixLauncherHomeSource(source, home); spelled {
		source = homed
	}
	out := parsePOSIX(source, 1, 0)
	var scripts []string
	for _, command := range out.commands {
		program := commandProgram(command.Executable)
		if command.Dialect != DialectPOSIX || !command.ArgvComplete || len(command.Argv) < 2 ||
			!slices.Contains([]string{"powershell", "pwsh"}, program) || !hostLauncherIdentity(command.Argv[0], program) {
			continue
		}
		if body, _, ok, _ := nestedCommand(command.Argv, program); ok && !slices.Contains(scripts, body) {
			scripts = append(scripts, body)
		}
	}
	return scripts
}
