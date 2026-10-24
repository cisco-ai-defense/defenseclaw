// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// ExactPythonHomePathRead returns the relative home path read by a complete,
// side-effect-free inline pathlib expression. The token check keeps adjacent
// literals, substitutions, and other calls out of this proof.
func ExactPythonHomePathRead(facts Facts) (string, bool) {
	if facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) != 1 {
		return "", false
	}
	command := facts.Commands[0]
	if command.Effect != EffectExecute || !command.ArgvComplete ||
		len(command.Redirects) != 0 || len(command.Argv) != 3 ||
		(command.Program != "python" && !strings.HasPrefix(command.Program, "python3")) ||
		command.Argv[1] != "-c" || len(command.Argv[2]) > 4096 {
		return "", false
	}
	code, ok := strings.CutPrefix(strings.TrimSpace(command.Argv[2]), "from pathlib import Path;")
	if !ok {
		return "", false
	}
	tokens, ok := lexModelPythonLine(strings.TrimSpace(code))
	if !ok || len(tokens) != 17 ||
		!modelPythonValues(tokens[:10], "print", "(", "Path", ".", "home", "(", ")", ".", "joinpath", "(") ||
		!exactModelPythonLiteral(tokens[10]) ||
		!modelPythonValues(tokens[11:], ")", ".", "", "(", ")", ")") ||
		(tokens[13].value != "read_text" && tokens[13].value != "read_bytes") {
		return "", false
	}
	path := tokens[10].value
	if strings.HasPrefix(path, "/") || strings.Contains(path, "..") || strings.ContainsAny(path, "\r\n\x00") {
		return "", false
	}
	return path, true
}
