// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const posixDPKGStatusPath = "/var/lib/dpkg/status"

var exactDPKGStatusHeredocOpen = regexp.MustCompile(
	`^cat[ \t]+(?:<<[ \t]*'([A-Za-z][A-Za-z0-9_]{0,31})'[ \t]+(>>?)[ \t]*/var/lib/dpkg/status|(>>?)[ \t]*/var/lib/dpkg/status[ \t]+<<[ \t]*'([A-Za-z][A-Za-z0-9_]{0,31})')[ \t]*$`,
)

func classifyExactPOSIXBindMount(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) ||
		!command.ArgvComplete || !staticArguments(command.Arguments) {
		return
	}
	argv := command.Argv
	if len(argv) == 5 && argv[2] == "--" {
		argv = []string{argv[0], argv[1], argv[3], argv[4]}
	}
	if len(argv) != 4 || argv[1] != "--bind" ||
		!exactStaticAbsolutePOSIXPath(argv[2]) ||
		!exactStaticAbsolutePOSIXPath(argv[3]) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationConfigChange)
	appendPath(out, command.ID, PathAccessRead, argv[2])
	appendPath(out, command.ID, PathAccessWrite, argv[3])
}

// ExactPOSIXDPKGStatusMutation proves an executing write, append, or replacement
// of the exact dpkg status database by a command other than the package manager
// itself. Reads, lookalike paths, dynamic operands, and incomplete parses do not
// satisfy the proof.
func ExactPOSIXDPKGStatusMutation(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	commands := commandFactsByID(facts.Commands)
	for _, candidate := range facts.Paths {
		if candidate.Flavor != PathFlavorPOSIX ||
			(candidate.Access != PathAccessWrite && candidate.Access != PathAccessAppend) ||
			exactPOSIXPathFact(candidate) != posixDPKGStatusPath {
			continue
		}
		command, ok := commands[candidate.CommandID]
		if !ok || !exactExecutingStaticCommand(command) ||
			posixPackageManagerProgram(command.Program) {
			continue
		}
		return true
	}
	return false
}

// ExactSubmittedPOSIXDPKGStatusHeredocMutation proves one closed Terminal
// Wrench bash_command envelope containing only a quoted, literal heredoc that
// writes or appends the exact dpkg status database. It deliberately does not
// project arbitrary multiline terminal input into generic command facts.
func ExactSubmittedPOSIXDPKGStatusHeredocMutation(input Input) bool {
	keystrokes, ok := exactDPKGStatusHeredocInput(input)
	if !ok || !utf8.ValidString(keystrokes) || strings.ContainsAny(keystrokes, "\r\x00") ||
		!strings.HasSuffix(keystrokes, "\n") {
		return false
	}
	for _, character := range keystrokes {
		if (character < ' ' && character != '\n' && character != '\t') || character == 0x7f {
			return false
		}
	}
	command := strings.TrimSuffix(keystrokes, "\n")
	lines := strings.Split(command, "\n")
	if len(lines) < 3 {
		return false
	}
	opener := exactDPKGStatusHeredocOpen.FindStringSubmatch(lines[0])
	if len(opener) != 5 {
		return false
	}
	delimiter := opener[1]
	if delimiter == "" {
		delimiter = opener[4]
	}
	if delimiter == "" || lines[len(lines)-1] != delimiter {
		return false
	}
	for _, line := range lines[1 : len(lines)-1] {
		if line == delimiter {
			return false
		}
	}
	return true
}

func exactDPKGStatusHeredocInput(input Input) (string, bool) {
	if input.Tool != "bash_command" || len(input.Argv) != 0 || len(input.Args) == 0 ||
		len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) {
		return "", false
	}
	var object struct {
		Keystrokes string       `json:"keystrokes"`
		Duration   *json.Number `json:"duration,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object.Keystrokes == "" {
		return "", false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", false
	}
	if object.Duration != nil {
		duration, err := strconv.ParseFloat(string(*object.Duration), 64)
		if err != nil || duration < 0 || math.IsInf(duration, 0) || math.IsNaN(duration) {
			return "", false
		}
	}
	if input.Command != "" && input.Command != object.Keystrokes {
		return "", false
	}
	return object.Keystrokes, true
}

// ExactPOSIXKernelControlBindOverride proves one literal mount --bind from one
// exact absolute source path to a target strictly below a reviewed /proc/sys
// control namespace. Alternate mount modes, root namespace targets, dynamic
// operands, and incomplete command grammars are excluded.
func ExactPOSIXKernelControlBindOverride(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return false
	}
	for _, command := range facts.Commands {
		if !exactExecutingStaticCommand(command) || command.Program != "mount" {
			continue
		}
		argv := command.Argv
		if len(argv) == 5 && argv[2] == "--" {
			argv = []string{argv[0], argv[1], argv[3], argv[4]}
		}
		if len(argv) != 4 || argv[1] != "--bind" ||
			!exactStaticAbsolutePOSIXPath(argv[2]) ||
			!exactStaticAbsolutePOSIXPath(argv[3]) ||
			!strictKernelControlDescendant(argv[3]) {
			continue
		}
		return true
	}
	return false
}

func commandFactsByID(commands []CommandFact) map[int64]CommandFact {
	indexed := make(map[int64]CommandFact, len(commands))
	for _, command := range commands {
		indexed[command.ID] = command
	}
	return indexed
}

func exactExecutingStaticCommand(command CommandFact) bool {
	return command.Kind == CommandKindProcess && command.Effect == EffectExecute &&
		command.ArgvComplete && !command.ControlFlowUncertain &&
		staticArguments(command.Arguments)
}

func exactPOSIXPathFact(candidate PathFact) string {
	if candidate.Flavor != PathFlavorPOSIX || !candidate.Absolute ||
		candidate.Resolved == "" || !exactStaticAbsolutePOSIXPath(candidate.Resolved) {
		return ""
	}
	return candidate.Resolved
}

func exactStaticAbsolutePOSIXPath(value string) bool {
	return staticAbsolutePOSIXPath(value) && path.Clean(value) == value
}

func strictKernelControlDescendant(target string) bool {
	for _, root := range []string{"/proc/sys/kernel", "/proc/sys/net", "/proc/sys/vm"} {
		if strings.HasPrefix(target, root+"/") {
			return true
		}
	}
	return false
}

func posixPackageManagerProgram(program string) bool {
	switch strings.ToLower(path.Base(program)) {
	case "apt", "apt-get", "apt-cache", "apt-mark", "dpkg", "dpkg-query", "dpkg-deb":
		return true
	default:
		return false
	}
}
