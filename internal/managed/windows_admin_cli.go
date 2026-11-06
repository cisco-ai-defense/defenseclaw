// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "strings"

// WindowsStandaloneAdminCLI is the managed CLI an administrator runs on a
// Windows standalone computer, as the docs name it. Setup puts no
// DefenseClaw command on PATH, so a hint must name this path (GAP-1183).
// Program Files is the machine's protected registration
// (windowsAdminProgramFiles), as for the managed layout, never the process's
// ProgramFiles variable: a standard user who set it in a shell was handed a
// hint naming a folder of theirs, which the hint tells an administrator to
// run elevated (g072 review 2 S2).
func WindowsStandaloneAdminCLI() string {
	return windowsAdminProgramFiles() + `\Cisco\DefenseClaw\bin\defenseclaw.exe`
}

// windowsDefaultProgramFiles is the Program Files of a hint when the machine
// registration cannot be read, and on a computer that is not Windows, where
// the hint is only rendered (tests, docs).
const windowsDefaultProgramFiles = `C:\Program Files`

// WindowsStandaloneGatewayCLI is the managed gateway executable an
// administrator runs on a Windows standalone computer: standalone Setup
// ships it beside WindowsStandaloneAdminCLI.
func WindowsStandaloneGatewayCLI() string {
	return WindowsGatewayBeside(WindowsStandaloneAdminCLI())
}

// WindowsGatewayBeside is the defenseclaw-gateway.exe in the folder of cli.
func WindowsGatewayBeside(cli string) string {
	return cli[:strings.LastIndexAny(cli, `/\`)+1] + "defenseclaw-gateway.exe"
}

// WindowsAdminCommand is a managed defenseclaw.exe command as it is typed in
// PowerShell on a Windows standalone computer: `& '<path>' arg...`. Setup
// puts no DefenseClaw command on PATH, so a bare `defenseclaw ...` is "not
// recognized" (GAP-1183, GAP-1338, cowork-1-0-8 GAP-0076). The form is
// PowerShell's: cmd.exe reads the `&` as a separator, so every sentence
// that hands it on names PowerShell. Each element of args is one argument.
func WindowsAdminCommand(args ...string) string {
	return WindowsCommandLine(WindowsStandaloneAdminCLI(), args...)
}

// WindowsGatewayCommand is WindowsAdminCommand for the managed gateway
// executable (sandbox administration is a gateway command, r103 GAP-0215).
func WindowsGatewayCommand(args ...string) string {
	return WindowsCommandLine(WindowsStandaloneGatewayCLI(), args...)
}

// WindowsCommandLine is executable run with args in PowerShell. The path is
// always a literal, and so is every argument that is not a plain word or a
// <placeholder>: an account named "John Smith" was two arguments, and
// "O'Brien" or "svc$" broke the quoting or expanded as a variable
// (cowork-1-0-8 GAP-0076). Commands are rendered here and nowhere else;
// TestManagedWindowsCommandsComeFromTheRenderer checks the sources.
func WindowsCommandLine(executable string, args ...string) string {
	var line strings.Builder
	line.WriteString("& ")
	line.WriteString(PowerShellLiteral(executable))
	for _, arg := range args {
		line.WriteByte(' ')
		line.WriteString(powerShellArgument(arg))
	}
	return line.String()
}

// PowerShellLiteral is value as one inert single-quoted PowerShell string.
// PowerShell reads the typographic single quotes as quotes too, so each of
// them is doubled like an apostrophe.
func PowerShellLiteral(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('\'')
	for _, r := range value {
		quoted.WriteRune(r)
		if strings.ContainsRune(powerShellSingleQuotes, r) {
			quoted.WriteRune(r)
		}
	}
	quoted.WriteByte('\'')
	return quoted.String()
}

// powerShellSingleQuotes are the characters PowerShell takes as a single
// quote: the apostrophe and U+2018 to U+201B.
const powerShellSingleQuotes = "'\u2018\u2019\u201a\u201b"

// powerShellArgument is arg as PowerShell passes it to a native command:
// unchanged when it is a plain word (a subcommand, a flag, a connector name)
// or a <placeholder> the reader replaces, a literal otherwise.
func powerShellArgument(arg string) string {
	if len(arg) > 2 && arg[0] == '<' && arg[len(arg)-1] == '>' && !strings.ContainsAny(arg[1:len(arg)-1], "<>'\"`$\u2018\u2019\u201a\u201b") {
		return arg
	}
	if arg == "" {
		return "''"
	}
	for _, r := range arg {
		if !powerShellPlainRune(r) {
			return PowerShellLiteral(arg)
		}
	}
	return arg
}

// powerShellPlainRune reports a character a bare argument may hold: a
// letter, a digit or one of - _ . : / = +, none of which PowerShell reads as
// syntax.
func powerShellPlainRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:/=+", r)
}
