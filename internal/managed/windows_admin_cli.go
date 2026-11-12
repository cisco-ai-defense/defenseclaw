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

// WindowsStandaloneSetupName is the standalone Setup a release ships. Setup
// is not installed on the computer it manages (the MDM kit removes its staged
// copy when a run ends), so a hint that needs it runs it from the folder that
// holds it (WindowsSetupCommand) and says where it comes from
// (WindowsSetupSource). cowork-1-0-8 GAP-0095.
const WindowsStandaloneSetupName = "DefenseClawSetup-Enterprise-Standalone-x64.exe"

// WindowsSetupSource says that Setup is not on the computer and where an
// administrator gets it. A hint that names a Setup command ends with it, once.
const WindowsSetupSource = "Setup is not installed on this computer: use the copy in your MDM package or the release download"

// WindowsSetupCommand is the standalone Setup run with args in PowerShell from
// the folder that holds it: & '.\DefenseClawSetup-Enterprise-Standalone-x64.exe' /repair JSON=1.
// PowerShell does not run a program of the current folder by its bare name, so
// the bare name a hint printed was "not recognized" even beside the file.
func WindowsSetupCommand(args ...string) string {
	return WindowsCommandLine(`.\`+WindowsStandaloneSetupName, args...)
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
// them is doubled like an apostrophe. It is the one PowerShell quoting rule:
// the hook-command builders (connector, legacyconnector), the ACP setup and
// every hint use it (g072 review 2 S3); the source check fails a quote
// doubled by hand.
func PowerShellLiteral(value string) string {
	return "'" + PowerShellLiteralBody(value) + "'"
}

// PowerShellLiteralBody is value escaped for the inside of a single-quoted
// PowerShell literal, for a template that holds the quotes itself
// ('{{.HookBinaryPS}}'): each single quote, the apostrophe or a typographic
// one, is doubled.
func PowerShellLiteralBody(value string) string {
	var quoted strings.Builder
	for _, r := range value {
		quoted.WriteRune(r)
		if strings.ContainsRune(powerShellSingleQuotes, r) {
			quoted.WriteRune(r)
		}
	}
	return quoted.String()
}

// PowerShellLiteralValue is the value of body, the inside of a single-quoted
// PowerShell literal (PowerShellLiteralBody): each doubled quote is one. A
// quote that is not doubled is kept, as the hook-command parsers kept a lone
// apostrophe.
//
// PowerShell's tokenizer reads any two single quotes in a row as one, the
// second ('’ is ’); this reads only identical pairs (g072 review 3 N1). That
// is enough, because every reader then requires the value to be DefenseClaw's
// own path (pathidentity.Same with a launcher candidate) or one of its exact
// commands: no other pairing decodes to those, and the only lone-quote form
// that does is this package's own pre-1.0.9 render, which stays owned so
// setup rewrites it. The Python copy, defenseclaw/winquote.py, reads the same.
func PowerShellLiteralValue(body string) string {
	runes := []rune(body)
	var value strings.Builder
	for i := 0; i < len(runes); i++ {
		value.WriteRune(runes[i])
		if strings.ContainsRune(powerShellSingleQuotes, runes[i]) && i+1 < len(runes) && runes[i+1] == runes[i] {
			i++
		}
	}
	return value.String()
}

// PowerShellLiteralBeforeTypographicQuotes is text, which holds PowerShell
// literals from PowerShellLiteral, as releases before 1.0.9 rendered it: they
// doubled only the apostrophe, so each doubled typographic quote is one again.
// Such a literal ended early on a path like C:\Users\O’Brien; the
// hook-ownership matchers keep that form owned, so setup rewrites it and
// teardown removes it. ok is false when text has no doubled typographic quote.
func PowerShellLiteralBeforeTypographicQuotes(text string) (string, bool) {
	old := text
	for _, r := range powerShellSingleQuotes[1:] {
		old = strings.ReplaceAll(old, string(r)+string(r), string(r))
	}
	return old, old != text
}

// powerShellSingleQuotes are the characters PowerShell takes as a single
// quote: the apostrophe and U+2018 to U+201B.
const powerShellSingleQuotes = "'\u2018\u2019\u201a\u201b"

// powerShellArgument is arg as PowerShell passes it to a native command:
// unchanged when it is a plain word (a subcommand, a flag, a connector name)
// or a <placeholder> the reader replaces, a literal otherwise.
//
// Two Windows PowerShell 5.1 limits of native-command arguments, which no
// caller reaches (g072 review 2 N1): it drops an empty argument, which 7.3
// and later pass (an unknown account is the <account> placeholder), and it
// passes an argument that holds a space and ends in a backslash as "...\",
// which the program reads with a stray quote (no path argument ends in one).
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
