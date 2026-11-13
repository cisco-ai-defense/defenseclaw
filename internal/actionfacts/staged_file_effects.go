// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// This file holds the staged-file effects of the shell recall work: bytes
// that reach a file through shell escape sequences, and a file that one
// command fetches from a bare network address and a later command of the same
// action runs. Both are detection evidence only. They never grant blocking
// authority: the first cannot know the file is later executed, the second
// cannot know the fetch succeeded or that control flow reaches the run.

var bareIPv4HostPattern = lazyMustCompile(
	`(?:^|[/@=\s'"])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]{1,5})?(?:[/?#\s'"]|$)`,
)

// escapedMinProgramBytes is the shortest decoded write that can start with a
// program or script header (the longest magic is four bytes).
const escapedMinProgramBytes = 4

// EscapedBinaryFileWrite reports a direct echo or printf whose operands decode,
// through hex or octal byte escapes, to bytes that are not text, written to a
// file (a write or append redirect, or a pipe into tee with a file operand),
// when the write is also shaped like staging a program:
//
//   - it begins with the magic of an executable or a script (ELF, PE, Mach-O,
//     "#!"): the first chunk of a binary, or a script written out in escapes; or
//   - it appends to the file (">>", "tee -a"): droppers write a binary one
//     chunk at a time, so a later chunk has no magic but is an append; or
//   - the same action then makes the file executable or runs it.
//
// "Not text" is a decision on the decoded bytes of the whole operand, not on
// runs of escapes or their length: the bytes are not valid UTF-8, or hold a NUL
// or a control byte other than tab, newline, carriage return and escape (so
// color codes and a byte order mark stay text). A single plain write of a key
// or a digest into a fixture file is binary but is none of the above, so it
// stays quiet.
func EscapedBinaryFileWrite(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX {
		return false
	}
	for index, command := range facts.Commands {
		if command.Dialect != DialectPOSIX || command.Kind != CommandKindProcess ||
			(command.Program != "echo" && command.Program != "printf") {
			continue
		}
		decoded, escaped := decodeEscapedOperands(command)
		magic := len(decoded) >= escapedMinProgramBytes && hasProgramMagic(decoded)
		if escaped == 0 || (!magic && !isBinaryContent(decoded)) {
			continue
		}
		target, appends, ok := escapedWriteTarget(facts, command)
		if !ok {
			continue
		}
		if appends || magic || fileMadeExecutableOrRunLater(facts, index, target) {
			return true
		}
	}
	return false
}

// decodeEscapedOperands decodes the operands of an echo or printf: hex and
// octal escapes become bytes, the common one-letter escapes become their byte,
// everything else stays as written. It returns the bytes and the count of hex
// and octal escapes it decoded.
func decodeEscapedOperands(command CommandFact) ([]byte, int) {
	var decoded []byte
	escaped := 0
	for index, argument := range command.Argv {
		if index == 0 || isEchoOptionWord(argument) {
			continue
		}
		for i := 0; i < len(argument); i++ {
			if argument[i] != '\\' || i+1 >= len(argument) {
				decoded = append(decoded, argument[i])
				continue
			}
			i++
			switch c := argument[i]; {
			case c == 'x':
				value, width := parseEscapeDigits(argument[i+1:], 16, 2)
				if width == 0 {
					decoded = append(decoded, '\\', 'x')
					continue
				}
				decoded = append(decoded, byte(value))
				escaped++
				i += width
			case c >= '0' && c <= '7':
				digits := argument[i:]
				if c == '0' {
					digits = argument[i+1:]
					i++
				}
				value, width := parseEscapeDigits(digits, 8, 3)
				if width == 0 {
					decoded = append(decoded, 0)
					escaped++
					continue
				}
				decoded = append(decoded, byte(value))
				escaped++
				i += width - 1
			case c == 'n':
				decoded = append(decoded, '\n')
			case c == 't':
				decoded = append(decoded, '\t')
			case c == 'r':
				decoded = append(decoded, '\r')
			case c == 'e' || c == 'E':
				decoded = append(decoded, 0x1b)
			case c == '\\' || c == '"' || c == '\'':
				decoded = append(decoded, c)
			default:
				decoded = append(decoded, '\\', c)
			}
		}
	}
	return decoded, escaped
}

func isEchoOptionWord(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' {
		return false
	}
	return strings.Trim(argument[1:], "neE") == ""
}

// parseEscapeDigits reads up to maxWidth digits of the base and returns the
// value (kept to a byte) and the number of digits read.
func parseEscapeDigits(text string, base, maxWidth int) (uint64, int) {
	var value uint64
	width := 0
	for width < len(text) && width < maxWidth {
		digit, err := strconv.ParseUint(text[width:width+1], base, 8)
		if err != nil {
			break
		}
		value = value*uint64(base) + digit
		width++
	}
	return value & 0xff, width
}

// isBinaryContent reports bytes that are not text: not valid UTF-8, or a NUL or
// a control byte other than tab, newline, carriage return and escape.
func isBinaryContent(data []byte) bool {
	if !utf8.Valid(data) {
		return true
	}
	for _, b := range data {
		if (b < 0x20 && b != '\t' && b != '\n' && b != '\r' && b != 0x1b) || b == 0x7f {
			return true
		}
	}
	return false
}

func hasProgramMagic(data []byte) bool {
	for _, magic := range [][]byte{
		{'#', '!'},
		{0x7f, 'E', 'L', 'F'},
		{'M', 'Z'},
		{0xcf, 0xfa, 0xed, 0xfe}, {0xce, 0xfa, 0xed, 0xfe},
		{0xfe, 0xed, 0xfa, 0xcf}, {0xfe, 0xed, 0xfa, 0xce},
		{0xca, 0xfe, 0xba, 0xbe},
	} {
		if len(data) >= len(magic) && string(data[:len(magic)]) == string(magic) {
			return true
		}
	}
	return false
}

// escapedWriteTarget returns the file the command writes (a write or append
// redirect, or a tee operand it pipes into) and whether the write appends.
func escapedWriteTarget(facts Facts, command CommandFact) (string, bool, bool) {
	for _, redirect := range command.Redirects {
		if (redirect.Access != PathAccessWrite && redirect.Access != PathAccessAppend) ||
			redirect.Target == "" || strings.HasPrefix(redirect.Target, "/dev/") {
			continue
		}
		return redirect.Target, redirect.Access == PathAccessAppend, true
	}
	if command.PipelineID == 0 {
		return "", false, false
	}
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID != command.ID || flow.From != DataStdout || flow.To != DataStdin {
			continue
		}
		for _, sink := range facts.Commands {
			if sink.ID != flow.ToCommandID || sink.Program != "tee" {
				continue
			}
			for _, candidate := range facts.Paths {
				if candidate.CommandID == sink.ID &&
					(candidate.Access == PathAccessWrite || candidate.Access == PathAccessAppend) &&
					!strings.HasPrefix(candidate.Value, "/dev/") {
					return candidate.Value, candidate.Access == PathAccessAppend, true
				}
			}
		}
	}
	return "", false, false
}

// fileMadeExecutableOrRunLater reports a later command of the action that
// changes the mode of the file or runs it.
func fileMadeExecutableOrRunLater(facts Facts, index int, target string) bool {
	clean := cleanRelative(target)
	for _, later := range facts.Commands[index+1:] {
		if len(later.Argv) > 0 && cleanRelative(later.Argv[0]) == clean {
			return true
		}
		if later.Program == "chmod" && slices.ContainsFunc(later.Argv[1:], func(argument string) bool {
			return cleanRelative(argument) == clean
		}) {
			return true
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID == later.ID && candidate.Access == PathAccessExecute && cleanRelative(candidate.Value) == clean {
				return true
			}
		}
	}
	return false
}

// LiteralStdinPasswordChange reports an account password set from text the
// command line itself supplies: the source-supported grammar (echo feeding
// passwd or chpasswd, optionally piped on into a shell), plus a passwd with no
// account operand fed by echo or printf, and passwd or chpasswd whose output
// is piped on into a shell. Ordinary chpasswd automation is not included: a
// build script that creates test users uses it without a trailing shell.
func LiteralStdinPasswordChange(facts Facts) bool {
	for _, command := range facts.Commands {
		if (command.Program == "passwd" || command.Program == "chpasswd") &&
			hasFactOperation(command, OperationAccountChange) {
			return true
		}
	}
	for _, flow := range facts.DataFlows {
		if flow.From != DataStdout || flow.To != DataStdin {
			continue
		}
		source, okSource := commandByID(facts, flow.FromCommandID)
		sink, okSink := commandByID(facts, flow.ToCommandID)
		if !okSource || !okSink {
			continue
		}
		switch {
		case (source.Program == "echo" || source.Program == "printf") &&
			sink.Program == "passwd" && len(sink.Argv) == 1:
			return true
		case (source.Program == "passwd" || source.Program == "chpasswd") &&
			(sink.Program == "bash" || sink.Program == "sh"):
			return true
		}
	}
	return false
}

func commandByID(facts Facts, id int64) (CommandFact, bool) {
	for _, command := range facts.Commands {
		if command.ID == id {
			return command, true
		}
	}
	return CommandFact{}, false
}

// BareAddressDownloadThenRunFetchedFile reports one action in which a fetch
// command (wget, curl, tftp, ftpget, optionally behind busybox) takes a file
// from a bare IPv4 address and a later command of the same action executes the
// fetched name, directly or through an interpreter, possibly after one
// cat/cp/mv copy of it. Hostnames are not covered: ordinary installers use
// them. The match is on file name, not on resolved location, because the
// working directory of a dropper line is chosen at run time.
func BareAddressDownloadThenRunFetchedFile(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX || len(facts.Commands) < 2 {
		return false
	}
	for index, source := range facts.Commands {
		names, ok := bareAddressFetchNames(source)
		if !ok {
			continue
		}
		extracted := false
		for _, later := range facts.Commands[index+1:] {
			executedList := executedNames(facts, later)
			for _, executed := range executedList {
				if names[executed] || extracted {
					return true
				}
			}
			if extractsFetchedArchive(later, names) {
				extracted = true
			}
			propagateCopiedName(facts, later, names)
		}
	}
	return false
}

func effectiveFetchProgram(command CommandFact) (string, []string) {
	argv := command.Argv
	if len(argv) == 0 {
		return "", nil
	}
	program := path.Base(argv[0])
	if program == "busybox" && len(argv) > 1 {
		return path.Base(argv[1]), argv[2:]
	}
	return program, argv[1:]
}

func bareAddressFetchNames(command CommandFact) (map[string]bool, bool) {
	if command.Kind != CommandKindProcess || command.Dialect != DialectPOSIX {
		return nil, false
	}
	program, args := effectiveFetchProgram(command)
	switch program {
	case "wget", "curl", "tftp", "ftpget":
	default:
		return nil, false
	}
	bare := false
	names := make(map[string]bool)
	add := func(value string) {
		if name := normalizedFetchedName(value); name != "" {
			names[name] = true
		}
	}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		if hasUntrustedBareAddress(argument) {
			bare = true
			if program == "wget" || program == "curl" {
				add(urlBaseName(argument))
			}
			continue
		}
		next := ""
		if index+1 < len(args) {
			next = args[index+1]
		}
		switch {
		case (program == "wget" && (argument == "-O" || argument == "--output-document")) ||
			(program == "curl" && (argument == "-o" || argument == "--output")) ||
			(program == "tftp" && (argument == "-r" || argument == "-l")):
			add(next)
			index++
		case program == "wget" && strings.HasPrefix(argument, "--output-document="):
			add(strings.TrimPrefix(argument, "--output-document="))
		case program == "wget" && strings.HasPrefix(argument, "-O") && len(argument) > 2:
			add(argument[2:])
		case program == "curl" && strings.HasPrefix(argument, "--output="):
			add(strings.TrimPrefix(argument, "--output="))
		case program == "tftp" && argument == "get" && next != "":
			add(next)
			index++
		}
	}
	if program == "tftp" || program == "ftpget" {
		// tftp host and ftpget host are bare operands, not URLs.
		for _, argument := range args {
			if parsesAsUntrustedAddress(argument) {
				bare = true
			}
		}
		if program == "ftpget" && len(args) >= 3 {
			add(args[len(args)-2])
			add(args[len(args)-1])
		}
	}
	for _, redirect := range command.Redirects {
		if redirect.Access == PathAccessWrite || redirect.Access == PathAccessAppend {
			add(redirect.Target)
		}
	}
	return names, bare && len(names) > 0
}

func hasUntrustedBareAddress(argument string) bool {
	match := bareIPv4HostPattern.FindStringSubmatch(argument)
	return len(match) == 2 && parsesAsUntrustedAddress(match[1])
}

func parsesAsUntrustedAddress(value string) bool {
	address, err := netip.ParseAddr(strings.Trim(value, "[]"))
	if err != nil || !address.Is4() {
		return false
	}
	return !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
		!address.IsUnspecified() && !address.IsMulticast()
}

func urlBaseName(rawURL string) string {
	value := rawURL
	if cut := strings.IndexAny(value, "?#"); cut >= 0 {
		value = value[:cut]
	}
	if scheme := strings.Index(value, "://"); scheme >= 0 {
		value = value[scheme+3:]
	}
	slash := strings.IndexByte(value, '/')
	if slash < 0 {
		return ""
	}
	return path.Base(value[slash:])
}

func normalizedFetchedName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" || value == "/" || strings.HasPrefix(value, "/dev/") {
		return ""
	}
	base := path.Base(path.Clean(value))
	if base == "." || base == "/" || base == ".." {
		return ""
	}
	return base
}

func executedNames(facts Facts, command CommandFact) []string {
	var names []string
	for _, candidate := range facts.Paths {
		if candidate.CommandID != command.ID || candidate.Access != PathAccessExecute {
			continue
		}
		if name := normalizedFetchedName(candidate.Value); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func propagateCopiedName(facts Facts, command CommandFact, names map[string]bool) {
	switch command.Program {
	case "cat", "cp", "mv":
	default:
		return
	}
	read := false
	for _, argument := range command.Argv[1:] {
		if names[normalizedFetchedName(argument)] {
			read = true
		}
	}
	if !read {
		return
	}
	for _, redirect := range command.Redirects {
		if redirect.Access == PathAccessWrite || redirect.Access == PathAccessAppend {
			if name := normalizedFetchedName(redirect.Target); name != "" {
				names[name] = true
			}
		}
	}
	if command.Program != "cat" && len(command.Argv) >= 3 {
		if name := normalizedFetchedName(command.Argv[len(command.Argv)-1]); name != "" {
			names[name] = true
		}
	}
}

// extractsFetchedArchive reports an archive tool that unpacks a fetched
// name. What the archive holds is unknown, so a later run of any file the
// action names counts as running fetched content.
func extractsFetchedArchive(command CommandFact, names map[string]bool) bool {
	switch command.Program {
	case "tar", "unzip", "gunzip", "bunzip2", "unxz", "7z", "7za", "unar":
	default:
		return false
	}
	for _, argument := range command.Argv[1:] {
		if names[normalizedFetchedName(argument)] {
			return true
		}
	}
	return false
}
