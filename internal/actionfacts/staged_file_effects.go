// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net/netip"
	"path"
	"strings"
)

// This file holds the staged-file effects of the shell recall work: bytes
// that reach a file through shell escape sequences, and a file that one
// command fetches from a bare network address and a later command of the same
// action runs. Both are detection evidence only. They never grant blocking
// authority: the first cannot know the file is later executed, the second
// cannot know the fetch succeeded or that control flow reaches the run.

var (
	escapedByteRunPattern = lazyMustCompile(
		`(?:\\x[0-9a-fA-F]{2}){8,}|(?:\\0?[0-7]{3}){8,}`,
	)
	bareIPv4HostPattern = lazyMustCompile(
		`(?:^|[/@=\s'"])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]{1,5})?(?:[/?#\s'"]|$)`,
	)
)

// EscapedBinaryFileWrite reports a direct echo or printf whose operand is a
// run of at least eight hex or octal byte escapes and whose output goes to a
// file (a write or append redirect, or a pipe into tee with a file operand).
// A coding agent has no reason to build a file this way: the bytes are not
// text, and the escape form hides them from content scanning. Dropper chains
// append a binary one chunk at a time, so the run test is per call and does
// not need the first chunk (the executable magic) to be present.
func EscapedBinaryFileWrite(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX {
		return false
	}
	for _, command := range facts.Commands {
		if command.Dialect != DialectPOSIX || command.Kind != CommandKindProcess ||
			(command.Program != "echo" && command.Program != "printf") ||
			!hasEscapedByteRun(command) {
			continue
		}
		if commandRedirectsToFile(command) || commandPipesToTeeFile(facts, command) {
			return true
		}
	}
	return false
}

func hasEscapedByteRun(command CommandFact) bool {
	for index, argument := range command.Argv {
		if index == 0 {
			continue
		}
		if escapedByteRunPattern.MatchString(argument) {
			return true
		}
	}
	return false
}

func commandRedirectsToFile(command CommandFact) bool {
	for _, redirect := range command.Redirects {
		if redirect.Access != PathAccessWrite && redirect.Access != PathAccessAppend {
			continue
		}
		if redirect.Target == "" || strings.HasPrefix(redirect.Target, "/dev/") {
			continue
		}
		return true
	}
	return false
}

func commandPipesToTeeFile(facts Facts, source CommandFact) bool {
	if source.PipelineID == 0 {
		return false
	}
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID != source.ID || flow.From != DataStdout || flow.To != DataStdin {
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
					return true
				}
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
