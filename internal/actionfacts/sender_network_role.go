// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
)

// The network role of a command, read from what the projection already
// knows about network programs (GAP-0719). The sender reader has no list of
// sender programs: the egress classifiers (ssh, nc, socat, curl, scp, rsync
// ...) publish network facts and data flows, and the reader reads those.
//
//   - A command with a network fact of the connect, tunnel or upload action
//     (so a program the classifiers know) whose standard input is fed (a pipe,
//     a redirect, a here-document) or whose standard output is written to the
//     network (a /dev/tcp redirect) writes data to that endpoint: a sender.
//     The endpoint is read from the fact; a destination that is not proven
//     loopback or private is not read in full (unknown tier).
//   - A command whose network role is not proven (no network fact: the
//     classifiers do not know the program) but that takes a URL or a
//     user@host:path operand, and has local data to send (a fed standard
//     input or a path operand), is a sender to an unknown destination.
//
// A program that only names a remote endpoint (git clone URL, pip install
// URL) has no local data input and is not a sender.

const (
	// SenderNetworkRole is a command with a proven network endpoint (a
	// network fact of its projection) that writes its standard input to it.
	SenderNetworkRole SenderOrigin = "network_role"
	// SenderUnprovenRole is a command whose network role is not proven that
	// takes a remote operand and local data.
	SenderUnprovenRole SenderOrigin = "unproven_role"
)

// mailSenderPrograms hand their standard input or attachments to a mail
// server. The classifiers publish no network facts for them, so this is the
// one list of sender programs the reader keeps; every other sender is read
// from the classifier facts or the operand shape.
var mailSenderPrograms = map[string]bool{
	"mail": true, "mailx": true, "sendmail": true, "swaks": true, "msmtp": true, "mutt": true,
}

// stdinFed reports that something is fed to the command's standard input: a
// pipe from another command, a file redirect, a here-document.
func stdinFed(facts Facts, command CommandFact) bool {
	if command.LiteralStdin != "" || command.LiteralStdinComplete {
		return true
	}
	for _, redirect := range command.Redirects {
		if redirect.FD == 0 && redirect.Access == PathAccessRead {
			return true
		}
	}
	for _, flow := range facts.DataFlows {
		if flow.ToCommandID == command.ID && flow.To == DataStdin {
			return true
		}
	}
	return false
}

// writesNetwork reports that the command's standard output goes to the
// network (a redirect into /dev/tcp).
func writesNetwork(facts Facts, command CommandFact) bool {
	for _, flow := range facts.DataFlows {
		if flow.FromCommandID == command.ID && flow.From == DataStdout && flow.To == DataNetwork {
			return true
		}
	}
	return false
}

// commandWords is a command's words after its program, from its arguments
// (a static glob as its pattern) or, when it has none, from its argv.
func commandWords(command CommandFact) []string {
	if len(command.Arguments) == 0 {
		return commandArgs(command)
	}
	words := make([]string, 0, len(command.Arguments))
	for i, argument := range command.Arguments {
		if i == 0 && senderProgramName(argument.Value) == senderProgramName(command.Program) {
			continue
		}
		word := argument.Value
		if word == "" {
			word = argument.StaticGlob // a static glob is the pattern, not nothing
		}
		words = append(words, word)
	}
	return words
}

func networkFactsOf(facts Facts, commandID int64) []NetworkFact {
	var out []NetworkFact
	for _, network := range facts.Network {
		if network.CommandID == commandID {
			out = append(out, network)
		}
	}
	return out
}

// readNetworkRoleSenders adds the senders of the two network-role rules (see
// the comment at the top of this file) for the projected commands that the
// upload reading did not already take.
func readNetworkRoleSenders(facts Facts, reading *SendReading, assumeFed bool) {
	taken := map[int64]bool{}
	for _, sender := range reading.Senders {
		if sender.CommandID != 0 {
			taken[sender.CommandID] = true
		}
	}
	for _, command := range facts.Commands {
		if command.Kind == CommandKindShellRedirect || command.Effect == EffectPreview || taken[command.ID] {
			continue
		}
		if sender, ok := readCommandNetworkRole(facts, command, assumeFed); ok {
			reading.Senders = append(reading.Senders, sender)
		}
	}
}

func readCommandNetworkRole(facts Facts, command CommandFact, assumeFed bool) (SenderFact, bool) {
	prog := senderProgramName(command.Program)
	words := commandWords(command)
	fed := assumeFed || stdinFed(facts, command)
	var connects []NetworkFact
	networked := false
	for _, network := range networkFactsOf(facts, command.ID) {
		networked = true
		switch network.Action {
		case NetworkConnect, NetworkTunnel, NetworkUpload:
			connects = append(connects, network)
		}
	}
	if len(connects) > 0 {
		if !fed && !writesNetwork(facts, command) {
			return SenderFact{}, false
		}
		sender := SenderFact{
			CommandID: command.ID, Program: prog, Origin: SenderNetworkRole,
			Network: connects, DestinationUnknown: !command.ArgvComplete,
			Operands: senderOperandWords(prog, words), FedText: command.LiteralStdin,
		}
		external := false
		for _, network := range connects {
			host := network.NormalizedHost
			if host == "" {
				host = network.Host
			}
			if host != "" && network.TargetKind != NetworkTargetUnknown && network.TargetKind != NetworkTargetGenerated {
				sender.Hosts = appendHost(sender.Hosts, host)
			}
			switch {
			case network.Scope == NetworkScopeLoopback || network.Scope == NetworkScopeLinkLocal || network.Scope == NetworkScopePrivate:
			case host == "localhost" || strings.HasSuffix(host, ".localhost"):
			default:
				external = true
			}
		}
		if !external {
			return SenderFact{}, false // a local socket: proven not external
		}
		// the program may write more than its input to the endpoint (ssh runs
		// a command there): the data handling is not read in full
		sender.DestinationUnknown = true
		return sender, true
	}
	if networked {
		return SenderFact{}, false // the classifier proved a role that is not a send (a download, a scan)
	}
	if mailSenderPrograms[prog] {
		return SenderFact{CommandID: command.ID, Program: prog, Origin: SenderUnprovenRole, DestinationUnknown: true,
			Operands: senderOperandWords(prog, words)}, true
	}
	if !unprovenRoleSends(prog, words, fed) {
		return SenderFact{}, false
	}
	return SenderFact{
		CommandID: command.ID, Program: prog, Origin: SenderUnprovenRole, DestinationUnknown: true,
		Operands: senderOperandWords(prog, words),
	}, true
}

// unprovenRoleSends reports a program the classifiers do not own that takes a
// remote operand (a URL, user@host:path, a dotted host:path; with a fed
// standard input also user@host) and has local data to send (a fed standard
// input or a path operand). A git subcommand other than push, and a remote
// operand with no local data, send nothing.
func unprovenRoleSends(prog string, words []string, fed bool) bool {
	if prog == "" || strings.HasPrefix(prog, "-") || remoteCopyProgram(prog) || prog == "find" || prog == "xargs" ||
		wrappedProgramIndex(prog, words) >= 0 {
		return false // an option, a program the remote-copy, find or xargs reading owns, a wrapper
	}
	switch prog {
	case "eval", "trap", "bash", "sh", "zsh", "dash", "ksh", "source", ".", "echo", "printf":
		return false // shell text, read as shell text; a program that only prints its words
	}
	if prog == "git" && senderGitSubcommand(words) != "push" {
		return false
	}
	remote, data := false, fed
	for _, word := range words {
		switch {
		case unprovenRemoteOperand(word):
			remote = true
		case fed && (emailLikeOperand(word) || dottedHostPortOperand(word) || bareHostnameOperand(word)):
			remote = true
		case localPathOperand(word):
			data = true
		}
	}
	return remote && data
}

// unprovenRemoteOperand reports a word that names a remote endpoint: a URL
// (not file:), user@host:path, or a dotted host followed by a path (never a
// port: file.go:12 is a line, host.example:443 a bare port).
func unprovenRemoteOperand(word string) bool {
	if len(word) > 2048 || strings.ContainsAny(word, "\x00 \t\r\n|;&<>()") {
		return false // a pattern or a sentence, not an operand
	}
	if senderURLOperand.MatchString(word) {
		return !strings.HasPrefix(strings.ToLower(word), "file:")
	}
	m := senderRemoteOperand.FindStringSubmatch(word)
	if m == nil || len(m[1]) < 2 {
		return false
	}
	rest := word[len(m[0]):]
	if strings.Contains(m[0], "@") {
		return true
	}
	return strings.Contains(m[1], ".") && rest != "" && (rest[0] < '0' || rest[0] > '9')
}

// emailLikeOperand is user@host.tld: a mail address or an ssh target.
func emailLikeOperand(word string) bool {
	user, host, ok := strings.Cut(word, "@")
	if !ok || user == "" || strings.ContainsAny(word, " /\\:=\x00") || len(word) > 320 {
		return false
	}
	return strings.Contains(host, ".") && !strings.HasPrefix(host, ".") && !strings.HasSuffix(host, ".")
}

// dottedHostPortOperand is host.tld:port (openssl s_client -connect).
func dottedHostPortOperand(word string) bool {
	host, port, ok := strings.Cut(word, ":")
	if !ok || port == "" || len(port) > 5 || !strings.Contains(host, ".") || !bareHostnameOperand(host) {
		return false
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

// senderFileExtensions are the last labels of a dotted word that name a file,
// not a host (a bare hostname operand is read only for a program whose
// standard input is fed).
var senderFileExtensions = map[string]bool{
	"txt": true, "log": true, "json": true, "yaml": true, "yml": true, "toml": true, "ini": true,
	"cfg": true, "conf": true, "env": true, "sh": true, "py": true, "go": true, "js": true,
	"ts": true, "md": true, "csv": true, "xml": true, "html": true, "htm": true, "css": true,
	"cpp": true, "rs": true, "java": true, "rb": true, "pl": true, "sql": true, "tgz": true,
	"gz": true, "zip": true, "tar": true, "bak": true, "key": true, "pem": true, "crt": true,
	"cer": true, "pub": true, "lock": true, "sum": true, "mod": true, "tmp": true, "out": true,
	"err": true, "pdf": true, "png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"bin": true, "exe": true, "dll": true, "so": true, "orig": true, "old": true, "swp": true,
}

// bareHostnameOperand is a dotted DNS name (example.com) whose last label is
// alphabetic and not a file extension.
func bareHostnameOperand(word string) bool {
	if len(word) < 4 || len(word) > 253 || strings.HasPrefix(word, ".") || strings.HasSuffix(word, ".") {
		return false
	}
	labels := strings.Split(strings.ToLower(word), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 || senderFileExtensions[tld] {
		return false
	}
	for _, c := range tld {
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// localPathOperand is a word that names a local file: a path, a dot file, a
// home path, a curl-style @file.
func localPathOperand(word string) bool {
	if word == "" || word == "-" || len(word) > 4096 || senderURLOperand.MatchString(word) || unprovenRemoteOperand(word) {
		return false
	}
	if strings.HasPrefix(word, "--") {
		return false // an option, not an operand (its value follows)
	}
	return strings.ContainsAny(word, `/\`) || strings.HasPrefix(word, ".") ||
		strings.HasPrefix(word, "~") || strings.HasPrefix(word, "@")
}

// senderGitSubcommand is the first word of git's arguments past its global options.
func senderGitSubcommand(words []string) string {
	for i := 0; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "-C" || word == "-c" || word == "--git-dir" || word == "--work-tree" || word == "--namespace":
			i++
		case strings.HasPrefix(word, "-"):
		default:
			return word
		}
	}
	return ""
}

// staticOperands are the operand words that hold no empty (dynamic) text.
func staticOperands(words []string) []string {
	out := make([]string, 0, len(words))
	for _, word := range words {
		if word != "" {
			out = append(out, word)
		}
	}
	return out
}
