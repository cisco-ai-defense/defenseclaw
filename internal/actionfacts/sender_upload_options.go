// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// uploadOptionFiles is the local files the upload options of a network
// client name as the uploaded data (known is false for a program with no
// option table here): the operand of every option the client's
// own option table marks as a file source (curl -T, -d @f, --data-binary @f,
// --json @f, -F name=@f, --data-urlencode name@f, -H @f, -b f; wget
// --post-file, --body-file). It reads the option tables whether or not the
// whole parse is complete, so a call the projection holds as partial (an
// option the response grammar does not know, a second URL) still names the
// files it sends. GAP-0768: a partial wget upload was silent in every tier.
func uploadOptionFiles(command CommandFact) (files []string, known bool) {
	if len(command.Argv) == 0 {
		return nil, false
	}
	switch {
	case isCurlProgram(command.Program):
		return curlUploadOptionFiles(parseCurlArgv(command.Argv)), true
	case isWgetProgram(command.Program):
		files, _, _ := scanWgetUploadOptions(command.Argv)
		return files, true
	}
	return nil, false
}

// scanWgetUploadOptions reads a wget argv option by option against the
// wget option tables WITHOUT stopping at an option the tables do not know:
// the files its --post-file and --body-file options name, its positional
// words, and whether an option could not be resolved (a real wget option the
// tables do not model, such as --trust-server-names). A long option is
// resolved as getopt does, by its exact name or its one unambiguous prefix. An
// unmodelled option never hides the upload options that follow it
// (GAP-0768).
func scanWgetUploadOptions(argv []string) (files, positional []string, unresolved bool) {
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case options && arg == "--":
			options = false
		case !options || arg == "-" || !strings.HasPrefix(arg, "-"):
			positional = append(positional, arg)
		case strings.HasPrefix(arg, "--"):
			name, value, joined := strings.Cut(arg[2:], "=")
			spec, ok := resolveWgetLongOption(name)
			if !ok {
				unresolved = true
				continue
			}
			if spec.arity != wgetOptionRequiredValue {
				continue
			}
			if !joined {
				if i+1 >= len(argv) {
					unresolved = true
					continue
				}
				i++
				value = argv[i]
			}
			if (spec.name == "--post-file" || spec.name == "--body-file") && value != "" && value != "-" {
				files = append(files, value)
			}
		default:
			for offset := 1; offset < len(arg); offset++ {
				spec, ok := wgetShortOptionSpecs[arg[offset]]
				if !ok {
					unresolved = true
					break
				}
				if spec.arity != wgetOptionRequiredValue {
					continue
				}
				if offset+1 >= len(arg) {
					if i+1 >= len(argv) {
						unresolved = true
					} else {
						i++
					}
				}
				break
			}
		}
	}
	return files, positional, unresolved
}

// resolveWgetLongOption finds a wget long option by its exact name (with the
// no- spelling of the booleans) or by the one table name it is a prefix of.
func resolveWgetLongOption(name string) (wgetOptionSpec, bool) {
	if name == "" {
		return wgetOptionSpec{}, false
	}
	if spec, ok := lookupWgetLongOption(name); ok {
		return spec, true
	}
	var found wgetOptionSpec
	matches := 0
	for key, spec := range wgetLongOptionSpecs {
		if strings.HasPrefix(key, name) && (matches == 0 || spec.name != found.name) {
			found = spec
			matches++
		}
	}
	return found, matches == 1
}

func curlUploadOptionFiles(parsed curlArgvParse) []string {
	var files []string
	add := func(path string) {
		if path != "" && path != "-" && path != "." {
			files = append(files, path)
		}
	}
	for _, option := range parsed.Options {
		if !option.ValuePresent {
			continue
		}
		switch option.Canonical {
		case "--data", "--data-ascii", "--data-binary", "--json":
			if path, stdin, source := webDataFile(option.Value); source && !stdin {
				add(path)
			}
		case "--data-urlencode":
			if path, stdin, source, _ := curlDataURLEncodeFile(option.Value); source && !stdin {
				add(path)
			}
		case "--form":
			if path, stdin, source := webFormFile(option.Value); source && !stdin {
				add(path)
			}
		case "--header":
			if strings.HasPrefix(option.Value, "@") {
				add(strings.TrimPrefix(option.Value, "@"))
			}
		case "--cookie":
			if !containsCookieLiteral(option.Value) {
				add(option.Value)
			}
		}
	}
	for _, target := range parsed.Targets {
		if target.UploadSet {
			add(target.UploadValue)
		}
	}
	return files
}

// senderOperandWords are the words of a sender's command that name what it
// sends or where: the operands, not the values its options own. An
// identity or certificate file (ssh -i, -o IdentityFile=, curl --key,
// --cert) authenticates the connection and is never the uploaded data
// (GAP-0771, GAP-0772). The option tables decide (sshFlagConsumesValue,
// scpOptionGrammar, the curl and wget argv parsers); a program with no table
// keeps every static word.
func senderOperandWords(program string, words []string) []string {
	switch program {
	case "ssh", "sftp", "autossh", "scp":
		out := make([]string, 0, len(words))
		for i := 0; i < len(words); i++ {
			word := words[i]
			if word == "--" {
				out = append(out, words[i+1:]...)
				break
			}
			if len(word) < 2 || word[0] != '-' || word[1] == '-' {
				out = append(out, word)
				continue
			}
			consumes, joined := false, false
			if program == "scp" {
				consumes, joined, _ = scpOptionGrammar(word)
			} else if len(word) == 2 {
				consumes = sshFlagConsumesValue(program, word)
			} else if sshFlagConsumesValue(program, word[:2]) {
				consumes, joined = true, true
			}
			if consumes && !joined {
				i++
			}
		}
		return staticOperands(out)
	case "curl":
		argv := append([]string{program}, words...)
		parsed := parseCurlArgv(argv)
		out := append([]string(nil), curlUploadOptionFiles(parsed)...)
		for _, target := range parsed.Targets {
			out = append(out, target.Value)
		}
		return staticOperands(out)
	case "wget":
		files, positional, _ := scanWgetUploadOptions(append([]string{program}, words...))
		return staticOperands(append(files, positional...))
	}
	return staticOperands(words)
}

// readUploadOptionSenders adds the curl and wget commands the projection did
// not take as a sender: a command whose upload options name a file is a
// sender whatever the rest of its parse says, and a partial parse (an option
// the tables do not know) with no proven upload is a sender to an unknown
// destination, never a clean allow (the one bound rule). The destination of
// a sender with no network fact is not read in full.
func readUploadOptionSenders(facts Facts, reading *SendReading) {
	taken := map[int64]bool{}
	for _, sender := range reading.Senders {
		if sender.CommandID != 0 {
			taken[sender.CommandID] = true
		}
	}
	for _, command := range facts.Commands {
		if command.Kind == CommandKindShellRedirect || command.Effect == EffectPreview || taken[command.ID] ||
			len(command.Argv) == 0 {
			continue
		}
		var files, targets []string
		partial := false
		switch {
		case isCurlProgram(command.Program):
			parsed := parseCurlArgv(command.Argv)
			files = curlUploadOptionFiles(parsed)
			for _, target := range parsed.Targets {
				targets = append(targets, target.Value)
			}
			partial = !parsed.Complete
		case isWgetProgram(command.Program):
			var unresolved bool
			files, targets, unresolved = scanWgetUploadOptions(command.Argv)
			partial = unresolved || !parseWgetArgv(command.Argv).Complete
		default:
			continue
		}
		if len(files) == 0 && !partial {
			continue
		}
		sender := SenderFact{
			CommandID: command.ID, Program: senderProgramName(command.Program), Origin: SenderUploadOption,
			DestinationUnknown: true, Operands: staticOperands(append(files, targets...)),
			FedText: fedStdinText(command),
		}
		for _, target := range targets {
			if host, ok := urlOperandHost(target); ok {
				sender.Hosts = appendHost(sender.Hosts, host)
			}
		}
		reading.Senders = append(reading.Senders, sender)
	}
}
