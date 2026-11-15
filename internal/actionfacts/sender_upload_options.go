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
		parsed := parseWgetArgv(command.Argv)
		if parsed.PostFileSet && parsed.PostFile != "" && parsed.PostFile != "-" {
			files = append(files, parsed.PostFile)
		}
		if parsed.BodyFileSet && parsed.BodyFile != "" && parsed.BodyFile != "-" {
			files = append(files, parsed.BodyFile)
		}
		return files, true
	}
	return nil, false
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
		parsed := parseWgetArgv(append([]string{program}, words...))
		files, _ := uploadOptionFiles(CommandFact{Program: program, Argv: append([]string{program}, words...)})
		return staticOperands(append(files, parsed.Targets...))
	}
	return staticOperands(words)
}
