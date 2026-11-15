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
