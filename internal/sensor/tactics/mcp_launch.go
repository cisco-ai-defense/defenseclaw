// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import (
	"slices"
	"strings"
	"sync/atomic"
)

// LaunchReader is the program table's reading of a command, as
// startsLocalMCPServer needs it. Launched returns the argv of the program a
// command's launchers start (env, sudo, nohup, timeout, setsid, ...) and
// whether that child is certain; Modeled reports a program the table has a
// row for. windows selects the Windows table.
//
// The host plane (package sensor) sets it from internal/effects; tactics does
// not import effects itself because the slim hook binary links tactics (its
// path readers use RunsProgram and MayNameProgram) and its size budget has no
// room for the effects tables. Without a reader every command that names a
// server keeps the 1.0.10 reading.
type LaunchReader struct {
	Launched func(argv []string, windows bool) (child []string, known bool)
	Modeled  func(program string, windows bool) bool
}

var launchReader atomic.Pointer[LaunchReader]

// SetLaunchReader installs the program table reader startsLocalMCPServer uses.
func SetLaunchReader(reader LaunchReader) {
	launchReader.Store(&reader)
}

// mcpContainerRunners start a container whose program is inside the image, so
// the run command's own words are all there is to read (docker run
// ghcr.io/acme/mcp-server-git): an MCP name among them counts.
var mcpContainerRunners = map[string]bool{"docker": true, "podman": true, "nerdctl": true}

// mcpContainerRunWords are the subcommands with which a container runner
// starts a container.
var mcpContainerRunWords = []string{"run", "create"}

// startsLocalMCPServer reports whether cmdline may run a local MCP tool
// server. Each command it holds (in a list, a pipeline, a substitution, or a
// script handed to sh -c, eval, PowerShell -Command or cmd /c) is read past
// its launchers with the wrapper rows of the effects program table
// (LaunchReader: env, sudo, nohup, timeout, setsid, nice, chroot, ...), and then:
//
//   - an MCP runtime (node, python3 -m, npx, uvx, ...) or a program named like
//     a server starts one when isMCPArgv says so, by position;
//   - a program with a row in the program table (cat, grep, tail, sed, ...)
//     does not: its operands are data, so cat mcp-server-x.json only names a
//     server (rel-1-0-10 GAP-1190);
//   - anything else keeps the 1.0.10 reading, an MCP name anywhere in the
//     command: an unmodeled program (it may be a launcher), a launcher with no
//     child or with an option its row does not account for, a dynamic program
//     word, a container image, or a script nested past the reader's limit.
//     The Claude client is unmodeled here; its own argument reader in
//     Classify decides.
func startsLocalMCPServer(cmdline string) bool {
	if !localMCPCommand.MatchString(cmdline) {
		return false
	}
	return scriptStartsMCPServer(cmdline, 0)
}

func scriptStartsMCPServer(script string, depth int) bool {
	lexer := &shellLexer{}
	lexer.parse(script, depth)
	if lexer.truncated {
		return true // the caller saw the name; the nested text was not read
	}
	for _, command := range lexer.commands {
		if commandStartsMCPServer(command.words, depth) {
			return true
		}
	}
	return false
}

// commandStartsMCPServer is startsLocalMCPServer for one simple command.
func commandStartsMCPServer(words []shellWord, depth int) bool {
	for len(words) > 0 && !words[0].quoted &&
		(shellKeywords[words[0].text] || shellAssignment.MatchString(words[0].text)) {
		words = words[1:]
	}
	if len(words) == 0 {
		return false
	}
	argv := make([]string, len(words))
	for index, word := range words {
		argv[index] = word.text
	}
	named := localMCPCommand.MatchString(strings.Join(argv, " "))
	if !named {
		return false
	}
	reader := launchReader.Load()
	if reader == nil {
		return true
	}
	child, known := reader.Launched(argv, windowsProgram(argv[0]))
	// A launcher with no child to read (env DOCS=@modelcontextprotocol/x
	// alone, the wrapper part the host plane classifies on its own) is the
	// program itself and unmodeled, like an unknown launcher option or a
	// dynamic program word.
	if !known || len(child) == 0 || strings.Contains(child[0], "$") {
		return true
	}
	program := programName(child[0])
	if mcpContainerRunners[program] && slices.ContainsFunc(child[1:], func(word string) bool {
		return slices.Contains(mcpContainerRunWords, word)
	}) {
		return true
	}
	if _, ok := interpreterScript(words); ok {
		return false // the shell reader reads the script as commands of their own
	}
	// A launcher the shell reader's own wrapper list does not know (setsid,
	// chroot ...) can start a shell whose script the reader did not follow:
	// read it here.
	if readProgram, _ := commandProgram(words); readProgram != program {
		if nested, ok := interpreterScript(childWords(words, argv, child)); ok {
			return scriptStartsMCPServer(nested, depth+1)
		}
	}
	if isMCPArgv(child) {
		return true
	}
	interpreter := strings.TrimSuffix(program, extensionOf(program))
	return !mcpInterpreters[interpreter] && !reader.Modeled(child[0], windowsProgram(child[0]))
}

// childWords are the shell words of the child argv LaunchedArgv returned: the
// tail of words, or new words when the row rewrote the child (script -c TEXT,
// flock FILE -c TEXT and watch become sh -c TEXT).
func childWords(words []shellWord, argv, child []string) []shellWord {
	if len(child) <= len(argv) && slices.Equal(argv[len(argv)-len(child):], child) {
		return words[len(words)-len(child):]
	}
	rewritten := make([]shellWord, len(child))
	for index, word := range child {
		rewritten[index] = shellWord{text: word}
	}
	return rewritten
}

// windowsProgram reports a program word written as a Windows path or with a
// Windows executable extension, which the Windows table reads.
func windowsProgram(program string) bool {
	lower := strings.ToLower(program)
	return strings.Contains(program, `\`) || strings.HasSuffix(lower, ".exe") ||
		strings.HasSuffix(lower, ".cmd") || strings.HasSuffix(lower, ".bat")
}
