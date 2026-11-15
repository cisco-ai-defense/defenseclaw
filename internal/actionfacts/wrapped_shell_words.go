// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// A static wrapper (env, sudo, timeout, nice, ... staticPOSIXWrapperPrograms)
// runs its program with the words the shell gave the call, so the program
// it runs is read from those words, with their run-time expansion, as the
// bare call is read (rel-1-0-10:GAP-0859, substrate-1:GAP-0332): an awk
// program behind a wrapper whose words have a shell hole is the unknown tier
// at the gateway (awkprog.DynamicReason), as the bare call is.

// expandStaticPOSIXWrappedAwkCalls reads the awk call a static wrapper chain
// runs when a word of the call expands at run time (staticPOSIXWrappedAwkCall):
// expandStaticPOSIXWrappers reads only exact argvs, and a bare awk call is
// read word by word whatever its words are (GAP-0653), so the wrapped call is
// read the same way, with the shell's word objects of the awk call.
func expandStaticPOSIXWrappedAwkCalls(out *parseOutput, wrapperDepth int) {
	for _, command := range cloneCommands(out.commands) {
		if command.ArgvComplete || !staticPOSIXWrappedAwkCall(command) {
			continue
		}
		if wrapperDepth >= maxWrapperDepth {
			out.markLimit(IssueWrapperLimit)
			return
		}
		nestedArgv, ok, _ := staticPOSIXWrapperArgv(command.Argv, commandProgram(command.Executable))
		if !ok {
			continue
		}
		child := analyzeStructuredArgvWords(
			nestedArgv,
			staticPOSIXWrappedWords(command.Arguments, command.Argv, nestedArgv),
			out.nextID,
			wrapperDepth+1,
			DialectPOSIX,
		)
		child.dialect = DialectPOSIX
		carryPOSIXLiteralTildes(&child, command)
		mergeStaticPOSIXWrapperChild(out, command, child)
	}
}

// mergeStaticPOSIXWrapperChild merges the reading of the command a wrapper
// runs into the call: the child is the wrapper's, its stdout flows to the
// wrapper's when not redirected, and it records the wrapper.
func mergeStaticPOSIXWrapperChild(out *parseOutput, command CommandFact, child parseOutput) {
	for i := range child.commands {
		if child.commands[i].ParentCommandID == 0 {
			child.commands[i].ParentCommandID = command.ID
			if posixDescriptorIsUnredirected(child.commands[i], 1) {
				child.appendDataFlow(DataFlowFact{
					FromCommandID: child.commands[i].ID,
					ToCommandID:   command.ID,
					From:          DataStdout,
					To:            DataProcess,
				})
			}
		}
		child.commands[i].Wrappers = append(
			[]WrapperFact{{Executable: command.Executable, Argv: cloneSlice(command.Argv)}},
			child.commands[i].Wrappers...,
		)
	}
	out.mergeNested(child)
}

// staticPOSIXWrappedWords are the shell's word objects of nested, the
// command a static wrapper runs (staticPOSIXWrapperArgv returns a suffix of
// argv): the words the bare call of that command would have, so whether a
// word expands at run time survives the wrapper (rel-1-0-10:GAP-0859). nil
// when the words do not line up with argv.
func staticPOSIXWrappedWords(arguments []ArgumentFact, argv, nested []string) []ArgumentFact {
	offset := len(argv) - len(nested)
	if len(arguments) != len(argv) || offset < 0 {
		return nil
	}
	return arguments[offset:]
}

// withShellWords gives a command built from argv strings the run-time
// expansion of its shell words (staticPOSIXWrappedWords): the static prefix
// and hole text the awk program reading uses, and ArgvComplete. A word that
// expands is no exact argv word.
func withShellWords(command *CommandFact, words []ArgumentFact) {
	if len(words) != len(command.Arguments) {
		return
	}
	for i, word := range words {
		if !word.Expands {
			continue
		}
		command.Arguments[i].Expands = true
		command.Arguments[i].staticPrefix = word.staticPrefix
		command.Arguments[i].holeText = word.holeText
		command.ArgvComplete = false
	}
}

// staticPOSIXWrappedAwkCall reports a chain of static wrappers that runs an
// awk call (env awk ..., sudo -u x timeout 5 awk ...) whose wrapper words are
// all static: the awk program is read word by word, as for the bare call,
// even when one of its own words expands at run time (rel-1-0-10:GAP-0859).
func staticPOSIXWrappedAwkCall(command CommandFact) bool {
	argv, arguments := command.Argv, command.Arguments
	if len(arguments) != len(argv) {
		return false
	}
	for depth := 0; depth <= maxWrapperDepth && len(argv) >= 2; depth++ {
		program := commandProgram(argv[0])
		if posixStaticWrapperSwitchKey(program) != posixStaticWrapperKey {
			return depth > 0 && awkProgramWord(argv[0])
		}
		nested, ok, uncertain := staticPOSIXWrapperArgv(argv, program)
		if !ok || uncertain {
			return false
		}
		offset := len(argv) - len(nested)
		for _, word := range arguments[:offset+1] {
			if word.Expands {
				return false
			}
		}
		argv, arguments = nested, arguments[offset:]
	}
	return false
}

// AwkCallBehindWrappers is the awk call a chain of wrappers runs, with the
// shell's word objects of its words: through the prefix wrappers
// StaticPrefixWrapperChild reads (env with assignments, sudo, timeout, nice,
// nohup, setsid, stdbuf, ionice, taskset, flock, doas ...) and through
// unbuffer, chroot, nsenter and xargs,
// whose child the path facts do not read because it runs in another context
// or gets more words. The gateway answers an awk program with a shell hole
// behind any of them at the unknown tier, as it answers the bare call
// (awkprog.DynamicReason, rel-1-0-10:GAP-0859, substrate-1:GAP-0332).
// Nothing else is read from it.
func AwkCallBehindWrappers(command CommandFact) (CommandFact, bool) {
	argv, arguments := command.Argv, command.Arguments
	if len(arguments) != len(argv) {
		return CommandFact{}, false
	}
	for depth := 0; depth <= maxWrapperDepth && len(argv) >= 2; depth++ {
		if arguments[0].Expands {
			return CommandFact{}, false
		}
		if depth > 0 && awkProgramWord(argv[0]) {
			inner := command
			inner.Executable, inner.Program = argv[0], commandProgram(argv[0])
			inner.Argv, inner.Arguments = cloneSlice(argv), cloneSlice(arguments)
			return inner, true
		}
		start := awkWrapperChild(argv, arguments)
		if start <= 0 || start >= len(argv) {
			return CommandFact{}, false
		}
		argv, arguments = argv[start:], arguments[start:]
	}
	return CommandFact{}, false
}

// awkWrapperChild is the index of the program word the wrappers at the
// head of argv run, or -1 (see AwkCallBehindWrappers).
func awkWrapperChild(argv []string, arguments []ArgumentFact) int {
	static := make([]bool, len(arguments))
	for i, argument := range arguments {
		static[i] = !argument.Expands
	}
	if run, ok := StaticPrefixWrapperChild(argv, static); ok {
		return run.Index
	}
	switch commandProgram(argv[0]) {
	case "unbuffer":
		// expect's unbuffer [-p] COMMAND.
		if len(argv) > 2 && argv[1] == "-p" {
			return 2
		}
		if len(argv) > 1 && !strings.HasPrefix(argv[1], "-") {
			return 1
		}
	case "chroot":
		if parsed := parseChrootInvocation(argv); parsed.complete && parsed.childIndex > 0 {
			return parsed.childIndex
		}
	case "nsenter":
		if parsed := parseNSEnterInvocation(argv); parsed.complete && parsed.childIndex > 0 {
			return parsed.childIndex
		}
	case "xargs":
		if start, _, known := XargsProgram(argv); known {
			return start
		}
	}
	return -1
}
