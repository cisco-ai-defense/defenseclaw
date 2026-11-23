// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// ActionMentionsNoWriteRole reports a command the target scan holds as a
// protected-target only because of words in statements that read a protected
// file (sha256sum KEYS, ls -l KEYS, test -e KEYS) while other statements of
// the same command do other work. The decision itself stays protected-target:
// a compound that reads the keys file beside other work is not the plain read
// the whole-command rule allows. The caller decides what that is worth; an
// action that only reads the file is no write of it (rel-1-0-10:GAP-0018).
//
// The excused scan reads a statement as a reader only under the call-level
// GAP-0570 rules (actionCallKeepsMentions: $_ carries the name a reader read
// into another statement, ls KEYS; echo x >> $_, rel-1-0-10:GAP-0860,
// GAP-0643) and when the reading call runs a system program (GAP-0715).
func ActionMentionsNoWriteRole(command, cwd, home string, dialect actionfacts.Dialect, facts map[string]string) bool {
	if ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) != "protected-target" {
		return false
	}
	memo := NewTargetMemo()
	memo.excuseNonWrites = true
	return memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) == ""
}

// stdinNameCopiers copy the files whose names their standard input lists
// (cpio -o, cpio -p): a reader that lists a protected file into them hands
// over the file, not text (rel-1-0-10:GAP-0843).
var stdinNameCopiers = []string{"cpio", "bsdcpio"}

// ActionMentionsNoKnownWrite is ActionMentionsNoWriteRole for the unknown
// tier (S7 lead ruling 2026-11-15, rel-1-0-10:GAP-0843): a command that names
// a protected file only in statements that read it, where another statement
// runs a program the scan has no model of (wc -l KEYS && $TOOL > /tmp/r), a
// reader stage hands its output on (cat KEYS | python3 -c "$CODE"), or a
// reader writes its output to a file the call names (cat KEYS > /tmp/k.bak).
// No word of it is a write target that reaches the file; a program the scan
// cannot read could write it as well without the mention, so the mention is
// no proof. $_ and a rebound reader name still hand the name on and keep the
// block (actionCallKeepsMentions). A POSIX call only: any fixed word of it,
// other than a protected key file it reads, in the home's .ssh or state
// folder (cat KEYS > ~/.ssh/k.new, cd ~/.ssh, $TOOL > ~/.ssh/rc.d/x) keeps
// the verdict rel gives it. A pipeline that hands the protected name to
// cpio, pax pass-through or xargs cp also keeps the block: those programs
// copy the files their input names (S7 lead ruling 2026-11-19).
func ActionMentionsNoKnownWrite(command, cwd, home string, dialect actionfacts.Dialect, facts map[string]string) bool {
	if dialect != "" && dialect != actionfacts.DialectPOSIX ||
		ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) != "protected-target" {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	keys := ProtectedAuthorizedKeysPaths(home)
	if pipelineCopiesStdinNames(file, cwd, home, keys) {
		return false
	}
	near := false
	syntax.Walk(file, func(node syntax.Node) bool {
		word, isWord := node.(*syntax.Word)
		if near || !isWord {
			return !near
		}
		value, static := StaticWord(word, home)
		if static && slices.Contains(stdinNameCopiers, strings.ToLower(filepath.Base(value))) {
			near = true
			return false
		}
		if !static || !strings.ContainsAny(value, "/.") && !strings.Contains(cwd, ".ssh") && !strings.Contains(cwd, ".defenseclaw") {
			return true
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(cwd, value)
		}
		if !slices.Contains(keys, filepath.Clean(value)) && !actionPathOutsideProtectedFolders(value, cwd, home) {
			near = true
		}
		return !near
	})
	if near {
		return false
	}
	memo := NewTargetMemo()
	memo.excuseNonWrites, memo.excuseUnknownRoles = true, true
	return memo.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, facts) == ""
}

// pipelineCopiesStdinNames identifies a protected name handed through a
// pipeline to a copier that reads file names from stdin. A plain ls stage
// must print that file name; unrelated or transformed text is no proof.
func pipelineCopiesStdinNames(file *syntax.File, cwd, home string, keys []string) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		pipe, ok := node.(*syntax.BinaryCmd)
		if !ok || pipe.Op != syntax.Pipe && pipe.Op != syntax.PipeAll {
			return true
		}
		consumer, ok := pipe.Y.Cmd.(*syntax.CallExpr)
		if !ok || !stdinNameCopier(consumer, home) {
			return true
		}
		producer, ok := pipe.X.Cmd.(*syntax.CallExpr)
		if !ok || len(producer.Args) != 2 {
			return true
		}
		program, programKnown := StaticWord(producer.Args[0], home)
		value, valueKnown := StaticWord(producer.Args[1], home)
		if !programKnown || !valueKnown || program != "ls" {
			return true
		}
		if !filepath.IsAbs(value) {
			value = filepath.Join(cwd, value)
		}
		found = slices.Contains(keys, filepath.Clean(value))
		return !found
	})
	return found
}

// stdinNameCopier is the one role property the mention reader needs. An
// xargs child is a copier only when the handed names are sources and its
// destination is separate; pax pass-through needs its destination alone.
func stdinNameCopier(call *syntax.CallExpr, home string) bool {
	if len(call.Args) == 0 {
		return false
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		var static bool
		words[i], static = StaticWord(arg, home)
		if !static {
			return false
		}
	}
	switch strings.ToLower(filepath.Base(words[0])) {
	case "pax":
		if len(words) == 2 && words[1] == "-w" {
			return true
		}
		return len(words) == 3 && (words[1] == "-rw" || words[1] == "-wr") && !strings.HasPrefix(words[2], "-")
	case "xargs":
		start, replace, known := actionfacts.XargsProgram(words)
		if !known || start >= len(words) || strings.ToLower(filepath.Base(words[start])) != "cp" {
			return false
		}
		for _, option := range words[1:start] {
			if strings.HasPrefix(option, "--arg-file") ||
				strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "--") && strings.Contains(option[1:], "a") {
				return false // names may come from an argument file, not the pipe
			}
		}
		handed := actionfacts.XargsHandedEntries(words[start:], replace)
		return !handed.MayChange && len(handed.Outputs) > 0
	}
	return false
}
