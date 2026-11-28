// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// ShellFileWrite is one file a POSIX shell call writes with text the
// reading knows (ShellDocumentFileWrites).
type ShellFileWrite struct {
	// Path is the file as the call names it.
	Path string
	// Text is what the call writes to it.
	Text string
	// Expanded reports text the shell expands before it writes it (an
	// unquoted here-document with parameters): the text is as written, not
	// what lands in the file.
	Expanded bool
}

// ShellDocumentFileWrites returns the files a POSIX shell command writes
// with text the reading knows, the same reading the run-time shell twin
// gives a later statement that runs one (writtenScripts): a here-document,
// a here-string, a static echo or printf, or the known output of the stage
// before it, sent to the file by a standard-output redirect or a tee operand
// (cat > x.py <<'EOF', tee x.py <<'EOF', echo TEXT > x.py). The content
// scanners read such a write as they read a write tool's content
// (rel-1-0-10:GAP-1640). A command the shell grammar does not parse, or a
// write whose target or text is made at run time, gives nothing.
//
// The writes are bounded: one text written to several names with the same
// extension is one write (the content scanners read a file by its extension
// and text; a literal and an expanded write of one text stay two), a write
// to a device (/dev/null, /dev/stderr, /dev/fd/N) is not
// a file, and the texts together hold at most MaxCommandBytes. Past that
// budget the writes already read are kept and the rest is not added. Size
// alone never makes the view partial: the distinct texts of one command
// are the command's own text, which the analysis bounds at the same size.
func ShellDocumentFileWrites(command string) (writes []ShellFileWrite) {
	if command == "" || !strings.ContainsAny(command, ">") && !strings.Contains(command, "tee") {
		return nil
	}
	defer func() {
		if recover() != nil {
			writes = nil
		}
	}()
	file, parsed := shellparse.Parse(command)
	if !parsed {
		return nil
	}
	inputs, _ := pipelineStageInputs(file)
	written := writtenScripts(file, inputs)
	if len(written) == 0 {
		return nil
	}
	expanded := shellTextExpanded(file, inputs)
	asWritten := heredocBodiesAsWritten(command, file)
	targets := make([]string, 0, len(written))
	for target := range written {
		if !strings.HasPrefix(target, "/dev/") {
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)
	type seenKey struct {
		ext, text string
		expanded  bool
	}
	seen := map[seenKey]bool{}
	budget := MaxCommandBytes
	for _, target := range targets {
		for _, write := range written[target] {
			add := ShellFileWrite{Path: target}
			switch body, raw := asWritten[write.end]; {
			case write.known:
				add.Text, add.Expanded = write.text, expanded[write.end]
			case raw:
				// The shell expands the parameters of the document
				// before it writes it: the text as written is what the
				// scanners can read, a partial view.
				add.Text, add.Expanded = body, true
			default:
				continue
			}
			key := seenKey{ext: path.Ext(target), text: add.Text, expanded: add.Expanded}
			if seen[key] {
				continue
			}
			if len(add.Text) > budget {
				return writes
			}
			seen[key] = true
			budget -= len(add.Text)
			writes = append(writes, add)
		}
	}
	return writes
}

// shellTextExpanded marks the statements whose written text the shell
// expands first: an unquoted here-document with parameters of its own or
// in the stage before it.
// The statements are keyed by their end offset, as writtenScripts keys its
// writes.
func shellTextExpanded(file *syntax.File, inputs map[*syntax.CallExpr]stageText) map[int]bool {
	out := map[int]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && inputs[call].parameters {
			out[int(stmt.End().Offset())] = true
		}
		for _, redir := range stmt.Redirs {
			if heredocHasParameters(redir) {
				out[int(stmt.End().Offset())] = true
			}
		}
		return true
	})
	return out
}

// heredocBodiesAsWritten is the body of the one unquoted here-document of a
// cat statement (keyed by the statement's end offset, as writtenScripts keys
// its writes) whose body expands parameters only: no command substitution,
// arithmetic or process substitution runs while the shell writes it. The
// text is the body as written.
func heredocBodiesAsWritten(command string, file *syntax.File) map[int]string {
	out := map[int]string{}
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || stdinRedirectCount(stmt) != 1 {
			return true
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		if program, static := simpleStaticWord(call.Args[0], nil); !static || wrapperProgramName(program) != "cat" {
			return true
		}
		for _, redir := range stmt.Redirs {
			if (redir.Op != syntax.Hdoc && redir.Op != syntax.DashHdoc) || redir.N != nil && redir.N.Value != "0" ||
				redir.Hdoc == nil || posixHeredocDelimiterQuoted(redir.Word) {
				continue
			}
			plain := true
			syntax.Walk(redir.Hdoc, func(node syntax.Node) bool {
				switch node.(type) {
				case *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
					plain = false
				}
				return plain
			})
			start, end := int(redir.Hdoc.Pos().Offset()), int(redir.Hdoc.End().Offset())
			if plain && start >= 0 && end >= start && end <= len(command) {
				out[int(stmt.End().Offset())] = command[start:end]
			}
		}
		return true
	})
	return out
}
