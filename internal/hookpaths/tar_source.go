// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// tarKnownValues retains only unconditional assignments before this extraction
// and one-item loop variables. Values from conditional branches cannot prove
// the archive bytes a later call will read.
func tarKnownValues(file *syntax.File, extraction *syntax.CallExpr, cwd, home string) actionValues {
	values := actionValues{"HOME": home, "PWD": cwd}
	if file == nil || extraction == nil {
		return values
	}
	var visit func(*syntax.Stmt)
	visit = func(stmt *syntax.Stmt) {
		if stmt == nil || stmt.Pos().Offset() >= extraction.Pos().Offset() {
			return
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
			visit(pair.X)
			visit(pair.Y)
			return
		}
		if loop, ok := stmt.Cmd.(*syntax.ForClause); ok &&
			extraction.Pos().Offset() >= loop.Pos().Offset() && extraction.End().Offset() <= loop.End().Offset() {
			if wordLoop, ok := loop.Loop.(*syntax.WordIter); ok && len(wordLoop.Items) == 1 && wordLoop.Name != nil {
				if value, fixed := StaticWord(wordLoop.Items[0], home); fixed {
					values[wordLoop.Name.Value] = value
				}
			}
			return
		}
		if stmt.End().Offset() > extraction.Pos().Offset() {
			return
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 {
			actionUpdateValues(stmt, values, cwd, home)
		}
	}
	for _, stmt := range file.Stmts {
		visit(stmt)
	}
	return values
}

// resolvedTarSources follows the bytes named by an extraction through static
// shell producers and earlier writes. Temporary joins are bounded and removed
// by the caller. A missing or dynamic source supplies no positive evidence.
func resolvedTarSources(file *syntax.File, extraction *syntax.CallExpr, cwd, home string) ([]string, func()) {
	if file == nil || extraction == nil || !filepath.IsAbs(cwd) {
		return nil, func() {}
	}
	values := tarKnownValues(file, extraction, cwd, home)
	word := func(w *syntax.Word) (string, bool) {
		if w == nil {
			return "", false
		}
		if v, ok := StaticWord(w, home); ok {
			return v, true
		}
		return actionWordValue(w, values, cwd, home)
	}
	args := func(c *syntax.CallExpr) (string, []string, []bool) {
		if c == nil || len(c.Args) == 0 {
			return "", nil, nil
		}
		var words []string
		var static []bool
		for _, w := range c.Args {
			v, ok := word(w)
			words = append(words, v)
			static = append(static, ok)
		}
		if !static[0] {
			return "", nil, nil
		}
		if index, wrapped := plainWrappedChild(words, static); wrapped {
			words, static = words[index:], static[index:]
		}
		return programBase(words[0]), words[1:], static[1:]
	}
	// Each entry is a sequence of disk sources. Following the map at use time
	// permits a copy, link, transform and rename chain to reach its original bytes.
	writes := map[string][]string{}
	normalize := func(p string) string { return OperandPath(p, cwd) }
	var parts func(string, int) []string
	parts = func(p string, depth int) []string {
		if depth > 24 || p == "" || p == "-" {
			return nil
		}
		p = normalize(p)
		if found, ok := writes[p]; ok {
			var out []string
			for _, q := range found {
				next := parts(q, depth+1)
				if len(next) == 0 || len(out)+len(next) > 256 {
					return nil
				}
				out = append(out, next...)
			}
			return out
		}
		return []string{p}
	}
	addWrite := func(dst string, src []string, appendMode bool) {
		if dst == "" || len(src) == 0 {
			return
		}
		dst = normalize(dst)
		if appendMode {
			writes[dst] = append(writes[dst], src...)
		} else {
			writes[dst] = src
		}
	}
	// Redirections execute before their statement's command. They are also used
	// by producer commands in pipes and process substitutions.
	redirInput := func(c *syntax.CallExpr) []string {
		var out []string
		syntax.Walk(file, func(n syntax.Node) bool {
			st, ok := n.(*syntax.Stmt)
			if !ok || st.Cmd != syntax.Command(c) {
				return true
			}
			for _, r := range st.Redirs {
				if r.Op == syntax.RdrIn {
					if v, ok := word(r.Word); ok {
						out = append(out, v)
					}
				}
			}
			return false
		})
		return out
	}
	var producer func(*syntax.CallExpr) []string
	producer = func(c *syntax.CallExpr) []string {
		p, a, s := args(c)
		var out []string
		switch p {
		case "cat", "gzip", "zcat", "xz", "xzcat", "zstd", "zstdcat", "bzip2", "bzcat", "dd", "tee":
			for i, v := range a {
				if !s[i] {
					continue
				}
				if p == "dd" {
					if strings.HasPrefix(v, "if=") {
						out = append(out, strings.TrimPrefix(v, "if="))
					}
					continue
				}
				if v != "-" && !strings.HasPrefix(v, "-") {
					out = append(out, v)
				}
			}
			out = append(out, redirInput(c)...)
		}
		return out
	}
	var earlier []*syntax.CallExpr
	var collectPrior func(*syntax.Stmt)
	collectPrior = func(stmt *syntax.Stmt) {
		if stmt == nil || stmt.Pos().Offset() >= extraction.Pos().Offset() {
			return
		}
		if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt {
			collectPrior(pair.X)
			collectPrior(pair.Y)
			return
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && call != extraction && stmt.End().Offset() <= extraction.Pos().Offset() {
			earlier = append(earlier, call)
		}
	}
	for _, stmt := range file.Stmts {
		collectPrior(stmt)
	}
	// AST walk order is textual for these calls. A process substitution on the
	// extraction statement is included because it runs before tar opens input.
	for _, c := range earlier {
		p, a, s := args(c)
		if p == "" {
			continue
		}
		var source, dest string
		switch p {
		case "cp", "gcp", "ln", "gln", "mv", "gmv", "install", "rsync", "ditto":
			if len(a) >= 2 && s[len(a)-2] && s[len(a)-1] {
				source, dest = a[len(a)-2], a[len(a)-1]
			}
		case "dd":
			for i, v := range a {
				if !s[i] {
					continue
				}
				if strings.HasPrefix(v, "if=") {
					source = strings.TrimPrefix(v, "if=")
				}
				if strings.HasPrefix(v, "of=") {
					dest = strings.TrimPrefix(v, "of=")
				}
			}
		case "gzip", "xz", "zstd", "bzip2":
			if len(a) > 0 {
				for i, v := range a {
					if s[i] && v != "-" && !strings.HasPrefix(v, "-") {
						source = v
						break
					}
				}
			}
			if source == "" {
				input := redirInput(c)
				if len(input) > 0 {
					source = input[0]
				}
			}
			if source != "" {
				suffix := map[string]string{"gzip": "gz", "xz": "xz", "zstd": "zst", "bzip2": "bz2"}[p]
				dest = source + "." + suffix
			}
		}
		if source != "" && dest != "" {
			addWrite(dest, []string{source}, false)
		}
		// A redirect can name a copy or a concatenation of known input files.
		syntax.Walk(file, func(n syntax.Node) bool {
			st, ok := n.(*syntax.Stmt)
			if !ok || st.Cmd != syntax.Command(c) {
				return true
			}
			sources := producer(c)
			if p == "tee" {
				for i, v := range a {
					if s[i] && v != "-" && !strings.HasPrefix(v, "-") {
						addWrite(v, sources, false)
					}
				}
			}
			for _, r := range st.Redirs {
				if r.Op != syntax.RdrOut && r.Op != syntax.AppOut && r.Op != syntax.RdrClob {
					continue
				}
				if v, ok := word(r.Word); ok {
					addWrite(v, sources, r.Op == syntax.AppOut)
				}
			}
			return false
		})
	}
	p, a, s := args(extraction)
	if p != "tar" && p != "bsdtar" && p != "gtar" {
		return nil, func() {}
	}
	sources := tarArchiveWords(a, s)
	stdin := len(sources) == 0
	for _, src := range sources {
		if src == "-" || src == "/dev/stdin" || src == "/dev/fd/0" {
			stdin = true
		}
	}
	if stdin {
		sources = append(sources, redirInput(extraction)...)
		syntax.Walk(file, func(n syntax.Node) bool {
			pipe, ok := n.(*syntax.BinaryCmd)
			if !ok || pipe.Op != syntax.Pipe || extraction.Pos().Offset() < pipe.Y.Pos().Offset() || extraction.End().Offset() > pipe.Y.End().Offset() {
				return true
			}
			syntax.Walk(pipe.X, func(n syntax.Node) bool {
				if c, ok := n.(*syntax.CallExpr); ok {
					input := producer(c)
					if len(input) > 1 {
						virtual := filepath.Join(cwd, ".dc-pipe-archive-"+strconv.Itoa(int(c.Pos().Offset())))
						writes[virtual] = input
						sources = append(sources, virtual)
					} else {
						sources = append(sources, input...)
					}
				}
				return true
			})
			return false
		})
	}
	// Process substitutions may stand in a -f argument or an input redirect.
	syntax.Walk(extraction, func(n syntax.Node) bool {
		if sub, ok := n.(*syntax.ProcSubst); ok {
			for _, st := range sub.Stmts {
				syntax.Walk(st, func(n syntax.Node) bool {
					if c, ok := n.(*syntax.CallExpr); ok {
						sources = append(sources, producer(c)...)
					}
					return true
				})
			}
		}
		return true
	})
	syntax.Walk(file, func(n syntax.Node) bool {
		st, ok := n.(*syntax.Stmt)
		if !ok || st.Cmd != syntax.Command(extraction) {
			return true
		}
		for _, redir := range st.Redirs {
			if redir.Word == nil {
				continue
			}
			syntax.Walk(redir.Word, func(n syntax.Node) bool {
				if sub, ok := n.(*syntax.ProcSubst); ok {
					for _, s := range sub.Stmts {
						syntax.Walk(s, func(n syntax.Node) bool {
							if c, ok := n.(*syntax.CallExpr); ok {
								sources = append(sources, producer(c)...)
							}
							return true
						})
					}
				}
				return true
			})
		}
		return false
	})
	var result, temps []string
	for _, src := range sources {
		if src == "" || src == "-" || src == "/dev/stdin" || src == "/dev/fd/0" {
			continue
		}
		resolved := parts(src, 0)
		if len(resolved) == 0 {
			continue
		}
		if len(resolved) == 1 {
			result = append(result, resolved[0])
			continue
		}
		tmp, err := os.CreateTemp("", "dc-tar-source-*")
		if err != nil {
			continue
		}
		valid := true
		var total int64
		for _, path := range resolved {
			f, err := os.Open(path)
			if err != nil {
				valid = false
				break
			}
			n, err := io.CopyN(tmp, f, maxTarPlainBytes-total+1)
			f.Close()
			total += n
			if err != nil && err != io.EOF || total > maxTarPlainBytes {
				valid = false
				break
			}
		}
		tmp.Close()
		if !valid {
			os.Remove(tmp.Name())
			continue
		}
		temps = append(temps, tmp.Name())
		result = append(result, tmp.Name())
	}
	return result, func() {
		for _, p := range temps {
			os.Remove(p)
		}
	}
}

// unfollowedTarProducer keeps the conservative archive reading when shell
// syntax supplies tar's stdin but no source bytes could be resolved. A plain
// missing file operand without a producer remains Possible.
func unfollowedTarProducer(file *syntax.File, extraction *syntax.CallExpr) bool {
	if file == nil || extraction == nil {
		return false
	}
	// A static remote URL has no local bytes for the gateway to name or
	// read. Keep that genuinely unverifiable input Possible in balanced.
	remoteOnly := false
	syntax.Walk(file, func(n syntax.Node) bool {
		pipe, ok := n.(*syntax.BinaryCmd)
		if !ok || pipe.Op != syntax.Pipe || extraction.Pos().Offset() < pipe.Y.Pos().Offset() || extraction.End().Offset() > pipe.Y.End().Offset() {
			return true
		}
		syntax.Walk(pipe.X, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			for _, arg := range call.Args[1:] {
				value, fixed := StaticWord(arg, "")
				if fixed && (strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "ftp://")) {
					remoteOnly = true
				}
			}
			return true
		})
		return false
	})
	if remoteOnly {
		return false
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		if pipe, ok := n.(*syntax.BinaryCmd); ok && pipe.Op == syntax.Pipe &&
			extraction.Pos().Offset() >= pipe.Y.Pos().Offset() && extraction.End().Offset() <= pipe.Y.End().Offset() {
			found = true
			return false
		}
		if st, ok := n.(*syntax.Stmt); ok && st.Cmd == syntax.Command(extraction) {
			for _, r := range st.Redirs {
				if r.Op == syntax.RdrIn {
					found = true
					return false
				}
			}
		}
		return true
	})
	syntax.Walk(extraction, func(n syntax.Node) bool {
		if _, ok := n.(*syntax.ProcSubst); ok {
			found = true
		}
		return !found
	})
	return found
}

// unknownPriorArchiveWrite identifies an earlier output redirect to a missing
// archive operand. Its source is not proved, so the earlier base reading is
// retained rather than treating the missing on-disk file as ordinary.
func unknownPriorArchiveWrite(file *syntax.File, extraction *syntax.CallExpr, cwd, home string, sources []string) bool {
	if file == nil || extraction == nil {
		return false
	}
	targets := map[string]bool{}
	for _, source := range sources {
		if source != "" {
			targets[OperandPath(source, cwd)] = true
		}
	}
	if len(targets) == 0 {
		return false
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		st, ok := n.(*syntax.Stmt)
		if !ok || st.Pos().Offset() >= extraction.Pos().Offset() {
			return true
		}
		for _, r := range st.Redirs {
			if r.Word == nil || r.Op != syntax.RdrOut && r.Op != syntax.AppOut && r.Op != syntax.RdrClob {
				continue
			}
			if value, ok := StaticWord(r.Word, home); ok && targets[OperandPath(value, cwd)] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}
