// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const maxIndirectSourceBytes = 16 << 10

// readIndirectSource reads only one regular file under cwd (the volume root,
// for readIndirectSourceAnywhere).
// These reads occur only for an explicit source, make, or AWK -f command.
func readIndirectSource(name, cwd string) (string, bool) {
	if !filepath.IsAbs(cwd) || name == "" || strings.ContainsAny(name, "\x00\r\n") {
		return "", false
	}
	relative := name
	if filepath.IsAbs(name) {
		prefix := filepath.Clean(cwd)
		if !os.IsPathSeparator(prefix[len(prefix)-1]) {
			prefix += string(filepath.Separator)
		}
		if !strings.HasPrefix(name, prefix) {
			return "", false
		}
		relative = strings.TrimPrefix(name, prefix)
	}
	root, err := pathOpenRoot(cwd)
	if err != nil {
		return "", false
	}
	defer root.Close()
	if pathBodyUnanswered(cwd, relative) {
		return "", false
	}
	before, err := root.Lstat(relative)
	if err != nil && strings.ContainsAny(relative, `/\`) && !errors.Is(err, fs.ErrNotExist) {
		return readIndirectSourceThroughLinks(cwd, relative)
	}
	noteBodyLinkLimit(err)
	return readIndirectSourceIn(root, relative, before, err)
}

// readIndirectSourceAnywhere reads the regular file a script operand names as
// the system opens it, wherever it lies: a name relative to cwd is joined to
// it unchanged (a .. climbs the physical parent, as the shell does), and the
// read starts at the root of the volume the path is on, so a script beside
// the project or in the user home is read as one in the project is. It is
// the same bounded read (a regular file of at most maxIndirectSourceBytes; a
// link past the system bound or a share that does not answer is an unread
// body).
func readIndirectSourceAnywhere(name, cwd string) (string, bool) {
	if !filepath.IsAbs(cwd) || name == "" || strings.ContainsAny(name, "\x00\r\n") {
		return "", false
	}
	if runtime.GOOS == "windows" {
		name = actionMSYSDrivePath(name)
	}
	path := name
	if !filepath.IsAbs(path) {
		path = joinPathElement(cwd, name)
	}
	return readIndirectSource(path, filepath.VolumeName(path)+string(filepath.Separator))
}

// readIndirectSourceIn reads relative below root once its Lstat answered.
func readIndirectSourceIn(root *os.Root, relative string, before os.FileInfo, err error) (string, bool) {
	if err != nil || !before.Mode().IsRegular() || before.Size() > maxIndirectSourceBytes {
		return "", false
	}
	file, err := root.Open(relative)
	if err != nil {
		noteBodyLinkLimit(err)
		return "", false
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Size() > maxIndirectSourceBytes {
		return "", false
	}
	content, err := io.ReadAll(io.LimitReader(file, maxIndirectSourceBytes+1))
	if err != nil || len(content) > maxIndirectSourceBytes {
		return "", false
	}
	return string(content), true
}

// readIndirectSourceThroughLinks reads a script whose name passes folder links
// that the Root below the working folder will not follow: os.Root follows at
// most eight links, while the system opens as many as it opens
// (SystemLinkLimit), and the command runs the script it opens. Declining a
// script behind nine links left it unread without a record, judged as one
// that writes nothing whatever it wrote (rel-1-0-9:GAP-0950). The system
// answers first: a path it refuses for passing too many links is an unread
// body (noteBodyLinkLimit), as for a working folder behind them. A path it
// opens is read only if the file lies below the physical working folder, as
// every body is; one that leaves the project stays unread, as a name with ..
// does. The file is taken from a Root on the physical folder and checked
// against the file opened.
func readIndirectSourceThroughLinks(cwd, relative string) (string, bool) {
	joined := joinPathElement(cwd, relative)
	if _, err := pathStat(joined); err != nil {
		noteBodyLinkLimit(err)
		return "", false
	}
	physical, err := pathEvalSymlinks(joined)
	if err != nil {
		return "", false
	}
	physicalCWD, err := pathEvalSymlinks(cwd)
	if err != nil {
		return "", false
	}
	below, err := filepath.Rel(physicalCWD, physical)
	if err != nil || below == "." || below == ".." || strings.HasPrefix(below, ".."+string(filepath.Separator)) {
		return "", false
	}
	root, err := pathOpenRoot(physicalCWD)
	if err != nil {
		return "", false
	}
	defer root.Close()
	before, err := root.Lstat(below)
	return readIndirectSourceIn(root, below, before, err)
}

func literalSourceFileOperands(words []string, cwd, home string, depth int) []string {
	if depth >= 4 || len(words) != 2 {
		return nil
	}
	content, ok := readActionScript(words[1], cwd)
	if !ok {
		return nil
	}
	return literalSimpleScriptOperands(content, cwd, home, depth+1)
}

func literalMakeRecipeOperands(words []string, cwd, home string, depth int) []string {
	if depth >= 4 || len(words) != 2 || words[1] == "" ||
		strings.HasPrefix(words[1], "-") || strings.ContainsAny(words[1], "/\\$*:;=\x00\r\n") {
		return nil
	}
	// GNU make prefers GNUmakefile over Makefile; a different file may give
	// the same target a different recipe.
	if _, err := pathLstat(filepath.Join(cwd, "GNUmakefile")); err == nil {
		return nil
	}
	content, ok := readIndirectSource("Makefile", cwd)
	if !ok {
		return nil
	}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "include ") || strings.HasPrefix(trimmed, "-include ") ||
			strings.HasPrefix(trimmed, "sinclude ") || strings.HasPrefix(trimmed, "define ") ||
			strings.HasPrefix(trimmed, "ifeq ") || strings.HasPrefix(trimmed, "ifneq ") ||
			strings.HasPrefix(trimmed, "ifdef ") || strings.HasPrefix(trimmed, "ifndef ") ||
			strings.HasPrefix(trimmed, ".ONESHELL:") {
			return nil
		}
	}
	lines := strings.Split(content, "\n")
	phony, recipe, matches := false, "", 0
	for i, line := range lines {
		if strings.HasPrefix(line, ".PHONY:") {
			for _, item := range strings.Fields(strings.TrimPrefix(line, ".PHONY:")) {
				phony = phony || item == words[1]
			}
		}
		if line != words[1]+":" {
			continue
		}
		matches++
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "\t") {
			recipe = strings.TrimSpace(strings.TrimLeft(lines[i+1], "\t@-+"))
			if i+2 < len(lines) && strings.HasPrefix(lines[i+2], "\t") {
				return nil
			}
		}
	}
	if matches != 1 || recipe == "" || strings.ContainsAny(recipe, "$\\\r\n") {
		return nil
	}
	if _, err := pathLstat(filepath.Join(cwd, words[1])); err == nil && !phony {
		return nil
	}
	return literalSimpleScriptOperands(recipe, cwd, home, depth+1)
}

func literalGitSSHCommandOperands(words []string, cwd, home string, depth int) []string {
	if depth >= 4 || len(words) != 5 || words[1] != "-c" || words[3] != "ls-remote" ||
		!strings.HasPrefix(words[2], "core.sshCommand=") {
		return nil
	}
	remote := words[4]
	if remote == "origin" {
		config, ok := readIndirectSource(".git/config", cwd)
		if !ok {
			return nil
		}
		remote = localGitRemoteURL(config, "origin")
	}
	if !literalSSHRemote(remote) {
		return nil
	}
	sshCommand := strings.TrimPrefix(words[2], "core.sshCommand=")
	if sshCommand == "" || len(sshCommand) > maxIndirectSourceBytes {
		return nil
	}
	redirects, parsed, dynamic := ShellWriteOperands(sshCommand, cwd, home)
	if !parsed || dynamic {
		return nil
	}
	return append(redirects, literalWriteOperandsDepth(sshCommand, cwd, home, depth+1)...)
}

func localGitRemoteURL(config, name string) string {
	section, remote := "", ""
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			if strings.HasPrefix(strings.ToLower(line), "[url ") ||
				strings.EqualFold(line, "[include]") || strings.HasPrefix(strings.ToLower(line), "[includeif ") {
				return ""
			}
			section = ""
			if line == `[remote "`+name+`"]` {
				section = name
			}
			continue
		}
		if section != name {
			continue
		}
		key, value, present := strings.Cut(line, "=")
		if present && strings.TrimSpace(key) == "url" {
			if remote != "" {
				return ""
			}
			remote = strings.TrimSpace(value)
		}
	}
	return remote
}

func literalSSHRemote(remote string) bool {
	if remote == "" || strings.ContainsAny(remote, "\x00\r\n\t ") {
		return false
	}
	if strings.HasPrefix(remote, "ssh://") {
		return len(remote) > len("ssh://")
	}
	if strings.Contains(remote, "://") {
		return false
	}
	userHost, _, found := strings.Cut(remote, ":")
	return found && strings.Contains(userHost, "@") && !strings.Contains(userHost, "/")
}

func literalSimpleScriptOperands(script, cwd, home string, depth int) []string {
	if depth > 4 {
		return nil
	}
	file, ok := parseShell(script)
	if !ok || len(file.Stmts) != 1 || file.Stmts[0].Background || file.Stmts[0].Negated {
		return nil
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 {
		return nil
	}
	redirects, parsed, dynamic := ShellWriteOperands(script, cwd, home)
	if !parsed || dynamic {
		return nil
	}
	return append(redirects, literalWriteOperandsDepth(script, cwd, home, depth)...)
}
