// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

// An approval in allowed_hooks is a digest the block message shows. It
// must cover what will run, not only the text that names it: the same
// handler text in another repository can point at a different script, and
// a plugin directory's name says nothing about its code. The digest
// therefore includes the content of every file a handler's command names
// and every file of a plugin directory. A handler whose references cannot
// all be bound (an unresolvable variable, a file past the size bound, a
// special or unreadable file, a command past the word bound) cannot be
// approved at all. Words are resolved against the directories below, never
// through PATH: a program a bare word finds through PATH (bash, node), and
// a file a command reads on its own (a Makefile for make), is bound by name
// only, as foreign-hook-guard.mdx documents.

const (
	// guardReferencedTokenLimit bounds the distinct words one handler
	// resolves for its digest. Past it the handler cannot be approved: a
	// later word could name a file the digest does not cover.
	guardReferencedTokenLimit = 256
	// guardReferencedDirLimit bounds the directories a handler's command
	// changes into ("cd dir"); later relative words also resolve there.
	guardReferencedDirLimit = 8
	// guardScanReferenceLimit bounds the referenced paths checked across
	// one scan.
	guardScanReferenceLimit = 8192
	// guardReferencedFileLimit is the largest referenced file hashed; a
	// handler naming a larger one cannot be approved.
	guardReferencedFileLimit = 64 << 20
	// guardScanHashLimit bounds the bytes hashed across one scan.
	guardScanHashLimit = 256 << 20
	// guardLinkHopLimit bounds the symbolic links followed while binding
	// one referenced path.
	guardLinkHopLimit = 40
	// guardPluginTreeLimit and guardPluginTreeDepth bound a plugin
	// directory's walk; a larger tree cannot be verified (approve its
	// files instead).
	guardPluginTreeLimit = 512
	guardPluginTreeDepth = 16
)

// unapprovableReason starts the Reason of a finding whose digest cannot
// cover what it runs. Unlike an unverifiable file ("cannot verify"), the
// entry itself is readable, so the cleanup still removes a user-level one.
const unapprovableReason = "cannot be approved: "

// commandToken is one word of a hook command. A path-like word (a path
// separator, a leading "~" or ".") names a file by its form. Any other word
// of a field the agent executes may still name a file in the directory the
// hook runs from (bash check.sh, node x.js, pwsh -File x.ps1): it is
// resolved too, and bound when something exists there.
type commandToken struct {
	text     string
	pathLike bool
}

// commandTokens splits a command string into words. Shell operators split
// words; quote characters are removed; "--flag=path" and "VAR=path"
// contribute their value. Options (-File, --quiet) and URLs other than
// file:// are skipped.
func commandTokens(command string) []commandToken {
	fields := strings.FieldsFunc(command, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(";|&()<>`", r)
	})
	unquote := strings.NewReplacer(`"`, "", `'`, "")
	var out []commandToken
	for _, field := range fields {
		// Shell quote removal: "$CLAUDE_PROJECT_DIR"/hooks/x.sh names
		// $CLAUDE_PROJECT_DIR/hooks/x.sh.
		field = unquote.Replace(field)
		if i := strings.LastIndex(field, "="); i >= 0 && !strings.ContainsAny(field[:i], `/\`) {
			field = field[i+1:]
		}
		if field == "" {
			continue
		}
		if strings.Contains(field, "://") && !strings.HasPrefix(field, "file://") {
			continue
		}
		pathLike := strings.ContainsAny(field, `/\`) || strings.HasPrefix(field, "~") || strings.HasPrefix(field, ".")
		if !pathLike && strings.HasPrefix(field, "-") {
			continue
		}
		out = append(out, commandToken{text: field, pathLike: pathLike})
	}
	return out
}

// changesDirectory reports whether word is a shell or PowerShell command
// whose argument becomes the directory later relative words run from.
func changesDirectory(word string) bool {
	switch strings.ToLower(word) {
	case "cd", "chdir", "pushd", "set-location", "push-location", "sl":
		return true
	}
	return false
}

// projectDirVariable reports whether name is an agent variable that holds
// the project root (CLAUDE_PROJECT_DIR, CURSOR_PROJECT_DIR, ...).
func projectDirVariable(name string) bool {
	name = strings.ToUpper(name)
	return strings.HasSuffix(name, "PROJECT_DIR") || strings.HasSuffix(name, "PROJECT_ROOT") || strings.HasSuffix(name, "WORKSPACE_ROOT") ||
		// A plugin's hooks resolve against its root (CLAUDE_PLUGIN_ROOT),
		// which is the base of a plugin hook source.
		strings.HasSuffix(name, "PLUGIN_ROOT")
}

// variableName reports whether name is an environment variable name.
func variableName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// expandTokenVariable replaces a leading ~, $VAR, ${VAR}, %VAR% or
// $env:VAR that names the home or the project root. ok is false for any
// other variable (and for ~user, ~+ and the like): the token cannot be
// resolved. A "%" that does not open a %VAR% reference is literal.
func expandTokenVariable(token string, source hookSource) (string, bool) {
	name, rest := "", ""
	switch {
	case token == "~" || strings.HasPrefix(token, "~/") || strings.HasPrefix(token, `~\`):
		if source.home == "" {
			return "", false
		}
		return source.home + token[1:], true
	case strings.HasPrefix(token, "~"):
		// ~user, ~+ (the working directory), ~- ...
		return "", false
	case strings.HasPrefix(token, "${"):
		end := strings.Index(token, "}")
		if end < 0 {
			return "", false
		}
		name, rest = token[2:end], token[end+1:]
	case strings.HasPrefix(token, "$env:"):
		end := strings.IndexAny(token[5:], `/\`)
		if end < 0 {
			name = token[5:]
		} else {
			name, rest = token[5:5+end], token[5+end:]
		}
	case strings.HasPrefix(token, "$"):
		end := strings.IndexAny(token[1:], `/\`)
		if end < 0 {
			name = token[1:]
		} else {
			name, rest = token[1:1+end], token[1+end:]
		}
	case strings.HasPrefix(token, "%"):
		end := strings.Index(token[1:], "%")
		if end < 0 || !variableName(token[1:1+end]) {
			return token, true
		}
		name, rest = token[1:1+end], token[2+end:]
	default:
		return token, true
	}
	switch upper := strings.ToUpper(name); {
	case upper == "HOME" || upper == "USERPROFILE":
		if source.home == "" {
			return "", false
		}
		return source.home + rest, true
	case projectDirVariable(upper):
		if source.base == "" {
			return "", false
		}
		return source.base + rest, true
	}
	return "", false
}

// referencedDir is a directory besides the project root and the config
// file's directory that relative words resolve against: the agent's working
// directory, a handler's cwd field, or a directory its command changes into.
type referencedDir struct {
	role string
	path string
}

type referencedCandidate struct {
	role string
	path string
	// always binds the candidate even when nothing is there (a path-like
	// word under the project root or the config directory); any other
	// candidate is bound only when something exists at it, so the digest
	// does not depend on where the agent was started.
	always bool
}

// resolveToken lists the files a word may name: an absolute path as is; a
// relative one against the project root (or home), the config file's
// directory and each of dirs, since agents differ in which one they run
// hooks from. ok is false when a path-like word uses a variable that cannot
// be resolved. Any other word naming a variable is taken literally when the
// variable is unknown ($f in f=$(jq ...); prettier "$f" is data).
func resolveToken(token commandToken, source hookSource, dirs []referencedDir) ([]referencedCandidate, bool) {
	text := strings.TrimPrefix(token.text, "file://")
	expanded, ok := expandTokenVariable(text, source)
	switch {
	case ok:
		text = expanded
	case token.pathLike:
		return nil, false
	}
	text = filepath.FromSlash(text)
	if filepath.IsAbs(text) {
		return []referencedCandidate{{role: "absolute", path: filepath.Clean(text), always: token.pathLike}}, true
	}
	var out []referencedCandidate
	add := func(role, dir string, always bool) {
		if dir == "" {
			return
		}
		path := filepath.Join(dir, text)
		for _, existing := range out {
			if samePath(existing.path, path) {
				return
			}
		}
		out = append(out, referencedCandidate{role: role, path: path, always: always && token.pathLike})
	}
	add("base", source.base, true)
	if source.path != "" {
		add("config", filepath.Dir(source.path), true)
	}
	for _, dir := range dirs {
		add(dir.role, dir.path, false)
	}
	return out, true
}

// handlerValue is one string a handler carries. exec marks the fields an
// agent executes (command, bash, powershell, args) and environment values
// (BASH_ENV names a script bash sources); only their plain words are
// resolved as file names.
type handlerValue struct {
	text string
	exec bool
}

// handlerExecKeys are the handler fields whose words the agent runs.
var handlerExecKeys = map[string]bool{"command": true, "bash": true, "powershell": true, "args": true, "env": true}

// handlerValueDepth bounds how deep handlerValues looks into a handler.
const handlerValueDepth = 8

// handlerValues returns every string a handler carries at any depth (args
// lists, env blocks, OS-specific overrides); any of them may name a file.
func handlerValues(handler any) []handlerValue {
	var out []handlerValue
	var walk func(value any, exec bool, depth int)
	walkFields := func(fields map[string]any, exec bool, depth int) {
		keys := make([]string, 0, len(fields))
		for key := range fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			walk(fields[key], exec || handlerExecKeys[key], depth+1)
		}
	}
	walk = func(value any, exec bool, depth int) {
		if depth > handlerValueDepth {
			return
		}
		switch v := value.(type) {
		case string:
			out = append(out, handlerValue{text: v, exec: exec})
		case []any:
			for _, item := range v {
				walk(item, exec, depth+1)
			}
		case []string:
			for _, item := range v {
				out = append(out, handlerValue{text: item, exec: exec})
			}
		case *object:
			walkFields(v.values, exec, depth)
		case map[string]any:
			walkFields(v, exec, depth)
		}
	}
	walk(handler, false, 0)
	return out
}

// handlerDirs lists the directories a handler's relative words may resolve
// against besides the project root and the config file's directory: the
// agent's working directories (some agents run hooks from the session's
// directory) and the handler's own cwd field (Copilot). problem is set when
// the cwd cannot be resolved.
func (s *guardScan) handlerDirs(handler any, source hookSource) ([]referencedDir, string) {
	var dirs []referencedDir
	for _, dir := range s.req.workingDirs() {
		dirs = append(dirs, referencedDir{role: "cwd", path: dir})
	}
	cwd := strings.TrimSpace(stringField(handler, "cwd"))
	if cwd == "" {
		return dirs, ""
	}
	candidates, ok := resolveToken(commandToken{text: cwd, pathLike: true}, source, nil)
	if !ok {
		return dirs, fmt.Sprintf("its cwd %s uses a variable DefenseClaw cannot resolve", truncate(cwd, 80))
	}
	for _, candidate := range candidates {
		dirs = append(dirs, referencedDir{role: "cwd-field:" + candidate.role, path: candidate.path})
	}
	return dirs, ""
}

// referencedFiles describes every file the values may name, for a
// handler's digest. problem is non-empty when a reference cannot be bound;
// such a finding cannot be approved.
func (s *guardScan) referencedFiles(values []handlerValue, source hookSource, dirs []referencedDir) ([]any, string) {
	out := []any{}
	problem := ""
	note := func(why string) {
		if problem == "" {
			problem = why
		}
	}
	seen := map[string]bool{}
	words := map[string]bool{}
	for _, value := range values {
		// A "cd dir" applies to the rest of its own command.
		local := append([]referencedDir(nil), dirs...)
		changed := 0
		changeDir := false
		for _, token := range commandTokens(value.text) {
			next := value.exec && changesDirectory(token.text)
			if !token.pathLike && !value.exec {
				changeDir = next
				continue
			}
			if !words[token.text] {
				words[token.text] = true
				if len(words) > guardReferencedTokenLimit {
					note(fmt.Sprintf("its command has more than %d words to check", guardReferencedTokenLimit))
					return append(out, map[string]any{"token": "", "state": "truncated"}), problem
				}
			}
			if err := s.check(); err != nil {
				note(err.Error())
				return append(out, map[string]any{"token": "", "state": "truncated"}), problem
			}
			candidates, ok := resolveToken(token, source, local)
			if !ok {
				key := token.text + "\x00unresolved"
				if !seen[key] {
					seen[key] = true
					out = append(out, map[string]any{"token": token.text, "state": "unresolved"})
				}
				note(fmt.Sprintf("it names %s, which uses a variable DefenseClaw cannot resolve", truncate(token.text, 80)))
				changeDir = next
				continue
			}
			var entered []referencedDir
			for _, candidate := range candidates {
				key := token.text + "\x00" + candidate.role + "\x00" + candidate.path
				if seen[key] {
					continue
				}
				seen[key] = true
				s.references++
				if s.references > guardScanReferenceLimit {
					s.exceeded = fmt.Errorf("the hook scan checked more than %d referenced paths", guardScanReferenceLimit)
					note(s.exceeded.Error())
					return append(out, map[string]any{"token": "", "state": "truncated"}), problem
				}
				state := s.fileState(candidate.path)
				if state == "absent" && !candidate.always {
					continue
				}
				out = append(out, map[string]any{"token": token.text, "base": candidate.role, "state": state})
				if why := unboundState(state); why != "" {
					note(fmt.Sprintf("it names %s, which %s", truncate(token.text, 80), why))
				}
				if changeDir && state == "directory" {
					entered = append(entered, referencedDir{role: "cd:" + candidate.role + ":" + token.text, path: candidate.path})
				}
			}
			if len(entered) > 0 {
				changed++
				if changed > guardReferencedDirLimit {
					note(fmt.Sprintf("its command changes directory more than %d times", guardReferencedDirLimit))
					return append(out, map[string]any{"token": "", "state": "truncated"}), problem
				}
				local = append(local, entered...)
			}
			changeDir = next
		}
	}
	return out, problem
}

// unboundState explains a referenced-file state the digest cannot bind
// ("" for content, a system file, a directory, or nothing there).
func unboundState(state string) string {
	switch {
	case state == "unreadable":
		return "cannot be read"
	case strings.HasPrefix(state, "special:"):
		return "is not a regular file"
	case strings.HasPrefix(state, "large:"):
		return fmt.Sprintf("is larger than %d bytes", guardReferencedFileLimit)
	}
	return ""
}

// fileState binds one referenced path: its content hash, or what else is
// there. An administrator-owned file (root-owned and not group or world
// writable) is bound by kind only, so an OS update of an interpreter does
// not invalidate approvals; a user cannot change it. A user can point a
// symbolic link of their own at another administrator-owned file, though,
// so when the path crosses such a link (the file itself or a folder above
// it) the link targets are bound as well. Where users may hard-link files
// they do not own (macOS), a root-owned file named from a folder a user
// controls is bound by content (systemBoundFile).
func (s *guardScan) fileState(path string) string {
	info, err := os.Stat(path)
	switch {
	case err != nil && (errors.Is(err, fs.ErrNotExist) || guardPathCannotExist(err)):
		return "absent"
	case err != nil:
		return "unreadable"
	case info.IsDir():
		return "directory"
	case !info.Mode().IsRegular():
		return "special:" + info.Mode().Type().String()
	case systemBoundFile(path, info):
		if targets := userLinkTargets(path); len(targets) > 0 {
			return "system:links:" + strings.Join(targets, "\x00")
		}
		return "system"
	case info.Size() > guardReferencedFileLimit:
		return fmt.Sprintf("large:%d", info.Size())
	}
	sum, err := s.hashFile(path, info)
	if err != nil {
		return "unreadable"
	}
	return "sha256:" + sum
}

// userLinkTargets resolves path one name at a time, as the OS does, and
// returns the target of each symbolic link it crosses that is not
// administrator-owned, in order. A link that cannot be read, or past
// guardLinkHopLimit links, ends the list with "unresolved".
func userLinkTargets(path string) []string {
	if !filepath.IsAbs(path) {
		return nil
	}
	var targets []string
	volume := filepath.VolumeName(path)
	dest := volume + string(filepath.Separator)
	rest := strings.Split(filepath.ToSlash(path[len(volume):]), "/")
	for hops := 0; len(rest) > 0; {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			dest = filepath.Dir(dest)
			continue
		}
		next := filepath.Join(dest, name)
		info, err := os.Lstat(next)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			dest = next
			continue
		}
		hops++
		target, err := os.Readlink(next)
		if err != nil || hops > guardLinkHopLimit {
			return append(targets, "unresolved")
		}
		if !adminOwnedLink(info) {
			targets = append(targets, target)
		}
		if filepath.IsAbs(target) {
			volume = filepath.VolumeName(target)
			dest = volume + string(filepath.Separator)
			target = target[len(volume):]
		}
		rest = append(strings.Split(filepath.ToSlash(target), "/"), rest...)
	}
	return targets
}

// hashFile hashes a regular file (following links, as the agent would)
// without blocking, within the scan's hashing budget.
func (s *guardScan) hashFile(path string, info os.FileInfo) (string, error) {
	if s.hashed+info.Size() > guardScanHashLimit {
		return "", errors.New("hash budget exhausted")
	}
	file, err := openGuardFileFollow(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", errors.New("changed while hashed")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, guardReferencedFileLimit+1))
	s.hashed += n
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// treeDigest binds a plugin directory to the names, kinds and contents of
// everything in it. A link, a special file, or a tree past the bounds
// cannot be verified.
func (s *guardScan) treeDigest(root string) (string, error) {
	var lines []string
	count := 0
	var walk func(dir, rel string, depth int) error
	walk = func(dir, rel string, depth int) error {
		if depth > guardPluginTreeDepth {
			return guardLimit("%s is nested more than %d directories deep", root, guardPluginTreeDepth)
		}
		entries, _, err := s.readDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			count++
			if count > guardPluginTreeLimit {
				return guardLimit("%s holds more than %d entries", root, guardPluginTreeLimit)
			}
			name := rel + "/" + entry.Name()
			path := filepath.Join(dir, entry.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			switch {
			case info.Mode()&os.ModeSymlink != 0:
				return fmt.Errorf("%s is a symbolic link", path)
			case info.IsDir():
				lines = append(lines, "D "+name)
				if err := walk(path, name, depth+1); err != nil {
					return err
				}
			case info.Mode().IsRegular():
				if info.Size() > guardReferencedFileLimit {
					return guardLimit("%s is larger than %d bytes", path, guardReferencedFileLimit)
				}
				sum, err := s.hashFile(path, info)
				if err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				lines = append(lines, "F "+name+" "+sum)
			default:
				return fmt.Errorf("%s is not a regular file (%s)", path, info.Mode().Type())
			}
		}
		return nil
	}
	if err := walk(root, "", 0); err != nil {
		return "", err
	}
	sort.Strings(lines)
	return sha256Hex([]byte("plugin-tree\n" + strings.Join(lines, "\n"))), nil
}
