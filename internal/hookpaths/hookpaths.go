// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpaths resolves tool write targets in the invoking user's process.
package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const Header = "X-DefenseClaw-Resolved-Writes"

// CWDKey carries the hook process's cwd for a gateway whose ProtectHome
// prevents it from validating that directory locally.
const CWDKey = "\x00cwd"

// TruncatedKey means at least one static write target could not fit in the
// bounded evidence. The gateway must not treat the remaining map as complete.
const TruncatedKey = "\x00truncated"

const maxWriteTargetLinkDepth = 16

// resolveWritePath follows existing links, including a link whose final file
// does not exist yet. A shell redirect can create that final file. Resolve
// the parent separately so links in directory components are covered too.
func resolveWritePath(path string, linkDepth int) (string, bool) {
	if linkDepth > maxWriteTargetLinkDepth || !filepath.IsAbs(path) {
		return "", false
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return "", false
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		link, err := os.Readlink(path)
		if err != nil {
			return "", false
		}
		if !filepath.IsAbs(link) {
			link = filepath.Join(filepath.Dir(path), link)
		}
		return resolveWritePath(link, linkDepth+1)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, true
	}
	resolvedParent, ok := resolveWritePath(parent, linkDepth)
	if !ok {
		return "", false
	}
	return filepath.Join(resolvedParent, filepath.Base(path)), true
}

// protectedFile is the identity of the user's authorized_keys file. A hard
// link elsewhere names the same file under another path, so a target is
// compared by file identity (device and inode on Unix, volume serial and file
// index on Windows) and not by pathname alone.
type protectedFile struct {
	path    string
	info    os.FileInfo
	unknown bool
}

func newProtectedFile(home string) protectedFile {
	protected := protectedFile{path: filepath.Join(home, ".ssh", "authorized_keys")}
	info, err := os.Stat(protected.path)
	switch {
	case err == nil:
		protected.info = info
	case !os.IsNotExist(err):
		protected.unknown = true
	}
	return protected
}

// target maps a resolved write target to the protected path when both name
// the same file. When the protected file cannot be identified, a multiply
// linked target may be an alias of it and is reported as unresolvable.
func (p protectedFile) target(resolved string) (string, bool) {
	if p.info == nil && !p.unknown {
		return resolved, true
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return resolved, true
	}
	if p.info != nil {
		if os.SameFile(info, p.info) {
			return p.path, true
		}
		return resolved, true
	}
	if linkCount(resolved, info) > 1 {
		return "", false
	}
	return resolved, true
}

// Resolve returns a bounded, header-safe map from absolute write operands to
// their filesystem targets. An empty value means resolution was attempted but
// could not be trusted. A regular file maps to itself, unless it is a hard
// link to the user's authorized_keys file.
func Resolve(payload []byte) string {
	var envelope map[string]json.RawMessage
	if len(payload) > 1<<20 || json.Unmarshal(payload, &envelope) != nil {
		return ""
	}
	field := func(names ...string) json.RawMessage {
		for _, name := range names {
			if value := envelope[name]; len(value) != 0 {
				return value
			}
		}
		return nil
	}
	var tool string
	_ = json.Unmarshal(field("tool_name", "toolName"), &tool)
	args := field("tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments")
	if len(args) == 0 {
		return ""
	}
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	input := actionfacts.Input{Tool: tool, Args: args, CWD: cwd, ActiveHome: home}
	facts := actionfacts.Analyze(input)
	// A connector can name the shell text "cmd" while ActionFacts requires
	// its canonical command field. Resolve that exact string as a shell too.
	var toolArgs map[string]json.RawMessage
	if json.Unmarshal(args, &toolArgs) == nil {
		for _, key := range []string{"command", "cmd"} {
			var command string
			if json.Unmarshal(toolArgs[key], &command) == nil && command != "" {
				fallback := input
				fallback.Tool, fallback.Args, fallback.Command = "Bash", nil, command
				facts.Paths = append(facts.Paths, actionfacts.Analyze(fallback).Paths...)
				break
			}
		}
	}
	targets := map[string]string{CWDKey: cwd}
	protected := newProtectedFile(home)
	writeCount := 0
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		path := candidate.Resolved
		if path == "" {
			path = candidate.Normalized
		}
		if path == "" || strings.ContainsAny(path, "*?[]$`") || strings.HasPrefix(path, "~") {
			continue
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(cwd, path)
		}
		path = filepath.Clean(path)
		if len(path) > 1024 {
			targets[TruncatedKey] = "1"
			continue
		}
		if _, present := targets[path]; !present && writeCount >= 32 {
			targets[TruncatedKey] = "1"
			continue
		}
		if _, present := targets[path]; !present {
			writeCount++
		}
		resolved, ok := resolveWritePath(path, 0)
		if ok {
			resolved, ok = protected.target(resolved)
		}
		if !ok {
			targets[path] = ""
		} else {
			targets[path] = resolved
		}
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		return ""
	}
	if len(encoded) > 6<<10 {
		// Preserve a non-authoritative header even when short paths fill
		// the byte budget before the target-count budget is reached.
		targets = map[string]string{CWDKey: cwd, TruncatedKey: "1"}
		encoded, err = json.Marshal(targets)
		if err != nil || len(encoded) > 6<<10 {
			return ""
		}
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// Decode accepts only the bounded client evidence format.
func Decode(value string) (map[string]string, bool) {
	if value == "" || len(value) > 8<<10 {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	var targets map[string]string
	if json.Unmarshal(data, &targets) != nil || len(targets) > 34 ||
		(targets[TruncatedKey] != "" && targets[TruncatedKey] != "1") {
		return nil, false
	}
	return targets, true
}
