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

// Resolve returns a bounded, header-safe map from absolute write operands to
// their filesystem targets. An empty value means resolution was attempted but
// could not be trusted. A regular file maps to itself.
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
		_, statErr := os.Lstat(path)
		resolved, err := filepath.EvalSymlinks(path)
		if os.IsNotExist(err) && os.IsNotExist(statErr) {
			// A new regular file has no leaf to resolve; its existing parent
			// still may be a symlink into a protected directory.
			parent, parentErr := filepath.EvalSymlinks(filepath.Dir(path))
			if parentErr == nil {
				resolved, err = filepath.Join(parent, filepath.Base(path)), nil
			}
		}
		if err != nil || statErr != nil && !os.IsNotExist(statErr) {
			targets[path] = ""
		} else {
			targets[path] = filepath.Clean(resolved)
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
