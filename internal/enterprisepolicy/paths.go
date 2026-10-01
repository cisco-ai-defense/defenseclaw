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
	"fmt"
	"path"
	"strings"
)

// DefenseClawDropInName is the file DefenseClaw owns in vendor drop-in
// directories. The numeric prefix sorts it late so it merges after most
// administrator files; conflicts with later files are detected explicitly.
const DefenseClawDropInName = "90-defenseclaw.json"

// PublicPolicyFileName is the world-readable foreign-hook guard summary.
const PublicPolicyFileName = "machine-policy.json"

// machinePath returns a vendor machine path for goos. Unix paths are joined
// under opts.Root; Windows paths are built from the trusted roots.
func machinePath(opts Options, unix, darwin string, windows func(programFiles, programData string) string) (string, error) {
	switch opts.goos() {
	case "windows":
		if windows == nil {
			return "", ErrUnsupported
		}
		return windows(strings.TrimRight(opts.WindowsProgramFiles, `\`), strings.TrimRight(opts.WindowsProgramData, `\`)), nil
	case "darwin":
		if darwin == "" {
			return "", ErrUnsupported
		}
		return rooted(opts, darwin), nil
	case "linux":
		if unix == "" {
			return "", ErrUnsupported
		}
		return rooted(opts, unix), nil
	default:
		return "", fmt.Errorf("%w on %s", ErrUnsupported, opts.goos())
	}
}

func rooted(opts Options, abs string) string {
	if opts.Root == "" {
		return abs
	}
	return path.Join(opts.Root, abs)
}

// CodexRequirementsPath is Codex's machine requirements file.
func CodexRequirementsPath(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/codex/requirements.toml",
		"/etc/codex/requirements.toml",
		func(_, programData string) string { return programData + `\OpenAI\Codex\requirements.toml` })
}

// ClaudeManagedDir is Claude Code's file-based managed settings directory.
func ClaudeManagedDir(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/claude-code",
		"/Library/Application Support/ClaudeCode",
		func(programFiles, _ string) string { return programFiles + `\ClaudeCode` })
}

// CursorEnterpriseHooksPath is Cursor's system-wide enterprise hooks file.
func CursorEnterpriseHooksPath(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/cursor/hooks.json",
		"/Library/Application Support/Cursor/hooks.json",
		func(_, programData string) string { return programData + `\Cursor\hooks.json` })
}

// CopilotPolicyDir is GitHub Copilot CLI's machine policy hook directory.
func CopilotPolicyDir(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/github-copilot/policy.d",
		"/etc/github-copilot/policy.d",
		func(_, programData string) string { return programData + `\GitHub\Copilot\policy.d` })
}

// joinFor joins a child onto a directory in the target OS's syntax.
func joinFor(opts Options, dir, child string) string {
	if opts.goos() == "windows" {
		return strings.TrimRight(dir, `\`) + `\` + child
	}
	return path.Join(dir, child)
}

func dirFor(opts Options, file string) string {
	if opts.goos() == "windows" {
		if index := strings.LastIndex(file, `\`); index > 2 {
			return file[:index]
		}
		return file
	}
	return path.Dir(file)
}

// hookBinaryDir is the directory holding the admin hook binary (Codex's
// managed_dir must contain the managed hook command).
func hookBinaryDir(opts Options) string {
	return dirFor(opts, opts.HookBinary)
}
