// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// copilotManagedShellCommand recognizes a plain script invocation, optionally
// through a shell interpreter. It never evaluates wrapper text or reads a
// relative executable chosen by the project. Unproven wrappers stay in place
// and make closed verification refuse the registration.
func copilotManagedShellCommand(command, current string) bool {
	word, rest, ok := posixHookCommandSplit(strings.TrimSpace(command))
	if !ok {
		return false
	}
	switch word {
	case "bash", "sh", "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh":
		word, rest, ok = posixHookCommandSplit(strings.TrimSpace(rest))
		if word == "--" && ok {
			word, rest, ok = posixHookCommandSplit(strings.TrimSpace(rest))
		}
	}
	if !ok || !filepath.IsAbs(word) || filepath.Clean(word) != word || strings.ContainsAny(word, "\x00\r\n") {
		return false
	}
	if rest = strings.TrimSpace(rest); rest != "" {
		flag, tail, valid := posixHookCommandSplit(rest)
		event, suffix, eventOK := posixHookCommandSplit(strings.TrimSpace(tail))
		if !valid || flag != "--event" || !eventOK || strings.TrimSpace(suffix) != "" || !ValidCopilotHookEvent(event) {
			return false
		}
	}
	if word == current {
		return true
	}
	body, err := safefile.ReadRegularFileBounded(word, 1<<20)
	if err != nil {
		return false
	}
	lines := bytes.SplitN(body, []byte("\n"), 4)
	marked := false
	for _, line := range lines[:min(3, len(lines))] {
		version, found := strings.CutPrefix(strings.TrimSuffix(string(line), "\r"), "# defenseclaw-managed-hook v")
		if found && version != "" && strings.Trim(version, "0123456789") == "" {
			marked = true
		}
	}
	return marked && (bytes.Contains(body, []byte(`DEFENSECLAW_HOOK_CONNECTOR="copilot"`)) ||
		bytes.Contains(body, []byte("/api/v1/copilot/hook")))
}
