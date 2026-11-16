// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

// Claude Cowork runs its agent loop as the Claude Code build Claude Desktop
// bundles (<data>/claude-code/<version>/ under each of its data folders,
// internal/claudedesktop: ~/Library/Application Support/Claude or Claude-3p
// on macOS, %APPDATA%\Claude, %LOCALAPPDATA%\Claude-Data\claude_<id> or
// %LOCALAPPDATA%\Claude-3p on Windows), on the device, as the user. Its hooks are ordinary Claude Code hooks, so a Cowork call
// reaches the claudecode route. The engine tells its hooks that they run for
// Cowork through these environment variables (measured on Claude Desktop
// 4.4212.0 with engine 2.1.309; none of them is documented as an interface).
const (
	// CoworkEnvFlag is "1" in a Cowork session.
	CoworkEnvFlag = "CLAUDE_CODE_IS_COWORK"
	// CoworkEnvSessionID is the Cowork session the call belongs to.
	CoworkEnvSessionID = "CLAUDE_CODE_SESSION_ID"
	// CoworkEnvWorkspaceHostPaths names the folders the user connected to
	// the session, as host paths.
	CoworkEnvWorkspaceHostPaths = "CLAUDE_CODE_WORKSPACE_HOST_PATHS"
)

// CoworkHeader carries the Cowork context of a claudecode hook call (a
// CoworkContext as JSON). The hook sends it only when CoworkEnvFlag is set
// and the engine that runs the hook is Claude Desktop's bundled build. The
// user can set both, so it is attribution for the audit, never a policy
// input or an identity: the user identity still comes from the operating
// system.
const CoworkHeader = "X-DefenseClaw-Cowork"

// Bounds of the Cowork context. A value outside them is dropped, never
// truncated into a different value.
const (
	maxCoworkHeaderBytes        = 8 << 10
	maxCoworkSessionIDBytes     = 128
	maxCoworkWorkspacePaths     = 16
	maxCoworkWorkspacePathBytes = 1024
)

// CoworkContext is what a Cowork hook call says about its session.
type CoworkContext struct {
	SessionID string `json:"session_id,omitempty"`
	// WorkspaceHostPaths are the folders connected to the session. They are
	// filesystem paths (path redaction class).
	WorkspaceHostPaths []string `json:"workspace_host_paths,omitempty"`
	// WorkspaceHostPathsBase64 is the raw CoworkEnvWorkspaceHostPaths
	// value, base64 encoded, that the shell hook (claude-code-hook.sh) sends
	// because it cannot parse the value: ParseCoworkHeader turns it into
	// WorkspaceHostPaths.
	WorkspaceHostPathsBase64 string `json:"workspace_host_paths_b64,omitempty"`
}

// CoworkSessionFromEnv reports whether getenv describes a Cowork session
// and returns its context. Only the exact value "1" marks one.
func CoworkSessionFromEnv(getenv func(string) string) (CoworkContext, bool) {
	if getenv == nil || strings.TrimSpace(getenv(CoworkEnvFlag)) != "1" {
		return CoworkContext{}, false
	}
	return CoworkContext{
		SessionID:          coworkSessionID(getenv(CoworkEnvSessionID)),
		WorkspaceHostPaths: ParseCoworkWorkspaceHostPaths(getenv(CoworkEnvWorkspaceHostPaths)),
	}, true
}

// HeaderValue is the CoworkHeader value: compact JSON, which escapes every
// control character.
func (c CoworkContext) HeaderValue() string {
	c = c.normalized()
	body, err := json.Marshal(c)
	if err != nil || len(body) > maxCoworkHeaderBytes {
		return `{}`
	}
	return string(body)
}

// ParseCoworkHeader decodes a CoworkHeader value. A value that is not one
// JSON object of the known fields within the bounds is rejected; the fields
// are normalized as on the hook side.
func ParseCoworkHeader(value string) (CoworkContext, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCoworkHeaderBytes {
		return CoworkContext{}, false
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	decoder.DisallowUnknownFields()
	var out CoworkContext
	if err := decoder.Decode(&out); err != nil || decoder.More() {
		return CoworkContext{}, false
	}
	return out.normalized(), true
}

func (c CoworkContext) normalized() CoworkContext {
	c.SessionID = coworkSessionID(c.SessionID)
	if len(c.WorkspaceHostPaths) == 0 && c.WorkspaceHostPathsBase64 != "" {
		if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(c.WorkspaceHostPathsBase64)); err == nil {
			c.WorkspaceHostPaths = ParseCoworkWorkspaceHostPaths(string(raw))
		}
	}
	c.WorkspaceHostPaths = boundedCoworkPaths(c.WorkspaceHostPaths)
	c.WorkspaceHostPathsBase64 = ""
	return c
}

// ParseCoworkWorkspaceHostPaths reads CoworkEnvWorkspaceHostPaths. Its
// format is not documented: a JSON array of strings is read as such,
// anything else as a list separated by newlines, or by ";" or ":" when every
// element is then an absolute path, or else as one path. Relative, oversized
// and control-character paths are dropped.
func ParseCoworkWorkspaceHostPaths(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxCoworkHeaderBytes {
		return nil
	}
	if strings.HasPrefix(raw, "[") {
		var list []string
		decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
		if decoder.Decode(&list) != nil || decoder.More() {
			return nil
		}
		return boundedCoworkPaths(list)
	}
	if strings.ContainsAny(raw, "\r\n") {
		return boundedCoworkPaths(strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' }))
	}
	for _, separator := range []string{";", ":"} {
		parts := strings.Split(raw, separator)
		if len(parts) < 2 {
			continue
		}
		all := true
		for _, part := range parts {
			if !coworkAbsolutePath(strings.TrimSpace(part)) {
				all = false
				break
			}
		}
		if all {
			return boundedCoworkPaths(parts)
		}
	}
	return boundedCoworkPaths([]string{raw})
}

func boundedCoworkPaths(paths []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, path := range paths {
		if len(out) == maxCoworkWorkspacePaths {
			break
		}
		path = strings.TrimSpace(path)
		if path == "" || len(path) > maxCoworkWorkspacePathBytes || !utf8.ValidString(path) ||
			strings.IndexFunc(path, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 ||
			!coworkAbsolutePath(path) || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// coworkAbsolutePath accepts a POSIX absolute path, a Windows drive path
// (C:\ or C:/) and a UNC path, whatever the gateway's OS.
func coworkAbsolutePath(path string) bool {
	switch {
	case strings.HasPrefix(path, `\\`):
		return len(path) > 2
	case strings.HasPrefix(path, "/"):
		return true
	case len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/'):
		c := path[0] | 0x20
		return c >= 'a' && c <= 'z'
	}
	return false
}

// coworkSessionID keeps a session ID made only of [A-Za-z0-9._:-] within
// the bound, else "".
func coworkSessionID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCoworkSessionIDBytes {
		return ""
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':' {
			continue
		}
		return ""
	}
	return value
}
