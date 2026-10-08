// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package assetfacts holds what asset_policy needs to know about an agent
// asset beyond the name a hook names: the name a skill folder declares in
// its SKILL.md, the skill folders a tool call reaches into, and how an MCP
// server is configured.
//
// A standalone gateway runs as a service account. On Linux and macOS it
// cannot read the home of the user whose hook it answers (the unit runs
// with ProtectHome), so the standalone hook, which runs as that user, reads
// these facts and sends them in Header. They are claims: the gateway uses a
// declared skill name only to match denied rules, never to admit an asset,
// and an MCP server definition only for the server the tool call names.
package assetfacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Header carries the encoded Facts on a standalone hook request.
const Header = "X-DefenseClaw-Asset-Facts"

const (
	maxHeaderBytes   = 128 << 10
	maxSkills        = 16
	maxFieldBytes    = 1024
	maxArgs          = 32
	maxManifestBytes = 64 << 10
	maxNameBytes     = 255
	maxInputStrings  = 64
	maxInputDepth    = 4
	maxProjectLevels = 16
)

// Facts are the claims one hook request carries.
type Facts struct {
	// Skills lists skill folders the request names or reaches into whose
	// SKILL.md declares another name.
	Skills []Skill `json:"skills,omitempty"`
	// MCP is the configuration of the MCP server the tool call names.
	MCP *MCPServer `json:"mcp,omitempty"`
}

// Skill is one skill folder and the name its SKILL.md frontmatter declares.
type Skill struct {
	Folder   string `json:"folder"`
	Declared string `json:"declared"`
}

// MCPServer is an MCP server definition from the agent configuration.
type MCPServer struct {
	Name      string   `json:"name"`
	URL       string   `json:"url,omitempty"`
	Command   string   `json:"command,omitempty"`
	Args      []string `json:"args,omitempty"`
	Transport string   `json:"transport,omitempty"`
}

// Encode renders facts as a header value, or "" when there is nothing to
// send. The cap fits every bounded fact set, including escaped arguments;
// otherwise an oversized MCP definition could silently lose a pinned deny.
func Encode(facts Facts) string {
	facts = bounded(facts)
	if len(facts.Skills) == 0 && facts.MCP == nil {
		return ""
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(facts) != nil {
		return ""
	}
	value := base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(raw.Bytes(), []byte{10}))
	if len(value) > maxHeaderBytes {
		return ""
	}
	return value
}

// Decode parses a header value. ok is false for an absent, oversized or
// malformed value; the fields are bounded as Encode bounds them.
func Decode(value string) (Facts, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxHeaderBytes {
		return Facts{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return Facts{}, false
	}
	var facts Facts
	if json.Unmarshal(raw, &facts) != nil {
		return Facts{}, false
	}
	facts = bounded(facts)
	return facts, len(facts.Skills) > 0 || facts.MCP != nil
}

// DeclaredFor returns the names the facts say folder declares.
func (f Facts) DeclaredFor(folder string) []string {
	var out []string
	for _, skill := range f.Skills {
		if strings.EqualFold(skill.Folder, strings.TrimSpace(folder)) {
			out = append(out, skill.Declared)
		}
	}
	return out
}

func bounded(facts Facts) Facts {
	var skills []Skill
	for _, skill := range facts.Skills {
		folder, declared := clean(skill.Folder, maxNameBytes), clean(skill.Declared, maxNameBytes)
		if folder == "" || declared == "" || len(skills) == maxSkills {
			continue
		}
		skills = append(skills, Skill{Folder: folder, Declared: declared})
	}
	facts.Skills = skills
	if server := facts.MCP; server != nil {
		out := MCPServer{
			Name: clean(server.Name, maxNameBytes), URL: clean(server.URL, maxFieldBytes),
			Command: clean(server.Command, maxFieldBytes), Transport: clean(server.Transport, 64),
		}
		for _, arg := range server.Args {
			if len(out.Args) == maxArgs {
				break
			}
			out.Args = append(out.Args, clean(arg, maxFieldBytes))
		}
		facts.MCP = nil
		if out.Name != "" && (out.URL != "" || out.Command != "") {
			facts.MCP = &out
		}
	}
	return facts
}

// clean drops a value that is not valid UTF-8, holds a control character or
// is longer than limit; it trims surrounding space.
func clean(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) > limit || !utf8.ValidString(value) {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

// DeclaredSkillName returns the name the SKILL.md in dir declares in its
// frontmatter ("name: ..."), or "" when there is no readable regular
// SKILL.md or it declares none. Only the start of the file is read.
func DeclaredSkillName(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	path := filepath.Join(dir, "SKILL.md")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes))
	if err != nil {
		return ""
	}
	return frontmatterName(string(data))
}

func frontmatterName(text string) string {
	text = strings.TrimPrefix(text, "\ufeff")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return ""
	}
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if trimmed := strings.TrimSpace(line); trimmed == "---" || trimmed == "..." {
			return ""
		}
		rest, ok := strings.CutPrefix(line, "name:")
		if !ok {
			continue
		}
		value := strings.TrimSpace(rest)
		if len(value) >= 2 && (value[0] == 0x22 || value[0] == 0x27) && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		} else if hash := strings.Index(value, " #"); hash >= 0 {
			value = strings.TrimSpace(value[:hash])
		}
		return clean(value, maxNameBytes)
	}
	return ""
}

// SkillRoots lists the folders connector loads skills from for a user with
// home and working folder cwd: the user skill folders and the project ones
// from cwd up to the repository root (or a few levels).
func SkillRoots(connector, home, cwd string) []string {
	var user, project []string
	switch strings.ToLower(strings.TrimSpace(connector)) {
	case "claudecode":
		user = []string{filepath.Join(".claude", "skills")}
		project = []string{filepath.Join(".claude", "skills")}
	case "codex":
		user = []string{filepath.Join(".codex", "skills"), filepath.Join(".agents", "skills")}
		project = []string{filepath.Join(".agents", "skills"), filepath.Join(".codex", "skills")}
	default:
		return nil
	}
	var roots []string
	if home = strings.TrimSpace(home); filepath.IsAbs(home) {
		for _, rel := range user {
			roots = append(roots, filepath.Join(home, rel))
		}
	}
	if dir := strings.TrimSpace(cwd); filepath.IsAbs(dir) {
		dir = filepath.Clean(dir)
		for level := 0; level < maxProjectLevels; level++ {
			if home != "" && filepath.Clean(home) == dir {
				break
			}
			for _, rel := range project {
				roots = append(roots, filepath.Join(dir, rel))
			}
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return roots
}

// FolderRef is a skill folder a tool call names: the folder path as far as
// it can be resolved and the folder name.
type FolderRef struct {
	Dir  string
	Name string
}

// SkillFolderRefs lists the skill folders the strings of a tool input reach
// into: every path with a "skills/<name>" pair of components, in a command
// line, a file path or a working folder. "~" and $HOME expand to home and
// a relative path resolves against cwd.
func SkillFolderRefs(input any, home, cwd string) []FolderRef {
	var values []string
	collectStrings(input, 0, &values)
	seen := map[string]bool{}
	var refs []FolderRef
	for _, value := range values {
		for _, token := range strings.FieldsFunc(value, isCommandSeparator) {
			ref, ok := skillFolderRef(token, home, cwd)
			if !ok || seen[strings.ToLower(ref.Name)] {
				continue
			}
			seen[strings.ToLower(ref.Name)] = true
			refs = append(refs, ref)
		}
	}
	return refs
}

func collectStrings(value any, depth int, out *[]string) {
	if depth > maxInputDepth || len(*out) >= maxInputStrings {
		return
	}
	switch v := value.(type) {
	case string:
		*out = append(*out, v)
	case []any:
		for _, item := range v {
			collectStrings(item, depth+1, out)
		}
	case []string:
		for _, item := range v {
			collectStrings(item, depth+1, out)
		}
	case map[string]any:
		for _, item := range v {
			collectStrings(item, depth+1, out)
		}
	}
}

func isCommandSeparator(r rune) bool {
	switch r {
	case 0x20, 0x09, 0x0a, 0x0d, 0x22, 0x27, 0x60, 0x3b, 0x7c, 0x26, 0x28, 0x29, 0x3c, 0x3e, 0x3d, 0x2c:
		return true
	}
	return false
}

func skillFolderRef(token, home, cwd string) (FolderRef, bool) {
	if !strings.ContainsAny(token, "/\\") {
		return FolderRef{}, false
	}
	path := strings.ReplaceAll(token, "\\", "/")
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
		if strings.HasPrefix(path, prefix) && home != "" {
			path = filepath.ToSlash(home) + "/" + strings.TrimPrefix(path, prefix)
			break
		}
	}
	parts := strings.Split(path, "/")
	for i := 0; i+1 < len(parts); i++ {
		if !strings.EqualFold(parts[i], "skills") {
			continue
		}
		name := parts[i+1]
		if name == "" || strings.HasPrefix(name, ".") || strings.EqualFold(name, "SKILL.md") || strings.ContainsAny(name, "*?[]{}$") {
			continue
		}
		dir := filepath.FromSlash(strings.Join(parts[:i+2], "/"))
		if !filepath.IsAbs(dir) && strings.TrimSpace(cwd) != "" {
			dir = filepath.Join(cwd, dir)
		}
		return FolderRef{Dir: filepath.Clean(dir), Name: name}, true
	}
	return FolderRef{}, false
}
