// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

const (
	maxPathFacts = 32
	maxLinkHops  = 40
	maxWalkDepth = 4
)

// pathKeys are tool_input keys whose string value is a file-system path in
// the wave-1 connectors' tools (Claude Code Read/Write/Edit/NotebookEdit/
// Glob/Grep, Codex and others' file tools).
var pathKeys = map[string]bool{
	"file_path": true, "filePath": true, "path": true, "notebook_path": true,
	"target_file": true, "filename": true, "old_path": true, "new_path": true,
	"source": true, "destination": true,
}

// readTools are tools whose PreToolUse target the gateway may want to see:
// the kit attaches the file it is about to read.
var readTools = map[string]map[string]bool{
	"claudecode": {"Read": true, "NotebookRead": true},
}

// payloadView is the part of a hook payload the kit inspects.
type payloadView struct {
	Event     string          `json:"hook_event_name"`
	CWD       string          `json:"cwd"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// CollectFacts inspects the event and returns the facts to attach, or nil
// when there are none. It never fails: an unreadable path becomes a fact
// with an Error, and an unparseable payload yields no facts.
func CollectFacts(connector, event string, payload []byte, attachCap int64) *Facts {
	var view payloadView
	if json.Unmarshal(payload, &view) != nil {
		return nil
	}
	if event == "" {
		event = view.Event
	}
	cwd := filepath.Clean(view.CWD)
	if !filepath.IsAbs(cwd) {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}
	f := &Facts{}
	budget := attachCap

	var input any
	if len(view.ToolInput) > 0 {
		_ = json.Unmarshal(view.ToolInput, &input)
	}
	seen := map[string]bool{}
	add := func(field, p string) {
		p = strings.TrimSpace(p)
		if p == "" || seen[field+"\x00"+p] {
			return
		}
		seen[field+"\x00"+p] = true
		if len(f.Paths) >= maxPathFacts {
			f.Truncated = true
			return
		}
		f.Paths = append(f.Paths, inspectPath(field, p, cwd))
	}
	walkPaths("tool_input", input, 0, add)

	isPre := event == "PreToolUse" || event == "preToolUse"
	if isPre && readTools[connector][view.ToolName] {
		for _, pf := range f.Paths {
			// A read of a skill's files runs the skill folder pass in this
			// call (one rule for every skill: the folder's content digest,
			// GAP-0039/0164), so a folder that arrived since the last pass is
			// decided before its files reach the model.
			if pf.Type == "file" && (pf.Field == "tool_input.file_path" || pf.Field == "tool_input.notebook_path") &&
				(inSkillRoot(pf.Abs) || inSkillRoot(pf.Resolved)) {
				f.readsSkill = true
			}
		}
	}
	// The repository's MCP config and server files: at SessionStart (the
	// agent starts the servers) and before every call of an MCP tool, which
	// the gateway refuses when the scan blocks its server (E20, GAP-0185).
	if event == "SessionStart" || event == "sessionStart" || (isPre && strings.HasPrefix(view.ToolName, "mcp__")) {
		budget = attachMCP(f, connector, cwd, budget)
	}
	_ = budget
	if len(f.Paths) == 0 && len(f.Files) == 0 && !f.Truncated && !f.readsSkill {
		return nil
	}
	return f
}

// walkPaths calls add for every path-valued key and for every file an
// apply_patch body names, depth-first in key order.
func walkPaths(field string, v any, depth int, add func(field, path string)) {
	if depth > maxWalkDepth {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := field + "." + k
			if s, ok := t[k].(string); ok {
				if pathKeys[k] {
					add(child, s)
				}
				for _, p := range patchPaths(s) {
					add(child, p)
				}
				continue
			}
			walkPaths(child, t[k], depth+1, add)
		}
	case []any:
		for i, e := range t {
			child := fmt.Sprintf("%s[%d]", field, i)
			if s, ok := e.(string); ok {
				for _, p := range patchPaths(s) {
					add(child, p)
				}
				continue
			}
			walkPaths(child, e, depth+1, add)
		}
	}
}

// patchPaths returns the files an apply_patch body adds, updates, deletes or
// moves to (the Codex patch format).
func patchPaths(s string) []string {
	if !strings.Contains(s, "*** Begin Patch") {
		return nil
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if strings.HasPrefix(line, prefix) {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(line, prefix)))
			}
		}
	}
	return out
}

func inspectPath(field, p, cwd string) PathFact {
	pf := PathFact{Field: field, Path: p, UID: -1, GID: -1}
	abs := p
	if strings.HasPrefix(abs, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			abs = filepath.Join(home, abs[2:])
		}
	}
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	pf.Abs = filepath.Clean(abs)
	cur := pf.Abs
	for i := 0; i < maxLinkHops; i++ {
		info, err := os.Lstat(cur)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			break
		}
		target, err := os.Readlink(cur)
		if err != nil {
			break
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		target = filepath.Clean(target)
		pf.LinkChain = append(pf.LinkChain, target)
		cur = target
	}
	if resolved, err := filepath.EvalSymlinks(pf.Abs); err == nil {
		pf.Resolved = resolved
	}
	info, err := os.Stat(pf.Abs)
	switch {
	case err == nil:
		pf.Type = "other"
		switch {
		case info.Mode().IsRegular():
			pf.Type = "file"
		case info.IsDir():
			pf.Type = "dir"
		}
		pf.Mode = fmt.Sprintf("%04o", uint32(info.Mode().Perm()))
		pf.UID, pf.GID, pf.NLink = fileOwner(info)
		pf.Size = info.Size()
	case os.IsNotExist(err):
		if l, lerr := os.Lstat(pf.Abs); lerr == nil && l.Mode()&os.ModeSymlink != 0 {
			pf.Type = "symlink"
		} else {
			pf.Type = "missing"
		}
	default:
		pf.Type = "other"
		pf.Error = err.Error()
	}
	target := pf.Resolved
	if target == "" {
		target = pf.Abs
	}
	pf.InsideCWD = within(target, cwd)
	return pf
}

// inSkillRoot reports a path inside a .claude, .codex or .agents skill
// folder.
func inSkillRoot(p string) bool {
	p = filepath.ToSlash(p)
	if p == "" {
		return false
	}
	for _, root := range []string{"/.claude/skills/", "/.codex/skills/", "/.agents/skills/"} {
		if strings.Contains(p, root) {
			return true
		}
	}
	// A Claude Code plugin's skills (skillRoots watches them too).
	if i := strings.Index(p, "/.claude/plugins/"); i >= 0 && strings.Contains(p[i:], "/skills/") {
		return true
	}
	return false
}

func within(p, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}

// attach adds up to budget bytes of the regular file at path and returns the
// budget left.
func attach(f *Facts, role, path, resolved string, budget int64) int64 {
	for _, a := range f.Files {
		if a.Path == path {
			return budget
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return budget
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return budget
	}
	a := AttachedFile{Role: role, Path: path, Resolved: resolved, Size: info.Size()}
	h := sha256.New()
	limit := budget
	if limit < 0 {
		limit = 0
	}
	content, _ := io.ReadAll(io.LimitReader(file, limit))
	h.Write(content)
	if int64(len(content)) < info.Size() {
		a.Truncated, f.Truncated = true, true
		// The digest covers the whole file even when the content is cut.
		_, _ = io.Copy(h, file)
	}
	a.SHA256 = hex.EncodeToString(h.Sum(nil))
	a.Content = content
	f.Files = append(f.Files, a)
	return budget - int64(len(content))
}

// attachMCP attaches the repository's MCP configuration for the connector
// and the in-repository files its stdio servers start (E20), so the gateway
// can scan them with mcp-scanner before the agent starts them.
func attachMCP(f *Facts, connector, cwd string, budget int64) int64 {
	var cfgPath string
	var servers []mcpServer
	switch connector {
	case "claudecode":
		cfgPath = filepath.Join(cwd, ".mcp.json")
		servers = claudeMCPServers(cfgPath)
	case "codex":
		cfgPath = filepath.Join(cwd, ".codex", "config.toml")
		servers = codexMCPServers(cfgPath)
	default:
		return budget
	}
	if _, err := os.Lstat(cfgPath); err != nil {
		return budget
	}
	budget = attach(f, "mcp_config", cfgPath, "", budget)
	for _, s := range servers {
		for _, cand := range append([]string{s.Command}, s.Args...) {
			if !looksLikePath(cand) {
				continue
			}
			p := cand
			if !filepath.IsAbs(p) {
				p = filepath.Join(cwd, p)
			}
			p = filepath.Clean(p)
			resolved, err := filepath.EvalSymlinks(p)
			if err != nil || !within(resolved, cwd) {
				continue
			}
			budget = attach(f, "mcp_server", p, resolved, budget)
		}
	}
	return budget
}

type mcpServer struct {
	Command string
	Args    []string
}

func looksLikePath(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	if strings.Contains(s, "/") {
		return true
	}
	switch strings.ToLower(filepath.Ext(s)) {
	case ".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".rb", ".pl", ".jar":
		return true
	}
	return false
}

func readSmall(path string) []byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	b, _ := io.ReadAll(io.LimitReader(file, MaxAttachBytes))
	return b
}

// claudeMCPServers reads the stdio servers of a Claude Code MCP config by
// the exact keys Claude Code reads (encoding/json's struct matching folds
// case, GAP-0176): the kit attaches the files these servers start.
func claudeMCPServers(path string) []mcpServer {
	var doc map[string]json.RawMessage
	if json.Unmarshal(readSmall(path), &doc) != nil {
		return nil
	}
	var servers map[string]map[string]json.RawMessage
	if json.Unmarshal(doc["mcpServers"], &servers) != nil {
		return nil
	}
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []mcpServer
	for _, n := range names {
		var s struct {
			Type, Command string
			Args          []string
		}
		_ = json.Unmarshal(servers[n]["type"], &s.Type)
		_ = json.Unmarshal(servers[n]["command"], &s.Command)
		_ = json.Unmarshal(servers[n]["args"], &s.Args)
		if s.Command != "" && (s.Type == "" || s.Type == "stdio") {
			out = append(out, mcpServer{Command: s.Command, Args: s.Args})
		}
	}
	return out
}

func codexMCPServers(path string) []mcpServer {
	var doc struct {
		MCPServers map[string]struct {
			Command string   `toml:"command"`
			Args    []string `toml:"args"`
		} `toml:"mcp_servers"`
	}
	if toml.Unmarshal(readSmall(path), &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc.MCPServers))
	for n := range doc.MCPServers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []mcpServer
	for _, n := range names {
		s := doc.MCPServers[n]
		if s.Command != "" {
			out = append(out, mcpServer{Command: s.Command, Args: s.Args})
		}
	}
	return out
}
