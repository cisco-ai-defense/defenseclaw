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
	"runtime"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/agentpaths"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const (
	maxPathFacts = 32
	maxLinkHops  = 40
	maxWalkDepth = 4
	// maxProjectHookBytes bounds the project settings file the kit reads;
	// maxProjectHookEvents and maxProjectHookEventLen bound what it reports.
	maxProjectHookBytes    = 1 << 20
	maxProjectHookEvents   = 32
	maxProjectHookEventLen = 64
	// maxCommandWordWalks bounds the distinct command words one shell call
	// walks in the actor's file system (addShellCommandFacts): the 64 words
	// hookpaths.CommandPathWords returned when the kit's link proofs came in
	// (substrate-1 GAP-0546); it now returns every word.
	maxCommandWordWalks = 64
)

// projectHookFiles are, per connector, the project settings files (relative
// to the session's cwd) whose hooks the actor's managed settings ignore:
// Claude Code's drop-in sets allowManagedHooksOnly (claudecode_sandbox.go),
// so a hook an uploaded repository declares never runs. The kit reports
// them at SessionStart so the attempt is recorded (GAP-0479).
var projectHookFiles = map[string][]string{
	"claudecode": {".claude/settings.json", ".claude/settings.local.json"},
}

// pathKeys are tool argument keys whose string value is a file-system path
// in the connectors' file tools: every key the reviewed file-tool schemas
// read as the path (actionfacts.FileToolPathKeys, root included; substrate-1
// GAP-0545) and the other file tools' names for a file.
var pathKeys = func() map[string]bool {
	keys := map[string]bool{
		"target_file": true, "filename": true, "old_path": true, "new_path": true,
		"source": true, "destination": true,
	}
	for _, key := range actionfacts.FileToolPathKeys() {
		keys[key] = true
	}
	return keys
}()

// readTools are tools whose PreToolUse target the gateway may want to see:
// the kit attaches the file it is about to read. OpenCode's read tool
// (filePath, before tool.execute.before) runs the skill folder pass like
// Claude Code's Read (GAP-1143).
var readTools = map[string]map[string]bool{
	"claudecode": {"Read": true, "NotebookRead": true},
	"opencode":   {"read": true},
}

// skillTools are the tools that load a skill by name (B5.4 use gate).
var skillTools = map[string]map[string]bool{
	"claudecode": {"Skill": true},
}

// payloadView is the part of a hook payload the kit inspects; the tool's
// arguments are read by ToolArgsOf.
type payloadView struct {
	Event    string `json:"hook_event_name"`
	CWD      string `json:"cwd"`
	ToolName string `json:"tool_name"`
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
	if args := ToolArgsOf(connector, event, payload); len(args) > 0 {
		_ = json.Unmarshal(args, &input)
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
	if shellProofEvent(connector, event) {
		addShellCommandFacts(f, connector, event, payload, cwd)
	}
	if (isPre || event == "tool.execute.before") && readTools[connector][view.ToolName] {
		for _, pf := range f.Paths {
			// A read of a skill's files runs the skill folder pass in this
			// call (one rule for every skill: the folder's content digest,
			// GAP-0039/0164), so a folder that arrived since the last pass is
			// decided before its files reach the model.
			if pf.Type == "file" && (pf.Field == "tool_input.file_path" || pf.Field == "tool_input.notebook_path" || pf.Field == "tool_input.filePath") &&
				(inSkillRoot(pf.Abs) || inSkillRoot(pf.Resolved)) {
				f.readsSkill = true
			}
		}
	}
	// The Claude Code Skill tool loads a skill: the folder pass runs in this
	// call too (B5.4 use gate), so the folder is re-digested before the skill
	// reaches the model and a receipt only holds for the same content.
	if isPre && skillTools[connector][view.ToolName] {
		f.readsSkill = true
	}
	// Every MCP config the connector reads (project, user and local scope)
	// and the in-repository server files: at SessionStart (the agent starts
	// the servers) and before every call of an MCP tool, which the gateway
	// refuses when the scan blocks its server (E20, GAP-0185).
	if event == "SessionStart" || event == "sessionStart" || (isPre && strings.HasPrefix(view.ToolName, "mcp__")) {
		budget = attachMCP(f, connector, cwd, budget)
	} else if isPre {
		budget = attachAgentHookBefore(f, connector, view.ToolName, budget)
		// A Write or Edit of one of those configs: its next content.
		budget = attachMCPWrite(f, connector, cwd, input, budget)
		// A command that may add an MCP server (claude mcp add, codex mcp
		// add), as a string (Bash) or an argv list (the Codex shell tool,
		// which the gateway reads joined): what the folder offers a
		// registry fetcher (GAP-0573, GAP-0643).
		if in, ok := input.(map[string]any); ok && strings.Contains(strings.ToLower(commandText(in["command"])), "mcp") {
			budget = attachFetchFacts(f, cwd, budget)
		}
	}
	_ = budget
	if event == "SessionStart" || event == "sessionStart" {
		f.ProjectHooks = collectProjectHooks(connector, cwd)
	}
	if len(f.Paths) == 0 && len(f.Files) == 0 && len(f.ProjectHooks) == 0 && len(f.Proofs) == 0 && !f.Truncated && !f.readsSkill {
		return nil
	}
	return f
}

// attachAgentHookBefore supplies exact current settings bytes for semantic
// native-edit and replacement judgement. One bounded read per settings target;
// the shared post budget also bounds multi-file patches. Unrelated calls attach
// nothing, and oversized files receive no digest pass.
func attachAgentHookBefore(f *Facts, connectorName, tool string, budget int64) int64 {
	if connectorName != "claudecode" {
		return budget
	}
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "edit", "edit_file", "str_replace", "multiedit", "multi_edit", "multi-edit",
		"write", "write_file", "writefile", "write-file", "create", "create_file",
		"apply_patch", "applypatch", "apply-patch", "patch":
	default:
		return budget
	}
	attached := map[string]bool{}
	for _, pf := range f.Paths {
		if pf.Field != "tool_input.file_path" && pf.Field != "tool_input.filePath" && pf.Field != "tool_input.path" && !strings.HasSuffix(pf.Field, ".patch") {
			continue
		}
		p := filepath.ToSlash(pf.Abs)
		if !strings.HasSuffix(p, "/.claude/settings.json") && !strings.HasSuffix(p, "/.claude/settings.local.json") {
			continue
		}
		if attached[pf.Abs] {
			continue
		}
		attached[pf.Abs] = true
		a := AttachedFile{Role: "agent_hook_config_before", Path: pf.Abs, Resolved: pf.Resolved, Size: -1, Truncated: true}
		limit := budget
		if limit > 64<<10 {
			limit = 64 << 10
		}
		if limit < 0 {
			limit = 0
		}
		file, err := os.Open(pf.Abs)
		if err == nil {
			info, statErr := file.Stat()
			if statErr == nil && info.Mode().IsRegular() {
				a.Size = info.Size()
				if info.Size() <= limit {
					content, readErr := io.ReadAll(io.LimitReader(file, limit+1))
					if readErr == nil && int64(len(content)) == info.Size() {
						a.Content = content
						a.Truncated = false
						sum := sha256.Sum256(content)
						a.SHA256 = hex.EncodeToString(sum[:])
					}
				}
			}
			file.Close()
		}
		if os.IsNotExist(err) && pf.Type == "missing" {
			// A missing file is an exact empty before-state, not a failed read.
			a.Size, a.Truncated = 0, false
			sum := sha256.Sum256(nil)
			a.SHA256 = hex.EncodeToString(sum[:])
		}
		if a.Truncated {
			f.Truncated = true
		}
		f.Files = append(f.Files, a)
		budget -= int64(len(a.Content))
	}
	return budget
}

// collectProjectHooks returns the connector's project settings files under
// cwd that declare at least one hook, with the events they name. A file
// that is missing, too big or not JSON declares nothing the agent loads.
func collectProjectHooks(connectorName, cwd string) []ProjectHooks {
	var out []ProjectHooks
	for _, rel := range projectHookFiles[connectorName] {
		p := filepath.Join(cwd, filepath.FromSlash(rel))
		info, err := os.Stat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxProjectHookBytes {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) > maxProjectHookBytes {
			continue
		}
		var doc struct {
			Hooks map[string]json.RawMessage `json:"hooks"`
		}
		if json.Unmarshal(raw, &doc) != nil {
			continue
		}
		ph := ProjectHooks{Path: p}
		for event, groups := range doc.Hooks {
			var list []struct {
				Hooks []json.RawMessage `json:"hooks"`
			}
			if json.Unmarshal(groups, &list) != nil {
				continue
			}
			n := 0
			for _, g := range list {
				n += len(g.Hooks)
			}
			if n == 0 {
				continue
			}
			ph.Hooks += n
			if len(event) > maxProjectHookEventLen {
				event = event[:maxProjectHookEventLen]
			}
			ph.Events = append(ph.Events, event)
		}
		if ph.Hooks == 0 {
			continue
		}
		sort.Strings(ph.Events)
		if len(ph.Events) > maxProjectHookEvents {
			ph.Events = ph.Events[:maxProjectHookEvents]
		}
		sum := sha256.Sum256(raw)
		ph.SHA256 = hex.EncodeToString(sum[:])
		out = append(out, ph)
	}
	return out
}

// addShellCommandFacts makes, in the actor's file system, the file-system
// proofs the laptop's gateway makes for the call's shell command
// (ShellCommandOf, for every connector's shell tool): the private-key read
// proof and the protected-target write decision. It also lists each path word
// of the command (hookpaths.CommandPathWords: arguments, redirect targets, the
// words of an eval or -c body) whose physical place differs from its
// spelling: a symlink, a symlinked folder, a `..` after one. The gateway has
// no view of this file system: without these, cat key-link, cat
// a/b/ssh/id_ed25519, cd -P a/b/ssh && cat id_ed25519, eval "cat key-link" and
// echo x >> link-to-defenseclaw-state read or write the actor's protected
// files where the laptop blocks (substrate-1 GAP-0471, GAP-0545, GAP-0546,
// GAP-0547). Only POSIX shells run in an actor.
func addShellCommandFacts(f *Facts, connectorName, event string, payload []byte, cwd string) {
	if runtime.GOOS == "windows" {
		return
	}
	command, workdir, ok := ShellCommandOf(connectorName, event, payload)
	if !ok {
		return
	}
	if workdir != "" {
		if !filepath.IsAbs(workdir) {
			workdir = filepath.Join(cwd, workdir)
		}
		cwd = filepath.Clean(workdir)
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return
	}
	if hookpaths.ActionPrivateKeyReadWithDialect(command, cwd, home, actionfacts.DialectPOSIX) ||
		hookpaths.ActionMakePrivateKeyRead(command, cwd, home) {
		f.Proofs = append(f.Proofs, ProofPrivateKeyRead)
	}
	if hookpaths.ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil) ==
		hookpaths.ProtectedTargetDecision {
		f.Proofs = append(f.Proofs, ProofProtectedWrite)
	}
	// Which places are private matters only to a call the kit proved reads
	// or writes the actor's keys: an own SSH folder copy alerts where the
	// copy stays private (substrate-1 GAP-0549).
	privacy := len(f.Proofs) > 0
	seen := map[string]bool{}
	for _, word := range hookpaths.CommandPathWords(command, home) {
		if seen[word.Text] {
			continue
		}
		if len(seen) == maxCommandWordWalks {
			f.Truncated = true
			return
		}
		seen[word.Text] = true
		if fact, listed := commandWordFact(word, cwd, home, privacy); listed {
			if len(f.Paths) >= maxPathFacts {
				f.Truncated = true
				return
			}
			f.Paths = append(f.Paths, fact)
		}
	}
}

// commandWordFact is the CommandWordField fact of one command word: its place
// with every link followed and with its last name kept, each as the kernel
// walks it from cwd (hookpaths.ResolveWriteTarget), and, when privacy is
// asked, whether it is a private place of home. listed is false when both
// places are the one the word spells and it is no private place.
func commandWordFact(word hookpaths.CommandPathWord, cwd, home string, privacy bool) (PathFact, bool) {
	full := word.Value
	if !strings.HasPrefix(full, "/") {
		full = strings.TrimRight(cwd, "/") + "/" + full
	}
	lexical := filepath.Clean(full)
	fact := PathFact{Field: CommandWordField, Path: word.Text, Abs: lexical, UID: -1, GID: -1, Type: "missing"}
	if followed, ok := hookpaths.ResolveWriteTarget(full); ok && followed != lexical {
		fact.Resolved = followed
	}
	if dir, name := filepath.Split(strings.TrimRight(full, "/")); dir != "" && name != "" && name != "." && name != ".." {
		if parent, ok := hookpaths.ResolveWriteTarget(dir); ok {
			if entry := filepath.Join(parent, name); entry != lexical {
				fact.Entry = entry
			}
		}
	}
	fact.PrivateHome = privacy && hookpaths.PrivateHomePlace(lexical, home)
	if fact.Resolved == "" && fact.Entry == "" && !fact.PrivateHome {
		return PathFact{}, false
	}
	if info, err := os.Stat(full); err == nil {
		fact.Type = "other"
		switch {
		case info.Mode().IsRegular():
			fact.Type = "file"
		case info.IsDir():
			fact.Type = "dir"
		}
	}
	return fact, true
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
	// walk is the path as the kernel walks it: joined, not cleaned, so a
	// `..` after a symlinked folder ascends from the link's target
	// (a/b/ssh/../.ssh/id_ed25519 is the actor's key when a/b/ssh links to
	// ~/.ssh; cleaned first it was the missing a/b/.ssh/id_ed25519,
	// substrate-1 GAP-0546). Abs is the cleaned spelling.
	walk := p
	if strings.HasPrefix(walk, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			walk = strings.TrimRight(home, "/") + "/" + walk[2:]
		}
	}
	if !filepath.IsAbs(walk) {
		walk = strings.TrimRight(cwd, "/") + "/" + walk
	}
	pf.Abs = filepath.Clean(walk)
	cur := walk
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
			if dir, err := filepath.EvalSymlinks(filepath.Dir(cur)); err == nil {
				target = filepath.Join(dir, target)
			} else {
				target = filepath.Join(filepath.Dir(cur), target)
			}
		}
		target = filepath.Clean(target)
		pf.LinkChain = append(pf.LinkChain, target)
		cur = target
	}
	if resolved, err := filepath.EvalSymlinks(walk); err == nil {
		pf.Resolved = resolved
	}
	info, err := os.Stat(walk)
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
		if l, lerr := os.Lstat(walk); lerr == nil && l.Mode()&os.ModeSymlink != 0 {
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

// inSkillRoot reports whether p is inside a skill root of the connector
// table (agentpaths, the one skillRoots and quarantine read) or a Claude
// Code plugin's skills. GAP-1143: it was its own list of .claude, .codex
// and .agents, so a read in the other connectors' roots (OpenCode's
// .opencode/skill, Cursor's, Copilot's, ...) did not run the folder pass.
func inSkillRoot(p string) bool {
	p = filepath.ToSlash(p)
	if p == "" {
		return false
	}
	under := func(dir string) bool {
		dir = strings.TrimSuffix(filepath.ToSlash(dir), "/")
		return dir != "" && strings.HasPrefix(p, dir+"/")
	}
	for _, e := range agentpaths.ActorEntries() {
		if e.Kind != agentpaths.Skills {
			continue
		}
		switch e.Base {
		case agentpaths.Home, agentpaths.Project:
			if strings.Contains(p, "/"+e.Rel+"/") {
				return true
			}
		case agentpaths.Config:
			mark := "/" + e.Rel + "/"
			if e.ConfigRel != "" {
				mark = "/" + e.ConfigRel + mark
			}
			if strings.Contains(p, mark) {
				return true
			}
			if v := strings.TrimSpace(os.Getenv(e.ConfigEnv)); e.ConfigEnv != "" && filepath.IsAbs(v) && under(filepath.Join(filepath.Clean(v), filepath.FromSlash(e.Rel))) {
				return true
			}
		case agentpaths.Abs:
			if under(e.Rel) {
				return true
			}
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

// mcpConfigPaths are the files the connector reads MCP servers from, in
// every scope (project, user, local), taken from the connector's own MCP
// surface (connector.ConnectorCapabilities.MCP, the paths the host
// inventory and setup use), so every connector the kit runs gets its
// sources by construction (GAP-0185).
func mcpConfigPaths(connectorName, cwd string) []string {
	c, ok := connector.NewDefaultRegistry().Get(connectorName)
	if !ok {
		return nil
	}
	cp, ok := c.(connector.ConnectorCapabilityProvider)
	if !ok {
		return nil
	}
	m := cp.Capabilities(connector.SetupOpts{WorkspaceDir: cwd}).MCP
	if !m.Supported {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, list := range [][]string{m.ConfigPaths, m.ReadPaths, m.WritePaths} {
		for _, p := range list {
			if p == "" || !filepath.IsAbs(p) {
				continue
			}
			p = filepath.Clean(p)
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// moduleCandidates are the files of the folder a Python module name runs
// (python -m a.b runs a/b.py or the package a/b); attest.ModuleCandidates
// is the gateway's copy of the same rule.
func moduleCandidates(module string) []string {
	p := strings.ReplaceAll(strings.TrimSpace(module), ".", "/")
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return nil
	}
	return []string{p + ".py", p + "/__main__.py", p + "/__init__.py"}
}

// attachMCP attaches every MCP config of the connector that exists and the
// in-repository files its stdio servers start (E20), so the gateway can
// scan them before the agent starts or calls them.
func attachMCP(f *Facts, connectorName, cwd string, budget int64) int64 {
	found := false
	for _, cfgPath := range mcpConfigPaths(connectorName, cwd) {
		if _, err := os.Lstat(cfgPath); err != nil {
			continue
		}
		found = true
		budget = attach(f, "mcp_config", cfgPath, "", budget)
		var servers []mcpServer
		switch {
		case strings.HasSuffix(cfgPath, ".toml"):
			servers = codexMCPServers(cfgPath)
		case strings.HasSuffix(cfgPath, ".json"):
			servers = claudeMCPServers(cfgPath, cwd)
		}
		for _, s := range servers {
			// Where a bare command is found, so an installed program is
			// told from the folder's (GAP-0575).
			attachCommandPath(f, s.Command)
			// A Python module the server runs (-m a.b): its file when it is
			// in the folder, else a record that the kit looked and found
			// none, so the gateway can tell the image's module from the
			// folder's (GAP-0556).
			for i, a := range s.Args {
				if a != "-m" || i+1 >= len(s.Args) {
					continue
				}
				found := false
				for _, c := range moduleCandidates(s.Args[i+1]) {
					p := filepath.Join(cwd, filepath.FromSlash(c))
					if resolved, err := filepath.EvalSymlinks(p); err == nil && within(resolved, cwd) {
						budget = attach(f, "mcp_server", p, resolved, budget)
						found = true
					}
				}
				if !found {
					f.Files = append(f.Files, AttachedFile{Role: "mcp_module_absent", Path: s.Args[i+1]})
				}
			}
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
	}
	if found {
		// What the folder offers a registry fetcher (npx, uvx): its own
		// programs and configs decide what a fetched server runs (GAP-0573).
		budget = attachFetchFacts(f, cwd, budget)
	}
	return budget
}

// attachMCPWrite attaches, for a file tool call that writes or edits one of
// the connector's MCP configs, the content the file will have after it
// (role mcp_config_write): a Write's content, or the edits applied to the
// file as it is now. A call shape the kit cannot apply attaches nothing;
// the gateway then reads the call itself and an edit fragment follows the
// fail mode.
func attachMCPWrite(f *Facts, connectorName, cwd string, input any, budget int64) int64 {
	in, ok := input.(map[string]any)
	if !ok {
		return budget
	}
	target := firstString(in, "file_path", "filePath", "path")
	if target == "" {
		return budget
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(cwd, target)
	}
	target = filepath.Clean(target)
	resolvedTarget, terr := filepath.EvalSymlinks(target)
	match := false
	for _, p := range mcpConfigPaths(connectorName, cwd) {
		if p == target {
			match = true
			break
		}
		if rp, err := filepath.EvalSymlinks(p); terr == nil && err == nil && rp == resolvedTarget {
			match = true
			break
		}
	}
	if !match {
		// A config the connector does not load (sub/.mcp.json): the gateway
		// reads the servers of a whole write (its content) from the call
		// itself and decides a fetched one with the folder's facts, so the
		// kit sends them (GAP-0643). A partial edit gives the gateway no
		// server; it needs none.
		if _, whole := in["content"].(string); whole && mcpConfigWriteNames[filepath.Base(target)] {
			budget = attachFetchFacts(f, cwd, budget)
		}
		return budget
	}
	content, cut, ok := nextContent(in, target, budget)
	if !ok {
		return budget
	}
	sum := sha256.Sum256(content)
	a := AttachedFile{Role: "mcp_config_write", Path: target, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:]), Content: content, Truncated: cut}
	if cut {
		f.Truncated = true
	}
	f.Files = append(f.Files, a)
	return attachFetchFacts(f, cwd, budget-int64(len(content)))
}

// mcpConfigWriteNames are the file names whose write the gateway reads for
// MCP servers wherever they are (attest mcpConfigWrite, the kit's copy of
// the same rule).
var mcpConfigWriteNames = map[string]bool{".mcp.json": true, "mcp.json": true, ".claude.json": true,
	"settings.json": true, "settings.local.json": true, "config.toml": true}

// commandText is a tool call's command as the gateway reads it: the string,
// or the strings of an argv list joined by spaces.
func commandText(v any) string {
	switch c := v.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, e := range c {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// nextContent is the file's content after a Write (content) or an Edit
// (old_string/new_string, oldString/newString, edits[]), cut to limit.
func nextContent(in map[string]any, target string, limit int64) (content []byte, cut, ok bool) {
	if limit < 0 {
		limit = 0
	}
	clip := func(b []byte) ([]byte, bool, bool) {
		if int64(len(b)) > limit {
			return b[:limit], true, true
		}
		return b, false, true
	}
	if s, isStr := in["content"].(string); isStr {
		return clip([]byte(s))
	}
	edits := []map[string]any{in}
	if list, isList := in["edits"].([]any); isList {
		edits = edits[:0]
		for _, e := range list {
			if m, isMap := e.(map[string]any); isMap {
				edits = append(edits, m)
			}
		}
	}
	file, err := os.Open(target)
	var cur []byte
	if err == nil {
		cur, _ = io.ReadAll(io.LimitReader(file, limit+1))
		file.Close()
		if int64(len(cur)) > limit {
			return cur[:limit], true, true
		}
	}
	text, applied := string(cur), false
	for _, e := range edits {
		oldS, okOld := e["old_string"].(string)
		newS, okNew := e["new_string"].(string)
		if !okOld && !okNew {
			oldS, _ = e["oldString"].(string)
			newS, okNew = e["newString"].(string)
		}
		if !okNew {
			continue
		}
		applied = true
		all, _ := e["replace_all"].(bool)
		if !all {
			all, _ = e["replaceAll"].(bool)
		}
		switch {
		case oldS == "" && text == "":
			text = newS
		case oldS == "":
			// The agent refuses an empty old_string on a file with content.
		case all:
			text = strings.ReplaceAll(text, oldS, newS)
		default:
			text = strings.Replace(text, oldS, newS, 1)
		}
	}
	if !applied {
		return nil, false, false
	}
	return clip([]byte(text))
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
func claudeMCPServers(path, cwd string) []mcpServer {
	var doc map[string]json.RawMessage
	if json.Unmarshal(readSmall(path), &doc) != nil {
		return nil
	}
	servers := map[string]map[string]json.RawMessage{}
	_ = json.Unmarshal(doc["mcpServers"], &servers)
	if cwd != "" {
		// ~/.claude.json: the local scope of this folder (claude mcp add's
		// default) starts servers too.
		var projects map[string]map[string]json.RawMessage
		if json.Unmarshal(doc["projects"], &projects) == nil {
			var local map[string]map[string]json.RawMessage
			if json.Unmarshal(projects[cwd]["mcpServers"], &local) == nil {
				for n, v := range local {
					servers["local\x00"+n] = v
				}
			}
		}
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
