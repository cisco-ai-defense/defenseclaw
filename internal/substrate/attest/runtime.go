// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// The run-time path: a skill or an MCP server that the agent adds while it
// runs (PLAN 6.6, E20). The kit's hook sees the tool call before it runs
// (PreToolUse) with the content the agent is about to write and, for an MCP
// admission, the repository's MCP configuration and the stdio server files it
// starts. The gateway's hook route hands that to RuntimeScanner, which scans
// with the same scanners and decides with the same admission rules as the
// host's watcher, and answers allow, warn or block. A block denies the tool
// call, so the skill file is never written.

// Role names of the files the kit attaches (kit.AttachedFile.Role).
const (
	RoleSkillFile = "skill_file"
	RoleMCPConfig = "mcp_config"
	RoleMCPServer = "mcp_server"
	RoleRead      = "read_target"
)

// AttachedFile is a file the kit read for the gateway. Everything in it is a
// claim from code running as the agent's user.
type AttachedFile struct {
	Role      string
	Path      string
	Content   []byte
	Truncated bool
}

// RuntimeAsset is one skill or MCP server to scan.
type RuntimeAsset struct {
	// Kind is skill or mcp.
	Kind string
	Name string
	// Path is where the agent is putting it (a claim).
	Path  string
	Files []AttachedFile
	// Server is set for kind mcp.
	Server *MCPServer
}

// RuntimeDecision is the answer for the hook route.
type RuntimeDecision struct {
	// Action is allow, warn or block.
	Action string
	Reason string
	Kind   string
	Name   string
	Path   string
	// Admission is the admission output, for the audit record.
	Admission *policy.AdmissionOutput
	Result    *scanner.ScanResult
	// Cached is true when an identical asset was decided a moment ago.
	Cached bool
	// Incomplete is true when attached content was cut by the kit's cap; the
	// decision then fails closed for kind skill and mcp.
	Incomplete bool
}

// RuntimeScanner scans assets added mid-session.
type RuntimeScanner struct {
	Skill     scanner.Scanner
	MCPStatic scanner.Scanner
	Admission AdmissionFunc
	Compiled  map[string]policy.CompiledAdmission
	BlockList []policy.ListEntry
	AllowList []policy.ListEntry
	// AllowedMCPHosts, when not empty, lists the remote MCP hosts allowed.
	AllowedMCPHosts []string
	// BlockAtOrAbove is an optional severity floor (see ScanOptions); the
	// default follows the host admission rules exactly.
	BlockAtOrAbove scanner.Severity
	// MaxFiles and MaxBytes bound one asset (defaults 64 files, 2 MiB).
	MaxFiles int
	MaxBytes int64
	// TTL is how long a decision is reused (default 5 minutes).
	TTL time.Duration
	Now func() time.Time

	mu    sync.Mutex
	cache map[string]cachedDecision
}

type cachedDecision struct {
	d  RuntimeDecision
	at time.Time
}

func (r *RuntimeScanner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Scan decides one asset. An error means the scan could not run: the caller
// applies its fail mode (unattended is closed, D8).
func (r *RuntimeScanner) Scan(ctx context.Context, a RuntimeAsset) (*RuntimeDecision, error) {
	if r.Skill == nil {
		return nil, errors.New("runtime scan: no skill scanner")
	}
	maxFiles, maxBytes, ttl := r.MaxFiles, r.MaxBytes, r.TTL
	if maxFiles == 0 {
		maxFiles = 64
	}
	if maxBytes == 0 {
		maxBytes = 2 << 20
	}
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	key := assetKey(a)
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]cachedDecision{}
	}
	if c, ok := r.cache[key]; ok && r.now().Sub(c.at) < ttl {
		r.mu.Unlock()
		d := c.d
		d.Cached = true
		return &d, nil
	}
	r.mu.Unlock()

	incomplete := false
	var total int64
	files := make([]AttachedFile, 0, len(a.Files))
	for _, f := range a.Files {
		if len(files) >= maxFiles || total+int64(len(f.Content)) > maxBytes {
			incomplete = true
			break
		}
		if f.Truncated {
			incomplete = true
		}
		total += int64(len(f.Content))
		files = append(files, f)
	}
	work, err := os.MkdirTemp("", "dc-attest-rt-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	so := ScanOptions{Admission: r.Admission, Compiled: r.Compiled, BlockList: r.BlockList, AllowList: r.AllowList, BlockAtOrAbove: r.BlockAtOrAbove, Now: r.now}
	if so.Admission == nil {
		so.Admission = FallbackAdmission
	}
	var res *scanner.ScanResult
	switch a.Kind {
	case config.AdmissionTypeSkill:
		dir := filepath.Join(work, "skill")
		if err := writeAttached(dir, files); err != nil {
			return nil, err
		}
		if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err != nil {
			// The agent is writing a helper file of a skill, or the skill
			// file under another name: scan what there is as a skill.
			if len(files) == 0 {
				return nil, errors.New("runtime scan: no skill content to scan")
			}
		}
		res, err = r.Skill.Scan(ctx, dir)
		if err != nil || res == nil {
			res = failedScan(r.Skill.Name(), a.Name, err)
		}
	case config.AdmissionTypeMCP:
		if a.Server == nil {
			return nil, errors.New("runtime scan: no MCP server definition")
		}
		res = &scanner.ScanResult{Scanner: ConfigScannerName, Target: a.Name, Timestamp: r.now().UTC()}
		res.Findings = append(res.Findings, ConfigRules(*a.Server, r.AllowedMCPHosts)...)
		if r.MCPStatic != nil && a.Server.Transport == "stdio" {
			var src strings.Builder
			for _, f := range files {
				if f.Role == RoleMCPServer && sourceExt[path.Ext(f.Path)] {
					src.Write(f.Content)
					src.WriteByte('\n')
				}
			}
			if tools := ExtractToolDefs(src.String()); len(tools) > 0 {
				tf := filepath.Join(work, "tools.json")
				raw, _ := json.Marshal(map[string]any{"tools": tools})
				if err := os.WriteFile(tf, raw, 0o600); err != nil {
					return nil, err
				}
				sr, err := r.MCPStatic.Scan(ctx, tf)
				if err != nil || sr == nil {
					sr = failedScan(r.MCPStatic.Name(), a.Name, err)
				}
				res.Findings = append(res.Findings, sr.Findings...)
				if sr.ScanError != "" {
					res.ScanError, res.ExitCode = sr.ScanError, sr.ExitCode
				}
				res.Scanner = r.MCPStatic.Name()
			}
		}
	default:
		return nil, fmt.Errorf("runtime scan: unknown asset kind %q", a.Kind)
	}

	// Host admission rules: no template-build floor.
	verdict, reason := so.decide(ctx, a.Kind, a.Name, a.Path, res)
	d := &RuntimeDecision{Kind: a.Kind, Name: a.Name, Path: a.Path, Result: res, Reason: reason, Incomplete: incomplete}
	switch verdict {
	case VerdictBlock:
		d.Action = "block"
	case VerdictWarn:
		d.Action = "warn"
	default:
		d.Action = "allow"
	}
	if incomplete && d.Action != "block" {
		d.Action, d.Reason = "block", "the attached content was cut by the size cap, so it was not fully scanned"
	}
	r.mu.Lock()
	r.cache[key] = cachedDecision{d: *d, at: r.now()}
	r.mu.Unlock()
	return d, nil
}

func assetKey(a RuntimeAsset) string {
	h := sha256.New()
	h.Write([]byte(a.Kind + "\x00" + a.Name + "\x00" + a.Path + "\x00"))
	fs := append([]AttachedFile(nil), a.Files...)
	sort.Slice(fs, func(i, j int) bool { return fs[i].Path < fs[j].Path })
	for _, f := range fs {
		sum := sha256.Sum256(f.Content)
		h.Write([]byte(f.Role + "\x00" + f.Path + "\x00"))
		h.Write(sum[:])
	}
	if a.Server != nil {
		b, _ := json.Marshal(a.Server)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeAttached writes claimed files into dir. A claimed path never leaves
// dir: absolute prefixes are cut to the file's base below its skill folder
// and ".." is refused.
func writeAttached(dir string, files []AttachedFile) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range files {
		rel := skillRelative(f.Path)
		if rel == "" || strings.Contains(rel, "..") {
			continue
		}
		out := filepath.Join(dir, filepath.FromSlash(rel))
		if !strings.HasPrefix(out, dir+string(filepath.Separator)) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(out, f.Content, 0o600); err != nil {
			return err
		}
	}
	return nil
}

var skillRootRE = regexp.MustCompile(`(?:^|/)(?:\.claude|\.codex|\.agents|\.config/[a-z]+)/skills/([^/]+)(?:/(.*))?$`)

// skillRelative returns the path of a skill file relative to its skill folder
// ("SKILL.md", "scripts/run.sh").
func skillRelative(p string) string {
	p = path.Clean("/" + p)
	if m := skillRootRE.FindStringSubmatch(p); m != nil {
		if m[2] == "" {
			return ""
		}
		return m[2]
	}
	return strings.TrimPrefix(p, "/")
}

var (
	skillPathInCommand = regexp.MustCompile(`(\S*(?:\.claude|\.codex|\.agents)/skills/[A-Za-z0-9._\-]+)(?:/(\S*))?`)
	mcpAddRE           = regexp.MustCompile(`\b(?:claude|codex)\s+mcp\s+add\b`)
	mcpConfigWrite     = regexp.MustCompile(`(?:^|/)(?:\.mcp\.json|mcp\.json|\.claude\.json|settings\.json|settings\.local\.json|config\.toml)$`)
)

// HookAssets finds the skills and MCP servers a tool call is about to add.
// payload is the agent's hook event (PreToolUse), attached the kit's files.
// It reads the tool input the agent gave, which is a claim, and returns what
// must be scanned before the call may run.
func HookAssets(payload json.RawMessage, attached []AttachedFile) []RuntimeAsset {
	var ev struct {
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if json.Unmarshal(payload, &ev) != nil {
		return nil
	}
	var in map[string]any
	_ = json.Unmarshal(ev.ToolInput, &in)
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := in[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	var out []RuntimeAsset

	target := str("file_path", "path", "notebook_path")
	content := str("content", "new_string", "new_source")
	command := str("command")
	if cmds, ok := in["command"].([]any); ok { // codex shell: argv list
		parts := make([]string, 0, len(cmds))
		for _, c := range cmds {
			if s, ok := c.(string); ok {
				parts = append(parts, s)
			}
		}
		command = strings.Join(parts, " ")
	}
	patch := str("patch", "input")

	writeTool := map[string]bool{"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true, "apply_patch": true}[ev.ToolName]
	readTool := map[string]bool{"Read": true, "View": true}[ev.ToolName]
	attachedFor := func(name string) []AttachedFile {
		var fs []AttachedFile
		for _, f := range attached {
			if f.Role != RoleSkillFile && f.Role != RoleRead {
				continue
			}
			if m := skillRootRE.FindStringSubmatch(path.Clean("/" + f.Path)); m != nil && m[1] == name {
				fs = append(fs, f)
			}
		}
		return fs
	}
	// Skills written through a file tool, and skill files the agent reads:
	// the gateway scans what is about to be written, or what is about to
	// reach the model's context.
	if target != "" && (writeTool || readTool) && skillRootRE.MatchString(path.Clean("/"+target)) {
		m := skillRootRE.FindStringSubmatch(path.Clean("/" + target))
		var files []AttachedFile
		if writeTool {
			files = append(files, AttachedFile{Role: RoleSkillFile, Path: target, Content: []byte(content)})
		}
		files = append(files, attachedFor(m[1])...)
		out = append(out, RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: m[1], Path: skillDirOf(target, m[1]), Files: files})
	}
	// The Skill tool: the agent is about to use a skill, however it got
	// there (written, copied, cloned, installed). The kit attaches the skill
	// folder; with nothing attached the asset has no files and Scan fails
	// closed.
	if ev.ToolName == "Skill" {
		if name := str("skill", "name"); name != "" {
			dir := ""
			files := attachedFor(name)
			if len(files) > 0 {
				dir = skillDirOf(files[0].Path, name)
			}
			out = append(out, RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: name, Path: dir, Files: files})
		}
	}
	// Skills written by a shell command or a patch: the command text is the
	// content (heredoc bodies, echo, tee, python -c ...).
	for _, text := range []string{command, patch} {
		if text == "" {
			continue
		}
		seen := map[string]bool{}
		for _, m := range skillPathInCommand.FindAllStringSubmatch(text, -1) {
			dir := m[1]
			if seen[dir] {
				continue
			}
			seen[dir] = true
			name := path.Base(dir)
			files := []AttachedFile{{Role: RoleSkillFile, Path: path.Join(dir, "SKILL.md"), Content: []byte(text)}}
			out = append(out, RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: name, Path: dir, Files: files})
		}
	}

	// MCP servers added by file tool: parse the config being written.
	if target != "" && mcpConfigWrite.MatchString(target) && content != "" {
		if servers, err := ParseMCPConfig(target, []byte(content)); err == nil {
			for _, s := range servers {
				s := s
				out = append(out, RuntimeAsset{Kind: config.AdmissionTypeMCP, Name: s.Name, Path: target, Server: &s, Files: serverFiles(attached)})
			}
		}
	}
	// MCP servers added by "claude mcp add" / "codex mcp add".
	if command != "" && mcpAddRE.MatchString(command) {
		if s := parseMCPAddCommand(command); s != nil {
			out = append(out, RuntimeAsset{Kind: config.AdmissionTypeMCP, Name: s.Name, Path: "mcp add", Server: s, Files: serverFiles(attached)})
		}
	}
	// An MCP admission event: the kit attached the repository's MCP
	// configuration and the server files (E20).
	for _, f := range attached {
		if f.Role != RoleMCPConfig {
			continue
		}
		servers, err := ParseMCPConfig(f.Path, f.Content)
		if err != nil {
			continue
		}
		for _, s := range servers {
			s := s
			out = append(out, RuntimeAsset{Kind: config.AdmissionTypeMCP, Name: s.Name, Path: f.Path, Server: &s, Files: serverFiles(attached)})
		}
	}
	return out
}

func skillDirOf(file, name string) string {
	i := strings.Index(file, "/skills/"+name)
	if i < 0 {
		return path.Dir(file)
	}
	return file[:i] + "/skills/" + name
}

func serverFiles(all []AttachedFile) []AttachedFile {
	var out []AttachedFile
	for _, f := range all {
		if f.Role == RoleMCPServer || f.Role == RoleMCPConfig {
			out = append(out, f)
		}
	}
	return out
}

// parseMCPAddCommand reads "claude mcp add [flags] <name> -- <command> [args]"
// and "claude mcp add --transport http <name> <url>". Flags that take a value
// are skipped over; an unreadable command returns nil (the caller treats the
// tool call as an unknown asset and the host rules apply).
func parseMCPAddCommand(cmd string) *MCPServer {
	loc := mcpAddRE.FindStringIndex(cmd)
	fields := strings.Fields(cmd[loc[1]:])
	s := &MCPServer{Transport: "stdio", Source: "mcp add"}
	valueFlags := map[string]bool{"-s": true, "--scope": true, "-t": true, "--transport": true, "-e": true, "--env": true, "-H": true, "--header": true, "--url": true}
	var pos []string
	i := 0
	for ; i < len(fields); i++ {
		f := fields[i]
		if f == "--" {
			i++
			break
		}
		if strings.HasPrefix(f, "-") {
			if valueFlags[f] && i+1 < len(fields) {
				v := fields[i+1]
				switch f {
				case "--url":
					s.URL, s.Transport = v, "http"
				case "-t", "--transport":
					if v == "http" || v == "sse" {
						s.Transport = v
					}
				case "-e", "--env":
					k, val, _ := strings.Cut(v, "=")
					s.EnvKeys = append(s.EnvKeys, k)
					if looksLikeCredential(val) {
						s.SecretEnv = append(s.SecretEnv, k)
					}
				}
				i++
			}
			continue
		}
		pos = append(pos, f)
	}
	if len(pos) == 0 {
		return nil
	}
	s.Name = pos[0]
	if s.URL != "" {
		return s
	}
	if s.Transport != "stdio" {
		if len(pos) < 2 {
			return nil
		}
		s.URL = pos[1]
		return s
	}
	rest := fields[i:]
	if len(rest) == 0 && len(pos) > 1 {
		rest = pos[1:]
	}
	if len(rest) == 0 {
		return nil
	}
	s.Command, s.Args = rest[0], rest[1:]
	return s
}
