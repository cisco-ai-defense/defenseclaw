// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"gopkg.in/yaml.v3"
)

// An agent's own hook config (GAP-0048). On a per-user install the files
// that register DefenseClaw's hooks with an agent belong to the account, so
// the agent can write them: one allowed Edit that adds disableAllHooks to a
// project .claude/settings.json turned DefenseClaw off for every later
// session in that folder, silently. tamper.detector_state_write covers only
// ~/.defenseclaw.
//
// A native file tool call (Write, Edit, MultiEdit, an apply_patch envelope)
// is judged on the document it leaves: it is tamper.agent_hook_config_disable
// (CRITICAL: blocks in the default and strict packs) only when that document
// turns DefenseClaw off - disableAllHooks or allowManagedHooksOnly set, a
// DefenseClaw hook entry removed or changed, Codex's [features] hooks = false,
// an OpenCode plugin list without the bridge, the bridge file removed or
// rewritten, a reserved hook-process env setting changed, or a hook file
// left unreadable. Ordinary model, env and permissions edits stay allowed.
// A shell write whose content the gateway cannot read is
// tamper.agent_hook_config_write (HIGH: an alert in the default pack, a block
// in strict). Targets are resolved through links on this host's file
// system, as the state rule's are; a managed install is guarded by the
// vendors' managed locks instead and keeps its own path.
const (
	agentHookConfigDisableRuleID = "tamper.agent_hook_config_disable"
	agentHookConfigWriteRuleID   = "tamper.agent_hook_config_write"
	agentHookConfigMaxBytes      = 1 << 20
	agentHookConfigMaxLinkHops   = 8
)

// agentHookConfigProjectFiles are the hook files an agent reads in any
// folder (a project or one of its parents) that can switch DefenseClaw off
// or hold its hooks; the suffix is matched on the slash spelling.
var agentHookConfigProjectFiles = []struct{ suffix, format string }{
	{"/.claude/settings.json", gatewayconnector.AgentHookConfigClaudeSettings},
	{"/.claude/settings.local.json", gatewayconnector.AgentHookConfigClaudeSettings},
	{"/.github/copilot/settings.json", gatewayconnector.AgentHookConfigCopilotSettings},
	{"/.github/copilot/settings.local.json", gatewayconnector.AgentHookConfigCopilotSettings},
	{"/.github/hooks/defenseclaw.json", gatewayconnector.AgentHookConfigJSONHooks},
	{"/.codex/config.toml", gatewayconnector.AgentHookConfigCodexTOML},
	{"/.devin/hooks.v1.json", gatewayconnector.AgentHookConfigJSONHooks},
	{"/.kiro/hooks/defenseclaw.json", gatewayconnector.AgentHookConfigJSONHooks},
	{"/.kiro/agents/defenseclaw.json", gatewayconnector.AgentHookConfigJSONHooks},
	{"/.kiro/agents/kiro_default.json", gatewayconnector.AgentHookConfigJSONHooks},
}

// agentHookConfigHomeFiles are the per-user hook files under the calling
// account's home, beside the paths this process's own environment names
// (gatewayconnector.AgentHookConfigFiles).
var agentHookConfigHomeFiles = []struct {
	parts  []string
	format string
}{
	{[]string{".claude", "settings.json"}, gatewayconnector.AgentHookConfigClaudeSettings},
	{[]string{".claude", "settings.local.json"}, gatewayconnector.AgentHookConfigClaudeSettings},
	{[]string{".codex", "config.toml"}, gatewayconnector.AgentHookConfigCodexTOML},
	{[]string{".codex", "hooks.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".config", "opencode", "plugins", "defenseclaw.js"}, gatewayconnector.AgentHookConfigBridge},
	{[]string{".config", "opencode", "config.json"}, gatewayconnector.AgentHookConfigOpenCodeConfig},
	{[]string{".config", "opencode", "opencode.json"}, gatewayconnector.AgentHookConfigOpenCodeConfig},
	{[]string{".config", "opencode", "opencode.jsonc"}, gatewayconnector.AgentHookConfigOpenCodeConfig},
	{[]string{".opencode", "opencode.json"}, gatewayconnector.AgentHookConfigOpenCodeConfig},
	{[]string{".opencode", "opencode.jsonc"}, gatewayconnector.AgentHookConfigOpenCodeConfig},
	{[]string{".cursor", "hooks.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".config", "devin", "config.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{"AppData", "Roaming", "devin", "config.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".copilot", "hooks", "defenseclaw.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".copilot", "settings.json"}, gatewayconnector.AgentHookConfigCopilotSettings},
	{[]string{".copilot", "config.json"}, gatewayconnector.AgentHookConfigCopilotSettings},
	{[]string{".config", "amp", "plugins", "defenseclaw.ts"}, gatewayconnector.AgentHookConfigBridge},
	{[]string{".gemini", "config", "hooks.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".kiro", "hooks", "defenseclaw.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".kiro", "agents", "defenseclaw.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".kiro", "agents", "kiro_default.json"}, gatewayconnector.AgentHookConfigJSONHooks},
	{[]string{".kiro", "settings", "cli.json"}, gatewayconnector.AgentHookConfigKiroSettings},
}

func agentHookConfigFoldCase() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

// agentHookConfigGuard classifies the write targets of one call.
type agentHookConfigGuard struct {
	cwd, home, physicalHome string
	files                   []gatewayconnector.AgentHookConfigFile
}

// shellMentionsRegistryPath is a cheap prefilter. Every component comes from
// the active registration registry, including enclosing hook directories.
func (g *agentHookConfigGuard) shellMentionsRegistryPath(text string) bool {
	for _, file := range g.files {
		path := file.Path
		if relative, ok := strings.CutPrefix(path, g.home+string(filepath.Separator)); ok && g.home != "" {
			path = relative
		} else if relative, ok := strings.CutPrefix(path, g.cwd+string(filepath.Separator)); ok && g.cwd != "" {
			path = relative
		}
		for _, component := range strings.Split(filepath.ToSlash(path), "/") {
			if len(component) > 2 && strings.Contains(text, strings.ToLower(component)) {
				return true
			}
		}
	}
	for _, name := range []string{"defenseclaw-hook-user", "defenseclaw-hook-post", ".defenseclaw"} {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

func newAgentHookConfigGuard(cwd, home string) *agentHookConfigGuard {
	guard := &agentHookConfigGuard{cwd: cwd, home: home, files: gatewayconnector.AgentHookConfigFiles()}
	if home != "" && filepath.IsAbs(home) {
		guard.home = filepath.Clean(home)
		for _, file := range agentHookConfigHomeFiles {
			guard.files = append(guard.files, gatewayconnector.AgentHookConfigFile{
				Path: filepath.Join(append([]string{guard.home}, file.parts...)...), Format: file.format,
			})
		}
		if hermes := hermespath.ConfigPathForUserHome(guard.home); hermes != "" {
			guard.files = append(guard.files, gatewayconnector.AgentHookConfigFile{Path: hermes, Format: gatewayconnector.AgentHookConfigHermesYAML})
		}
		if physical, err := filepath.EvalSymlinks(guard.home); err == nil && physical != guard.home {
			guard.physicalHome = physical
		}
	}
	if filepath.IsAbs(cwd) {
		for dir := filepath.Clean(cwd); ; dir = filepath.Dir(dir) {
			for _, file := range agentHookConfigProjectFiles {
				guard.files = append(guard.files, gatewayconnector.AgentHookConfigFile{
					Path: filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(file.suffix, "/"))), Format: file.format,
				})
			}
			if dir == filepath.Dir(dir) || (guard.home != "" && dir == guard.home) {
				break
			}
		}
	}
	return guard
}

// shellTarget covers both a registration file and a directory operation
// that replaces or removes one of its enclosing connector directories.
func (g *agentHookConfigGuard) shellTarget(raw string) bool {
	if g.format(raw) != "" {
		return true
	}
	for _, place := range g.places(raw) {
		for _, file := range g.files {
			if !strings.HasPrefix(file.Path, place+string(filepath.Separator)) {
				continue
			}
			// Home and project roots are outside the connector's config tree.
			if place == g.home || place == g.cwd || place == string(filepath.Separator) ||
				strings.HasPrefix(g.home, place+string(filepath.Separator)) ||
				strings.HasPrefix(g.cwd, place+string(filepath.Separator)) {
				continue
			}
			if info, err := os.Stat(place); err == nil && info.IsDir() {
				return true
			}
		}
		for _, file := range agentHookConfigProjectFiles {
			parts := strings.Split(strings.TrimPrefix(file.suffix, "/"), "/")
			for count := 1; count < len(parts); count++ {
				if strings.HasSuffix(filepath.ToSlash(place), "/"+strings.Join(parts[:count], "/")) {
					return true
				}
			}
		}
	}
	return false
}

// ownedFile identifies installed DefenseClaw artifacts whose entire content
// is part of a registered hook. A mutation of one is a Named disable.
func (g *agentHookConfigGuard) ownedFile(raw string) bool {
	for _, place := range g.places(raw) {
		if g.format(place) == gatewayconnector.AgentHookConfigBridge ||
			(filepath.Base(place) == "defenseclaw.json" && g.format(place) != "") {
			return true
		}
		if g.home == "" {
			continue
		}
		bin := filepath.Join(g.home, ".local", "bin")
		if place == filepath.Join(bin, "defenseclaw-hook-user") ||
			place == filepath.Join(bin, "defenseclaw-hook-post") {
			return true
		}
		hooks := filepath.Join(g.home, ".defenseclaw", "hooks")
		if strings.HasPrefix(place, hooks+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func (g *agentHookConfigGuard) ownedFolder(raw string) bool {
	for _, place := range g.places(raw) {
		if place == g.home || place == g.cwd || place == string(filepath.Separator) {
			continue
		}
		for _, file := range g.files {
			if g.ownedFile(file.Path) && strings.HasPrefix(file.Path, place+string(filepath.Separator)) {
				return true
			}
		}
		if g.home != "" {
			for _, path := range []string{
				filepath.Join(g.home, ".defenseclaw", "hooks"),
				filepath.Join(g.home, ".local", "bin", "defenseclaw-hook-user"),
				filepath.Join(g.home, ".local", "bin", "defenseclaw-hook-post"),
			} {
				if place == path || strings.HasPrefix(path, place+string(filepath.Separator)) {
					return true
				}
			}
		}
	}
	return false
}

func agentHookConfigRegistrationPaths(g *agentHookConfigGuard) []string {
	seen := make(map[string]bool, len(g.files)*2)
	var out []string
	add := func(path string) {
		if path != "" && filepath.IsAbs(path) && !seen[path] {
			seen[path] = true
			out = append(out, path)
		}
	}
	for _, file := range g.files {
		for path := filepath.Clean(file.Path); filepath.IsAbs(path); path = filepath.Dir(path) {
			if path == g.home || path == g.cwd || path == string(filepath.Separator) ||
				strings.HasPrefix(g.home, path+string(filepath.Separator)) ||
				strings.HasPrefix(g.cwd, path+string(filepath.Separator)) {
				break
			}
			add(path)
		}
	}
	if g.home != "" {
		for _, name := range []string{"defenseclaw-hook-user", "defenseclaw-hook-post"} {
			add(filepath.Join(g.home, ".local", "bin", name))
		}
		hooks := filepath.Join(g.home, ".defenseclaw", "hooks")
		add(hooks)
		if entries, err := os.ReadDir(hooks); err == nil && len(entries) <= 64 {
			for _, entry := range entries {
				add(filepath.Join(hooks, entry.Name()))
			}
		}
	}
	return out
}

// places are the absolute spellings of a target: as written (~ and the
// working directory applied), and the file it reaches through links.
func (g *agentHookConfigGuard) places(raw string) []string {
	target := strings.TrimSpace(raw)
	if target == "" || strings.ContainsRune(target, 0) {
		return nil
	}
	if target == "~" || strings.HasPrefix(target, "~/") || strings.HasPrefix(target, `~\`) {
		if g.home == "" {
			return nil
		}
		target = filepath.Join(g.home, target[1:])
	}
	if !filepath.IsAbs(target) {
		if g.cwd == "" || !filepath.IsAbs(g.cwd) {
			return nil
		}
		target = filepath.Join(g.cwd, target)
	}
	target = filepath.Clean(target)
	places := []string{target}
	current := target
	for hop := 0; hop < agentHookConfigMaxLinkHops; hop++ {
		if physical, err := filepath.EvalSymlinks(current); err == nil {
			places = append(places, physical)
			break
		}
		// A file that does not exist yet, or a link to one: the folder it
		// lands in, through its links, and the link's own target.
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(current)
			if err != nil {
				break
			}
			if !filepath.IsAbs(link) {
				link = filepath.Join(filepath.Dir(current), link)
			}
			current = filepath.Clean(link)
			places = append(places, current)
			continue
		}
		if dir, err := filepath.EvalSymlinks(filepath.Dir(current)); err == nil {
			places = append(places, filepath.Join(dir, filepath.Base(current)))
		}
		break
	}
	if g.physicalHome != "" {
		for _, place := range places {
			if rest, ok := strings.CutPrefix(place, g.physicalHome+string(filepath.Separator)); ok {
				places = append(places, filepath.Join(g.home, rest))
			}
		}
	}
	return places
}

// format is the hook-file format of a target, "" for any other file.
func (g *agentHookConfigGuard) format(raw string) string {
	fold := agentHookConfigFoldCase()
	same := func(left, right string) bool {
		if fold {
			return strings.EqualFold(left, right)
		}
		return left == right
	}
	for _, place := range g.places(raw) {
		for _, file := range g.files {
			if same(place, file.Path) {
				return file.Format
			}
		}
		slashed := filepath.ToSlash(place)
		for _, file := range agentHookConfigProjectFiles {
			if len(slashed) >= len(file.suffix) && same(slashed[len(slashed)-len(file.suffix):], file.suffix) {
				return file.format
			}
		}
	}
	// The instruction-file proof uses the same device/inode identity. It
	// also covers case and short-name aliases where the host supports them.
	for _, place := range g.places(raw) {
		identity := hookpaths.FileIdentity(place)
		if identity == "" {
			continue
		}
		for _, file := range g.files {
			if identity == hookpaths.FileIdentity(file.Path) {
				return file.Format
			}
		}
	}
	return ""
}

// read returns a target's current content, false when there is no regular
// file to read.
func (g *agentHookConfigGuard) read(raw string) ([]byte, bool) {
	if ManagedEnterpriseActive() {
		path := strings.TrimSpace(raw)
		if path == "~" {
			path = g.home
		} else if strings.HasPrefix(path, "~/") {
			path = filepath.Join(g.home, path[2:])
		} else if !filepath.IsAbs(path) {
			path = filepath.Join(g.cwd, path)
		}
		if path == "" || !filepath.IsAbs(path) {
			return nil, false
		}
		body, err := safefile.ReadRegularFileBounded(filepath.Clean(path), agentHookConfigMaxBytes)
		return body, err == nil
	}
	places := g.places(raw)
	if len(places) == 0 {
		return nil, false
	}
	file, err := os.Open(places[0])
	if err != nil {
		return nil, false
	}
	defer file.Close()
	if info, err := file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(file, agentHookConfigMaxBytes+1))
	if err != nil || len(body) > agentHookConfigMaxBytes {
		return nil, false
	}
	return body, true
}

// agentHookConfigChange is one file a native file tool call writes.
type agentHookConfigChange struct {
	path string
	// text is the call's own text for the file, judged when the change
	// cannot be applied to the file as it is.
	text string
	// after is the document the call leaves (exists false: it removes the
	// file); ok false when the change does not apply to the file as read.
	after func(read func(string) ([]byte, bool)) (body []byte, exists, ok bool)
}

type agentHookConfigTextEdit struct {
	old, new string
	all      bool
}

func agentHookConfigString(object map[string]any, keys ...string) (string, bool) {
	for _, key := range keys {
		if value, ok := object[key].(string); ok {
			return value, true
		}
	}
	return "", false
}

func agentHookConfigBool(object map[string]any, keys ...string) bool {
	for _, key := range keys {
		if value, ok := object[key].(bool); ok {
			return value
		}
	}
	return false
}

// agentHookConfigFileChanges reads a native file tool call: the files it
// writes and how. native is false for a call that is not one, or whose
// arguments it cannot read; the shell path judges those.
func agentHookConfigFileChanges(tool string, args json.RawMessage) (changes []agentHookConfigChange, native bool) {
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.UseNumber()
	if decoder.Decode(&object) != nil || object == nil {
		return nil, false
	}
	pathKeys := []string{"file_path", "filePath", "path"}
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "write", "write_file", "writefile", "write-file", "create", "create_file":
		path, pathOK := agentHookConfigString(object, pathKeys...)
		content, contentOK := agentHookConfigString(object, "content", "file_text")
		if !pathOK || !contentOK {
			return nil, false
		}
		return []agentHookConfigChange{{path: path, text: content,
			after: func(func(string) ([]byte, bool)) ([]byte, bool, bool) { return []byte(content), true, true },
		}}, true
	case "edit", "edit_file", "str_replace":
		path, pathOK := agentHookConfigString(object, pathKeys...)
		old, oldOK := agentHookConfigString(object, "old_string", "oldString", "old_str")
		replacement, newOK := agentHookConfigString(object, "new_string", "newString", "new_str")
		if !pathOK || !oldOK || !newOK {
			return nil, false
		}
		edits := []agentHookConfigTextEdit{{old: old, new: replacement, all: agentHookConfigBool(object, "replace_all", "replaceAll")}}
		return []agentHookConfigChange{agentHookConfigEditChange(path, edits)}, true
	case "multiedit", "multi_edit", "multi-edit":
		path, pathOK := agentHookConfigString(object, pathKeys...)
		items, itemsOK := object["edits"].([]any)
		if !pathOK || !itemsOK || len(items) == 0 {
			return nil, false
		}
		edits := make([]agentHookConfigTextEdit, 0, len(items))
		for _, value := range items {
			item, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			old, oldOK := agentHookConfigString(item, "old_string", "oldString", "old_str")
			replacement, newOK := agentHookConfigString(item, "new_string", "newString", "new_str")
			if !oldOK || !newOK {
				return nil, false
			}
			edits = append(edits, agentHookConfigTextEdit{old: old, new: replacement, all: agentHookConfigBool(item, "replace_all", "replaceAll")})
		}
		return []agentHookConfigChange{agentHookConfigEditChange(path, edits)}, true
	case "apply_patch", "applypatch", "apply-patch", "patch":
		for _, key := range []string{"input", "patch", "patchText", "patch_text", "command"} {
			raw, present := object[key]
			if !present {
				continue
			}
			text := ""
			switch value := raw.(type) {
			case string:
				text = value
			case []any:
				words := make([]string, 0, len(value))
				for _, word := range value {
					text, ok := word.(string)
					if !ok {
						return nil, false
					}
					words = append(words, text)
				}
				text = strings.Join(words, "\n")
			}
			if changes, ok := agentHookConfigPatchChanges(text); ok {
				return changes, true
			}
			return nil, false
		}
	}
	return nil, false
}

func agentHookConfigEditChange(path string, edits []agentHookConfigTextEdit) agentHookConfigChange {
	var text strings.Builder
	for _, edit := range edits {
		text.WriteString(edit.old)
		text.WriteString("\n")
		text.WriteString(edit.new)
		text.WriteString("\n")
	}
	return agentHookConfigChange{path: path, text: text.String(),
		after: func(read func(string) ([]byte, bool)) ([]byte, bool, bool) {
			before, exists := read(path)
			return agentHookConfigApplyEdits(before, exists, edits)
		},
	}
}

// agentHookConfigApplyEdits applies Edit and MultiEdit replacements as the
// agents do: every old text must occur (once, unless replace-all); an empty
// first old text creates a file that is missing or empty. ok is false when
// the agent would refuse the edit.
func agentHookConfigApplyEdits(before []byte, exists bool, edits []agentHookConfigTextEdit) ([]byte, bool, bool) {
	document := string(before)
	for index, edit := range edits {
		if edit.old == "" {
			if index != 0 || (exists && len(before) != 0) {
				return nil, false, false
			}
			document, exists = edit.new, true
			continue
		}
		if !exists {
			return nil, false, false
		}
		count := strings.Count(document, edit.old)
		if count == 0 || (count > 1 && !edit.all) {
			return nil, false, false
		}
		if edit.all {
			document = strings.ReplaceAll(document, edit.old, edit.new)
		} else {
			document = strings.Replace(document, edit.old, edit.new, 1)
		}
	}
	return []byte(document), exists, true
}

type agentHookConfigPatchHunk struct{ old, new []string }

// agentHookConfigPatchChanges reads one apply_patch envelope (Codex,
// OpenCode): Add File, Delete File, Update File with its hunks, and the
// move of an Update.
func agentHookConfigPatchChanges(text string) ([]agentHookConfigChange, bool) {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	begin := slices.IndexFunc(lines, func(line string) bool { return strings.HasSuffix(strings.TrimSpace(line), "*** Begin Patch") })
	if begin < 0 {
		return nil, false
	}
	var changes []agentHookConfigChange
	index := begin + 1
	for index < len(lines) {
		line := strings.TrimSpace(lines[index])
		switch {
		case strings.HasPrefix(line, "*** End Patch"):
			return changes, len(changes) > 0
		case strings.HasPrefix(line, "*** Add File: "):
			path := strings.TrimSpace(strings.TrimPrefix(line, "*** Add File: "))
			var body []string
			for index++; index < len(lines) && strings.HasPrefix(lines[index], "+"); index++ {
				body = append(body, lines[index][1:])
			}
			content := strings.Join(body, "\n") + "\n"
			changes = append(changes, agentHookConfigChange{path: path, text: content,
				after: func(func(string) ([]byte, bool)) ([]byte, bool, bool) { return []byte(content), true, true }})
		case strings.HasPrefix(line, "*** Delete File: "):
			path := strings.TrimSpace(strings.TrimPrefix(line, "*** Delete File: "))
			changes = append(changes, agentHookConfigChange{path: path,
				after: func(func(string) ([]byte, bool)) ([]byte, bool, bool) { return nil, false, true }})
			index++
		case strings.HasPrefix(line, "*** Update File: "):
			path := strings.TrimSpace(strings.TrimPrefix(line, "*** Update File: "))
			index++
			moveTo := ""
			if index < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[index]), "*** Move to: ") {
				moveTo = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[index]), "*** Move to: "))
				index++
			}
			var hunks []agentHookConfigPatchHunk
			var raw strings.Builder
			for ; index < len(lines); index++ {
				current := lines[index]
				trimmed := strings.TrimSpace(current)
				if strings.HasPrefix(trimmed, "*** ") && trimmed != "*** End of File" {
					break
				}
				raw.WriteString(current)
				raw.WriteString("\n")
				switch {
				case strings.HasPrefix(current, "@@"):
					hunks = append(hunks, agentHookConfigPatchHunk{})
				case trimmed == "*** End of File":
				default:
					if len(hunks) == 0 {
						hunks = append(hunks, agentHookConfigPatchHunk{})
					}
					hunk := &hunks[len(hunks)-1]
					switch {
					case current == "":
						hunk.old, hunk.new = append(hunk.old, ""), append(hunk.new, "")
					case current[0] == ' ':
						hunk.old, hunk.new = append(hunk.old, current[1:]), append(hunk.new, current[1:])
					case current[0] == '-':
						hunk.old = append(hunk.old, current[1:])
					case current[0] == '+':
						hunk.new = append(hunk.new, current[1:])
					default:
						return nil, false
					}
				}
			}
			source := path
			apply := func(read func(string) ([]byte, bool)) ([]byte, bool, bool) {
				before, exists := read(source)
				if !exists {
					return nil, false, false
				}
				body, ok := agentHookConfigApplyHunks(string(before), hunks)
				return []byte(body), true, ok
			}
			if moveTo == "" {
				changes = append(changes, agentHookConfigChange{path: path, text: raw.String(), after: apply})
				continue
			}
			changes = append(changes,
				agentHookConfigChange{path: path, text: raw.String(),
					after: func(func(string) ([]byte, bool)) ([]byte, bool, bool) { return nil, false, true }},
				agentHookConfigChange{path: moveTo, text: raw.String(), after: apply})
		default:
			if line != "" {
				return nil, false
			}
			index++
		}
	}
	return nil, false
}

// agentHookConfigApplyHunks applies update hunks in order, each at the
// first place after the last one where its old lines occur: exactly, then
// ignoring trailing and then surrounding white space, as apply_patch does.
func agentHookConfigApplyHunks(before string, hunks []agentHookConfigPatchHunk) (string, bool) {
	trailing := strings.HasSuffix(before, "\n")
	lines := strings.Split(strings.TrimSuffix(before, "\n"), "\n")
	if before == "" {
		lines = nil
	}
	position := 0
	for _, hunk := range hunks {
		if len(hunk.old) == 0 {
			lines = append(lines, hunk.new...)
			position = len(lines)
			continue
		}
		at := -1
		for _, normalize := range []func(string) string{
			func(line string) string { return line },
			func(line string) string { return strings.TrimRight(line, " \t") },
			strings.TrimSpace,
		} {
			for start := position; start+len(hunk.old) <= len(lines) && at < 0; start++ {
				match := true
				for offset, want := range hunk.old {
					if normalize(lines[start+offset]) != normalize(want) {
						match = false
						break
					}
				}
				if match {
					at = start
				}
			}
			if at >= 0 {
				break
			}
		}
		if at < 0 {
			return "", false
		}
		updated := append(append(append([]string(nil), lines[:at]...), hunk.new...), lines[at+len(hunk.old):]...)
		lines, position = updated, at+len(hunk.new)
	}
	body := strings.Join(lines, "\n")
	if trailing || len(lines) > 0 {
		body += "\n"
	}
	return body, true
}

// agentHookConfigDocument parses a hook file of format; nil when it does
// not parse as the agent reads it.
func agentHookConfigDocument(format string, body []byte) map[string]any {
	var document map[string]any
	switch format {
	case gatewayconnector.AgentHookConfigCodexTOML:
		if toml.Unmarshal(body, &document) != nil {
			return nil
		}
	case gatewayconnector.AgentHookConfigHermesYAML:
		if yaml.Unmarshal(body, &document) != nil {
			return nil
		}
	case gatewayconnector.AgentHookConfigClaudeSettings:
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil
		}
	default:
		normalized, err := gatewayconnector.NormalizeAgentJSONC(body)
		if err != nil {
			return nil
		}
		decoder := json.NewDecoder(bytes.NewReader(normalized))
		decoder.UseNumber()
		if decoder.Decode(&document) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil
		}
	}
	if document == nil {
		document = map[string]any{}
	}
	return document
}

// agentHookConfigFingerprint lists DefenseClaw's hook entries under the
// document's hook member: each string that names DefenseClaw, at its path
// (array positions dropped, so a reorder changes nothing), with the plain
// settings of every object above it (a matcher, a type, a timeout, args).
// An entry that is gone or changed is missing from a later fingerprint.
func agentHookConfigFingerprint(node any) map[string]int {
	out := map[string]int{}
	var walk func(value any, path, above string)
	walk = func(value any, path, above string) {
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			var plain strings.Builder
			for _, key := range keys {
				if agentHookConfigPlain(typed[key]) {
					encoded, _ := json.Marshal(typed[key])
					plain.WriteString(key + "=" + string(encoded) + ";")
				}
			}
			above += "\x1f" + path + "{" + plain.String() + "}"
			for _, key := range keys {
				walk(typed[key], path+"."+key, above)
			}
		case []any:
			for _, item := range typed {
				walk(item, path+"[]", above)
			}
		case string:
			if strings.Contains(strings.ToLower(typed), "defenseclaw") {
				out[path+"="+typed+"\x1e"+above]++
			}
		}
	}
	walk(node, "", "")
	return out
}

func agentHookConfigPlain(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		return false
	case []any:
		for _, item := range typed {
			switch item.(type) {
			case map[string]any, []any:
				return false
			}
		}
	}
	return true
}

// agentHookConfigTurnsOff names how the document a call leaves turns the
// agent's DefenseClaw hooks off, "" when it does not.
func agentHookConfigTurnsOff(format string, before []byte, beforeExists bool, after []byte, afterExists bool) string {
	if format == gatewayconnector.AgentHookConfigBridge {
		if beforeExists && (!afterExists || !bytes.Equal(before, after)) {
			return "removes or rewrites a DefenseClaw bridge plugin"
		}
		return ""
	}
	member := "hooks"
	if format == gatewayconnector.AgentHookConfigOpenCodeConfig {
		member = "plugin"
	}
	var old map[string]any
	if beforeExists {
		old = agentHookConfigDocument(format, before)
	}
	entries := map[string]int{}
	if old != nil {
		entries = agentHookConfigFingerprint(old[member])
	}
	if !afterExists {
		if len(entries) > 0 {
			return "removes the file that registers DefenseClaw's hooks"
		}
		return ""
	}
	updated := agentHookConfigDocument(format, after)
	if updated == nil {
		if len(entries) > 0 {
			return "leaves the file unreadable, so the agent drops DefenseClaw's hooks"
		}
		return ""
	}
	switch format {
	case gatewayconnector.AgentHookConfigClaudeSettings, gatewayconnector.AgentHookConfigCopilotSettings:
		keys := []string{"disableAllHooks"}
		if format == gatewayconnector.AgentHookConfigClaudeSettings {
			keys = append(keys, "allowManagedHooksOnly")
		}
		for _, key := range keys {
			// Anything but false: a value the agent's settings schema
			// refuses drops the whole file, hooks included.
			value, present := updated[key]
			if !present || value == false {
				continue
			}
			if previous, had := old[key]; had && previous != false {
				continue
			}
			return "sets " + key
		}
	case gatewayconnector.AgentHookConfigCodexTOML:
		if reason := codexHooksSwitchedOff(old, updated); reason != "" {
			return reason
		}
	case gatewayconnector.AgentHookConfigKiroSettings:
		if old != nil && !reflect.DeepEqual(old["chat.defaultAgent"], updated["chat.defaultAgent"]) {
			return "changes the Kiro default agent"
		}
	}
	if format == gatewayconnector.AgentHookConfigClaudeSettings || format == gatewayconnector.AgentHookConfigCopilotSettings {
		oldEnv, _ := old["env"].(map[string]any)
		newEnv, _ := updated["env"].(map[string]any)
		for key, value := range newEnv {
			if agentHookConfigReservedEnvValue(key, value) && !reflect.DeepEqual(oldEnv[key], value) {
				return "changes a reserved hook process environment variable"
			}
		}
	}
	remaining := agentHookConfigFingerprint(updated[member])
	for entry, count := range entries {
		if remaining[entry] < count {
			if format == gatewayconnector.AgentHookConfigOpenCodeConfig {
				return "drops the DefenseClaw bridge from the plugin list"
			}
			return "removes or changes DefenseClaw's hook entries"
		}
	}
	return ""
}

func agentHookConfigReservedEnv(key string) bool {
	upper := strings.ToUpper(key)
	if strings.HasPrefix(upper, "DEFENSECLAW_") || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
		return true
	}
	switch upper {
	case "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS":
		return true
	}
	return false
}

// agentHookConfigReservedEnvValue: NODE_OPTIONS is ordinary (memory, warnings)
// unless it preloads code into the agent.
func agentHookConfigReservedEnvValue(key string, value any) bool {
	if agentHookConfigReservedEnv(key) {
		return true
	}
	if strings.ToUpper(key) != "NODE_OPTIONS" {
		return false
	}
	text, isString := value.(string)
	if value != nil && !isString {
		return true
	}
	words := strings.Fields(text)
	for i, word := range words {
		for _, flag := range []string{"--require", "--import", "--loader", "--experimental-loader", "-r"} {
			if word == flag && i+1 < len(words) && !strings.HasPrefix(words[i+1], "-") {
				return true
			}
			if strings.HasPrefix(word, flag+"=") && len(word) > len(flag)+1 ||
				flag == "-r" && strings.HasPrefix(word, "-r") && !strings.HasPrefix(word, "--") && len(word) > 2 {
				return true
			}
		}
	}
	return false
}

// codexHooksSwitchedOff names a [features] hooks or codex_hooks switch that
// the updated Codex config turns off (anything but true), or a [features]
// that is no longer a table (Codex refuses its hooks then).
func codexHooksSwitchedOff(old, updated map[string]any) string {
	features, present := updated["features"]
	if !present {
		return ""
	}
	oldFeatures, _ := old["features"].(map[string]any)
	table, ok := features.(map[string]any)
	if !ok {
		if _, wasTable := old["features"].(map[string]any); wasTable || old == nil || old["features"] == nil {
			return "makes [features] something other than a table"
		}
		return ""
	}
	for _, key := range []string{"hooks", "codex_hooks"} {
		value, set := table[key]
		if !set {
			if oldFeatures[key] == true {
				return "removes [features] " + key + " from a nested Codex run"
			}
			continue
		}
		if value == true {
			continue
		}
		if previous, had := oldFeatures[key]; had && previous != true {
			continue
		}
		return "sets [features] " + key + " = false"
	}
	return ""
}

// agentHookConfigTextMayDisable reports call text, for a change the gateway
// cannot apply, that touches what switches the hooks off.
func agentHookConfigTextMayDisable(text string) bool {
	lower := strings.ToLower(text)
	for _, token := range []string{"disableallhooks", "allowmanagedhooksonly", "hooks", "defenseclaw", "plugin", "features"} {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// agentHookConfigFindings adds the agent hook config findings of one call
// (GAP-0048): the disable rule for a native file tool call whose document
// turns DefenseClaw off, the write rule for a shell write to a hook file.
// A rule the active pack does not hold adds nothing.
func agentHookConfigFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable ||
		request.SkipLocalFilesystemResolution || isSandboxHookRequest(ctx) {
		return findings
	}
	managed := ManagedEnterpriseActive()
	managedRaw := ""
	if managed {
		managedRaw = agentHookConfigRawShellCommand(request.Input)
		if managedRaw == "" || (!strings.Contains(managedRaw, "=") && !strings.Contains(managedRaw, "--settings") &&
			!strings.Contains(managedRaw, "--config") && !strings.Contains(managedRaw, " -c") &&
			!strings.Contains(managedRaw, "--setting-sources") && !hookpaths.RegistrationWriteCandidate(managedRaw)) {
			return findings
		}
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	out := append([]RuleFinding(nil), findings...)
	add := func(ruleID, note, target string) {
		if slices.ContainsFunc(out, func(finding RuleFinding) bool { return finding.RuleID == ruleID }) {
			return
		}
		_, rule, ok := trustedActionCatalogRule(generation, ruleID)
		if !ok {
			return
		}
		title := rule.Title
		if note != "" {
			title += " (" + note + ")"
		}
		out = append(out, RuleFinding{
			RuleID: rule.ID, Title: title, Severity: rule.Severity, Confidence: rule.Confidence,
			Evidence: filepath.Base(target), Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
			enforcement: findingEnforcementAllowed,
			proof:       newExactFallbackFindingProof(rule.ID, true, true, true, true),
		})
	}
	if managed {
		// Managed installations keep their own file policy. A literal
		// configuration change on the launched agent is still a proved
		// disablement of this call's hooks.
		parts := agentHookConfigPlacedCommands(managedRaw, request.Input.CWD, request.Input.ActiveHome, 0)
		for _, part := range parts {
			guard := newAgentHookConfigGuard(part.Dir, request.Input.ActiveHome)
			if hookpaths.RegistrationWriteCandidate(part.Command) {
				registered := agentHookConfigRegistrationPaths(guard)
				for _, path := range registered {
					if (strings.Contains(strings.ToLower(part.Command), strings.ToLower(filepath.Base(path))) ||
						strings.Contains(part.Command, "patch") || strings.Contains(part.Command, "{")) &&
						(guard.ownedFile(path) || guard.ownedFolder(path)) &&
						hookpaths.RegistrationWriteReach(part.Command, part.Dir, request.Input.ActiveHome, []string{path}) {
						add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", path)
					}
				}
			}
			if len(parts) > 1 && part.Command == managedRaw &&
				(strings.Contains(managedRaw, "cd ") || strings.Contains(managedRaw, "pushd ")) {
				continue
			}
			facts := []actionfacts.Facts{actionfacts.Analyze(actionfacts.Input{
				Tool: "Bash", Command: part.Command, CWD: part.Dir, ActiveHome: request.Input.ActiveHome,
			})}
			for _, command := range facts[0].Commands {
				if reason, target := agentHookConfigRunOverride(agentHookConfigExactWords(command), guard, facts); reason != "" {
					add(agentHookConfigDisableRuleID, reason, target)
				}
			}
			if reason, target := agentHookConfigPrefixOverrideOne(part.Command, guard); reason != "" {
				add(agentHookConfigDisableRuleID, reason, target)
			}
		}
		return out
	}
	guard := newAgentHookConfigGuard(request.Input.CWD, request.Input.ActiveHome)
	if changes, native := agentHookConfigFileChanges(request.Input.Tool, request.Input.Args); native {
		for _, change := range changes {
			if guard.ownedFile(change.path) {
				add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", change.path)
				continue
			}
			format := guard.format(change.path)
			if format == "" {
				continue
			}
			before, exists := guard.read(change.path)
			after, afterExists, ok := change.after(guard.read)
			if !ok {
				if agentHookConfigTextMayDisable(change.text) {
					add(agentHookConfigWriteRuleID, "", change.path)
				}
				continue
			}
			if reason := agentHookConfigTurnsOff(format, before, exists, after, afterExists); reason != "" {
				add(agentHookConfigDisableRuleID, reason, change.path)
			}
		}
		return out
	}
	// A shell call: its content is not read, so a write to a hook file is
	// the write rule. The hook client's resolved targets carry links the
	// command text does not name.
	for operand, resolved := range request.ResolvedWriteTargets {
		_ = operand
		if strings.HasPrefix(operand, "\x00") || !filepath.IsAbs(resolved) ||
			guard.format(resolved) == "" && !guard.ownedFile(resolved) {
			continue
		}
		if guard.ownedFile(resolved) {
			add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", resolved)
		} else {
			add(agentHookConfigWriteRuleID, "", resolved)
		}
	}
	text := strings.ToLower(request.LegacyText + "\n" + request.Input.Command + "\n" + string(request.Input.Args) + "\n" + strings.Join(request.Input.Argv, "\n"))
	if !guard.shellMentionsRegistryPath(text) &&
		!slices.ContainsFunc([]string{"git ", "patch ", "claude ", "codex ", "opencode ", "amp ", "copilot ", "kiro-cli ", "hermes ", "cursor-agent ", "devin ", "gemini ", "npx "},
			func(name string) bool { return strings.Contains(text, name) }) {
		return out
	}
	// The registration set is read by hookpaths' shared shell writer. A
	// placed statement carries its own directory, including after literal cd.
	rawCommand := agentHookConfigRawShellCommand(request.Input)
	parts := agentHookConfigPlacedCommands(rawCommand, guard.cwd, guard.home, 0)
	for _, part := range parts {
		partGuard := guard
		if part.Dir != guard.cwd {
			partGuard = newAgentHookConfigGuard(part.Dir, guard.home)
		}
		if hookpaths.RegistrationWriteCandidate(part.Command) {
			registered := agentHookConfigRegistrationPaths(partGuard)
			if hookpaths.RegistrationWriteReach(part.Command, part.Dir, guard.home, registered) {
				lowerCommand := strings.ToLower(part.Command)
				for _, path := range registered {
					if !strings.Contains(lowerCommand, strings.ToLower(filepath.Base(path))) &&
						!strings.Contains(lowerCommand, "patch") && !strings.Contains(part.Command, "{") {
						continue
					}
					if !hookpaths.RegistrationWriteReach(part.Command, part.Dir, guard.home, []string{path}) {
						continue
					}
					if partGuard.ownedFile(path) || partGuard.ownedFolder(path) {
						add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", path)
					} else {
						add(agentHookConfigWriteRuleID, "", path)
					}
				}
			}
		}
		if len(parts) > 1 && part.Command == rawCommand &&
			(strings.Contains(rawCommand, "cd ") || strings.Contains(rawCommand, "pushd ")) {
			continue
		}
		facts := []actionfacts.Facts{actionfacts.Analyze(actionfacts.Input{
			Tool: "Bash", Command: part.Command, CWD: part.Dir, ActiveHome: guard.home,
		})}
		for _, command := range facts[0].Commands {
			argv := agentHookConfigExactWords(command)
			if reason, target := agentHookConfigRunOverride(argv, partGuard, facts); reason != "" {
				add(agentHookConfigDisableRuleID, reason, target)
			} else if target != "" {
				add(agentHookConfigWriteRuleID, "", target)
			}
			if target := agentHookConfigGitTarget(argv, partGuard); target != "" {
				add(agentHookConfigWriteRuleID, "", target)
			}
		}
		if reason, target := agentHookConfigPrefixOverrideOne(part.Command, partGuard); reason != "" {
			add(agentHookConfigDisableRuleID, reason, target)
		} else if target != "" {
			add(agentHookConfigWriteRuleID, "", target)
		}
	}
	return out
}

func agentHookConfigRawShellCommand(input actionfacts.Input) string {
	if input.Command != "" {
		return input.Command
	}
	var args map[string]json.RawMessage
	if json.Unmarshal(input.Args, &args) != nil {
		return ""
	}
	for _, key := range []string{"command", "cmd"} {
		var command string
		if json.Unmarshal(args[key], &command) == nil && command != "" {
			return command
		}
	}
	return ""
}

// agentHookConfigPlacedCommands keeps each literal shell body and each
// statement's directory. All shell decisions consume this same placement.
func agentHookConfigPlacedCommands(command, cwd, home string, depth int) []hookpaths.PlacedStatement {
	if depth > 4 || command == "" || len(command) > 8192 {
		return nil
	}
	root := hookpaths.PlacedStatement{Command: command, Dir: cwd}
	out := []hookpaths.PlacedStatement{root}
	placed := []hookpaths.PlacedStatement{root}
	if strings.Contains(command, "cd ") || strings.Contains(command, "cd\t") || strings.Contains(command, "pushd ") {
		if statements, ok := hookpaths.TopLevelStatements(command, cwd, home); ok {
			placed = statements
			out = append(out, statements...)
		}
	}
	if !strings.Contains(command, "sh") {
		return out
	}
	for _, statement := range placed {
		facts := actionfacts.Analyze(actionfacts.Input{Tool: "Bash", Command: statement.Command, CWD: statement.Dir, ActiveHome: home})
		for _, fact := range facts.Commands {
			words := agentHookConfigExactWords(fact)
			static := make([]bool, len(words))
			for i := range static {
				static[i] = words[i] != "" && (i >= len(fact.Arguments) || !fact.Arguments[i].Expands)
			}
			if run, ok := actionfacts.StaticPrefixWrapperChild(words, static); ok &&
				!run.DirUnknown && run.Dir == "" && !run.ChangesResolution {
				words = words[run.Index:]
			}
			if body := hookpaths.NestedShellBody(words); body != "" {
				// A literal assignment on the shell process is inherited by
				// the agent launched in its -c body.
				if file, err := syntax.NewParser().Parse(strings.NewReader(statement.Command), ""); err == nil {
					syntax.Walk(file, func(node syntax.Node) bool {
						call, ok := node.(*syntax.CallExpr)
						if !ok {
							return true
						}
						for _, assignment := range call.Assigns {
							if assignment.Name == nil || !agentHookConfigRunHomeAssignment(assignment.Name.Value+"=x") {
								continue
							}
							if value, fixed := hookpaths.StaticWord(assignment.Value, home); fixed {
								body = assignment.Name.Value + "=" + value + " " + body
							}
						}
						return true
					})
				}
				out = append(out, agentHookConfigPlacedCommands(body, statement.Dir, home, depth+1)...)
			}
		}
	}
	return out
}

func agentHookConfigExactWords(command actionfacts.CommandFact) []string {
	if len(command.Arguments) == 0 {
		return command.Argv
	}
	words := make([]string, len(command.Arguments))
	for index, arg := range command.Arguments {
		words[index] = arg.Value
		if words[index] == "" && arg.StaticGlob != "" && !strings.ContainsAny(arg.StaticGlob, "*?[]{}$`\\") {
			words[index] = arg.StaticGlob
		}
	}
	return words
}

func agentHookConfigGitGlobalSubcommand(argv []string, guard *agentHookConfigGuard) (int, string) {
	if len(argv) < 2 || filepath.Base(argv[0]) != "git" {
		return -1, ""
	}
	root := guard.cwd
	explicitWorktree := ""
	for index := 1; index < len(argv); {
		arg := argv[index]
		switch {
		case arg == "-C" || arg == "-c" || arg == "--git-dir" || arg == "--work-tree" ||
			arg == "--namespace" || arg == "--super-prefix" || arg == "--config-env" || arg == "--exec-path":
			if index+1 >= len(argv) {
				return -1, ""
			}
			value := argv[index+1]
			if arg == "-C" {
				root = agentHookConfigGitJoin(root, value)
			}
			if arg == "--work-tree" {
				explicitWorktree = value
			}
			index += 2
		case strings.HasPrefix(arg, "-C") && len(arg) > 2:
			root = agentHookConfigGitJoin(root, arg[2:])
			index++
		case strings.HasPrefix(arg, "-c") && len(arg) > 2:
			index++
		case strings.HasPrefix(arg, "--work-tree="):
			explicitWorktree = strings.TrimPrefix(arg, "--work-tree=")
			index++
		case strings.HasPrefix(arg, "--git-dir=") || strings.HasPrefix(arg, "--namespace=") ||
			strings.HasPrefix(arg, "--super-prefix=") || strings.HasPrefix(arg, "--config-env=") ||
			strings.HasPrefix(arg, "--exec-path="):
			index++
		case arg == "--no-pager" || arg == "--paginate" || arg == "--bare" ||
			arg == "--no-optional-locks" || arg == "--no-replace-objects" || arg == "--literal-pathspecs" ||
			arg == "--glob-pathspecs" || arg == "--noglob-pathspecs" || arg == "--icase-pathspecs":
			index++
		case arg == "--":
			index++
		case strings.HasPrefix(arg, "-"):
			return -1, ""
		default:
			if explicitWorktree != "" {
				return index, agentHookConfigGitJoin(root, explicitWorktree)
			}
			for dir := root; ; dir = filepath.Dir(dir) {
				if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
					return index, dir
				}
				if dir == filepath.Dir(dir) {
					break
				}
			}
			return index, root
		}
	}
	return -1, ""
}

func agentHookConfigGitJoin(root, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	return filepath.Clean(filepath.Join(root, value))
}

func agentHookConfigGitNewBranchOnly(sub string, args []string) bool {
	for index, arg := range args {
		branchFlag := sub == "checkout" && (arg == "-b" || arg == "-B" || arg == "--orphan") ||
			sub == "switch" && (arg == "-c" || arg == "-C" || arg == "--create" || arg == "--force-create")
		if !branchFlag || index+1 >= len(args) {
			continue
		}
		for _, rest := range args[index+2:] {
			if rest == "--" || !strings.HasPrefix(rest, "-") {
				return false
			}
		}
		return true
	}
	return false
}

func agentHookConfigGitGlobReach(spec, worktree string, guard *agentHookConfigGuard) bool {
	pattern := spec
	top := false
	if strings.HasPrefix(pattern, ":(") {
		end := strings.IndexByte(pattern, ')')
		if end < 0 {
			return false
		}
		top = strings.Contains(pattern[:end], "top")
		pattern = pattern[end+1:]
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return false
	}
	for _, file := range guard.files {
		if !strings.HasPrefix(file.Path, worktree+string(filepath.Separator)) {
			continue
		}
		base := guard.cwd
		if top {
			base = worktree
		}
		rel, err := filepath.Rel(base, file.Path)
		if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		rel = filepath.ToSlash(rel)
		if matched, _ := filepath.Match(pattern, rel); matched {
			return true
		}
		if !strings.Contains(pattern, "/") {
			if matched, _ := filepath.Match(pattern, filepath.Base(rel)); matched {
				return true
			}
		}
		if suffix, ok := strings.CutPrefix(pattern, "**/"); ok {
			if matched, _ := filepath.Match(suffix, filepath.Base(rel)); matched {
				return true
			}
		}
	}
	return false
}

func agentHookConfigGitTarget(argv []string, guard *agentHookConfigGuard) string {
	index, worktree := agentHookConfigGitGlobalSubcommand(argv, guard)
	if index < 0 {
		return ""
	}
	sub := argv[index]
	args := argv[index+1:]
	// A command-local alias that expands to one known worktree writer has
	// the same path scope as spelling that subcommand directly.
	for i := 1; i < index; i++ {
		var setting string
		if argv[i] == "-c" && i+1 < index {
			setting = argv[i+1]
			i++
		} else if strings.HasPrefix(argv[i], "-c") {
			setting = strings.TrimPrefix(argv[i], "-c")
		}
		if value, ok := strings.CutPrefix(setting, "alias."+sub+"="); ok &&
			(value == "restore" || value == "checkout" || value == "switch" || value == "reset" || value == "apply") {
			sub = value
		} else if value, ok := strings.CutPrefix(setting, "alias."+sub+"=!git "); ok {
			words := strings.Fields(value)
			if len(words) > 0 {
				return agentHookConfigGitTarget(append(append([]string{"git"}, words...), args...), guard)
			}
		}
	}
	switch sub {
	case "am", "cherry-pick", "merge", "pull", "rebase", "revert", "switch", "checkout", "restore", "reset", "stash", "apply", "checkout-index":
	case "read-tree":
		if !slices.Contains(args, "-u") && !slices.ContainsFunc(args, func(arg string) bool {
			return strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "u")
		}) {
			return ""
		}
	default:
		return ""
	}
	if (sub == "checkout" || sub == "switch") && agentHookConfigGitNewBranchOnly(sub, args) {
		return ""
	}
	if sub == "stash" {
		operation := "push"
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				operation = arg
				break
			}
		}
		switch operation {
		case "pop", "apply", "branch":
		default:
			return ""
		}
	}
	if sub == "reset" && !slices.Contains(args, "--hard") && !slices.Contains(args, "--merge") && !slices.Contains(args, "--keep") {
		return ""
	}
	if sub == "restore" && slices.Contains(args, "--staged") && !slices.Contains(args, "--worktree") {
		return ""
	}
	if sub == "apply" {
		for _, option := range []string{"--check", "--cached", "--stat", "--numstat", "--summary"} {
			if slices.Contains(args, option) {
				return ""
			}
		}
		readAny, unknown := false, false
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			places := guard.places(arg)
			if len(places) == 0 {
				unknown = true
				break
			}
			patch, err := os.ReadFile(places[0])
			if err != nil || len(patch) > agentHookConfigMaxBytes {
				unknown = true
				break
			}
			target, complete := agentHookConfigPatchTarget(patch, guard)
			if target != "" {
				return target
			}
			if !complete {
				unknown = true
				break
			}
			readAny = true
		}
		if readAny && !unknown {
			return ""
		}
	}
	// An explicit pathspec may name a file currently absent from this tree.
	if sub == "restore" || (sub == "checkout" || sub == "reset") && slices.Contains(args, "--") {
		start := sub == "restore"
		saw := false
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if arg == "--" {
				start = true
				continue
			}
			if arg == "-s" || arg == "--source" || arg == "--conflict" || arg == "--pathspec-from-file" {
				i++
				continue
			}
			if !start || strings.HasPrefix(arg, "-") {
				continue
			}
			saw = true
			if agentHookConfigGitGlobReach(arg, worktree, guard) {
				return arg
			}
			candidate := arg
			if arg == ":/" {
				candidate = worktree
			} else if relative, ok := strings.CutPrefix(arg, ":(top)"); ok {
				candidate = filepath.Join(worktree, relative)
			} else if !filepath.IsAbs(arg) {
				candidate = filepath.Join(guard.cwd, arg)
			}
			candidate = filepath.Clean(candidate)
			if guard.shellTarget(candidate) || guard.ownedFile(candidate) {
				return arg
			}
			for _, file := range guard.files {
				if file.Path == candidate || strings.HasPrefix(file.Path, candidate+string(filepath.Separator)) {
					return arg
				}
			}
		}
		if saw {
			return ""
		}
	}
	pathspec := sub == "restore"
	for _, arg := range args {
		if arg == "--" {
			pathspec = true
			continue
		}
		if pathspec && !strings.HasPrefix(arg, "-") && guard.shellTarget(arg) {
			return arg
		}
	}
	// Explicit paths that exist and reach no registration file limit the
	// rewrite to them (git checkout -- foo.c, git restore foo.c).
	if sub == "checkout" || sub == "restore" || sub == "reset" {
		named := false
		for _, arg := range args {
			if arg == "--" || strings.HasPrefix(arg, "-") {
				continue
			}
			candidate := arg
			if !filepath.IsAbs(candidate) {
				candidate = filepath.Join(guard.cwd, candidate)
			}
			info, err := os.Lstat(candidate)
			if err != nil {
				continue
			}
			if guard.shellTarget(arg) || guard.ownedFile(arg) {
				return arg
			}
			if info.IsDir() {
				dir := filepath.Clean(candidate) + string(filepath.Separator)
				for _, file := range guard.files {
					if strings.HasPrefix(file.Path, dir) {
						if _, err := os.Stat(file.Path); err == nil {
							return arg
						}
					}
				}
			}
			named = true
		}
		if named {
			return ""
		}
	}
	// A worktree rewrite can restore a tracked registration document.
	for _, file := range guard.files {
		relative, err := filepath.Rel(worktree, file.Path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			if _, err := os.Stat(file.Path); err == nil {
				return file.Path
			}
		}
	}
	for _, file := range agentHookConfigProjectFiles {
		path := filepath.Join(worktree, filepath.FromSlash(strings.TrimPrefix(file.suffix, "/")))
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// agentHookConfigPatchTarget trusts a patch as unrelated only when every
// section has a recognizable file target. Unknown syntax stays opaque.
func agentHookConfigPatchTarget(patch []byte, guard *agentHookConfigGuard) (string, bool) {
	section, seen, anyPath := false, false, false
	for _, line := range strings.Split(string(patch), "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			if section && !seen {
				return "", false
			}
			section, seen = true, false
			continue
		}
		if line == "+++ /dev/null" || line == "--- /dev/null" {
			continue
		}
		for _, prefix := range []string{"+++ b/", "--- a/", "rename to ", "rename from "} {
			if path, ok := strings.CutPrefix(line, prefix); ok {
				path, _, _ = strings.Cut(path, "\t")
				path = strings.TrimSpace(path)
				if path == "" {
					return "", false
				}
				seen, anyPath = true, true
				if guard.shellTarget(path) {
					return path, true
				}
				break
			}
		}
		if (strings.HasPrefix(line, "+++ ") || strings.HasPrefix(line, "--- ")) &&
			!strings.HasPrefix(line, "+++ b/") && !strings.HasPrefix(line, "--- a/") {
			return "", false
		}
	}
	return "", anyPath && (!section || seen)
}

func agentHookConfigRunOverride(argv []string, guard *agentHookConfigGuard, facts []actionfacts.Facts) (reason, target string) {
	if len(argv) < 2 {
		return "", ""
	}
	// A quoted assignment is an ordinary shell word. Shells also accept it
	// before a command, so retain its value when the facts reader supplies it.
	if agentHookConfigRunHomeAssignment(argv[0]) {
		key, value, _ := strings.Cut(argv[0], "=")
		if agent := agentHookConfigLaunchedAgent(argv[1:]); agent != "" {
			if why := agentHookConfigLiteralHomeOverride(key, value, guard, agent); why != "" {
				return why, agent
			}
		}
		return agentHookConfigRunOverride(argv[1:], guard, facts)
	}
	program := strings.ToLower(filepath.Base(argv[0]))
	if program == "env" {
		var assignments []string
		dropsHome := false
		for index := 1; index < len(argv); index++ {
			if argv[index] == "--" {
				continue
			}
			if argv[index] == "-i" || argv[index] == "--ignore-environment" {
				dropsHome = true
				continue
			}
			if (argv[index] == "-u" || argv[index] == "--unset") && index+1 < len(argv) {
				dropsHome = dropsHome || argv[index+1] == "HOME"
				index++
				continue
			}
			if strings.HasPrefix(argv[index], "-") || strings.Contains(argv[index], "=") {
				if agentHookConfigRunHomeAssignment(argv[index]) {
					assignments = append(assignments, argv[index])
				}
				continue
			}
			reason, target = agentHookConfigRunOverride(argv[index:], guard, facts)
			if agent := agentHookConfigLaunchedAgent(argv[index:]); reason == "" && target == "" && agent != "" {
				if dropsHome && !slices.ContainsFunc(assignments, func(word string) bool { return strings.HasPrefix(word, "HOME=") }) {
					return "runs an agent without its registered hook configuration home", agent
				}
				for _, assignment := range assignments {
					key, value, _ := strings.Cut(assignment, "=")
					expected := agentHookConfigExpectedHome(key, agent, guard)
					if expected == "" {
						continue
					}
					if path, literal := agentHookConfigLiteralHomePath(value, guard); literal && path == filepath.Clean(expected) {
						continue
					}
					if why := agentHookConfigLiteralHomeOverride(key, value, guard, agent); why != "" {
						return why, agent
					}
					return "", agent
				}
			}
			return reason, target
		}
		return "", ""
	}
	if program == "exec" || program == "command" || program == "nohup" {
		return agentHookConfigRunOverride(argv[1:], guard, facts)
	}
	if program == "timeout" || program == "nice" || program == "ionice" || program == "stdbuf" || program == "time" || program == "sudo" || program == "doas" {
		for index := 1; index < len(argv); index++ {
			word := argv[index]
			if word == "--" {
				continue
			}
			if strings.HasPrefix(word, "-") {
				if (word == "-n" || word == "-u" || word == "-g" || word == "-o" || word == "-i") && index+1 < len(argv) {
					index++
				}
				continue
			}
			if (program == "timeout" || program == "nice") && index == 1 && (program == "timeout" || word[0] >= '0' && word[0] <= '9') {
				continue
			}
			return agentHookConfigRunOverride(argv[index:], guard, facts)
		}
		return "", ""
	}
	launcherStart := 0
	if program == "npx" || program == "npx.cmd" || program == "bunx" || program == "bunx.cmd" {
		launcherStart = 1
	} else if (program == "pnpm" || program == "yarn") && len(argv) > 1 && argv[1] == "dlx" {
		launcherStart = 2
	} else if program == "npm" && len(argv) > 1 && (argv[1] == "exec" || argv[1] == "x") {
		launcherStart = 2
	}
	if launcherStart > 0 {
		for index := launcherStart; index < len(argv); index++ {
			if argv[index] == "-y" || argv[index] == "--yes" || argv[index] == "--" {
				continue
			}
			if (argv[index] == "-p" || argv[index] == "--package") && index+2 < len(argv) {
				index++
				continue
			}
			packageName := argv[index]
			if at := strings.LastIndex(packageName, "@"); at > 0 {
				packageName = packageName[:at]
			}
			switch packageName {
			case "@anthropic-ai/claude-code", "claude-code", "claude":
				return agentHookConfigRunOverride(append([]string{"claude"}, argv[index+1:]...), guard, facts)
			case "@openai/codex", "codex":
				return agentHookConfigRunOverride(append([]string{"codex"}, argv[index+1:]...), guard, facts)
			}
			break
		}
	}
	format := ""
	switch program {
	case "claude", "claude.exe":
		format = gatewayconnector.AgentHookConfigClaudeSettings
	case "codex", "codex.exe":
		format = gatewayconnector.AgentHookConfigCodexTOML
	case "opencode", "opencode.exe":
		format = gatewayconnector.AgentHookConfigOpenCodeConfig
	case "amp", "kiro-cli", "hermes", "cursor-agent", "devin", "gemini":
		format = gatewayconnector.AgentHookConfigJSONHooks
	case "copilot", "copilot.exe":
		format = gatewayconnector.AgentHookConfigCopilotSettings
	default:
		return "", ""
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		value := ""
		if arg == "--setting-sources" || strings.HasPrefix(arg, "--setting-sources=") {
			if arg == "--setting-sources" && index+1 < len(argv) {
				value = argv[index+1]
			} else {
				value = strings.TrimPrefix(arg, "--setting-sources=")
			}
			if format == gatewayconnector.AgentHookConfigClaudeSettings && !strings.Contains(value, "user") {
				return "", program
			}
			continue
		}
		if arg == "--settings" || arg == "--settings-file" || arg == "--config" || arg == "-c" {
			if index+1 >= len(argv) {
				continue
			}
			value = argv[index+1]
			index++
		} else if key, rest, ok := strings.Cut(arg, "="); ok && (key == "--settings" || key == "--settings-file" || key == "--config") {
			arg, value = key, rest
		} else if strings.HasPrefix(arg, "-c") && len(arg) > 2 && format == gatewayconnector.AgentHookConfigCodexTOML {
			arg, value = "-c", arg[2:]
		} else {
			continue
		}
		if (arg == "-c" || arg == "--config") && format == gatewayconnector.AgentHookConfigCodexTOML && strings.Contains(value, "=") {
			if why := agentHookConfigInlineCodexOverride(value); why != "" {
				return why, program
			}
			if why := agentHookConfigCodexOverrideOnConfig(value, guard); why != "" {
				return why, program
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(value), "{") {
			if why := agentHookConfigTurnsOff(format, nil, false, []byte(value), true); why != "" {
				return why, program
			}
			if format == gatewayconnector.AgentHookConfigOpenCodeConfig {
				if document := agentHookConfigDocument(format, []byte(value)); document != nil {
					if plugins, present := document["plugin"]; present && len(agentHookConfigFingerprint(plugins)) == 0 {
						return "removes DefenseClaw's plugin from a nested OpenCode run", program
					}
				}
			}
			continue
		}
		if arg == "--settings" || arg == "--settings-file" || arg == "--config" {
			if agentHookConfigRunSettingsWritten(value, guard, facts) {
				return "", value
			}
			if body, readable := guard.read(value); readable {
				if why := agentHookConfigTurnsOff(format, nil, false, body, true); why != "" {
					return why, value
				}
				continue
			}
			return "", value
		}
	}
	return "", ""
}

func agentHookConfigInlineCodexOverride(value string) string {
	document := agentHookConfigDocument(gatewayconnector.AgentHookConfigCodexTOML, []byte(value))
	if document == nil {
		return ""
	}
	if reason := agentHookConfigTurnsOff(gatewayconnector.AgentHookConfigCodexTOML, nil, false, []byte(value), true); reason != "" {
		return reason
	}
	if hooks, ok := document["hooks"].(map[string]any); ok {
		for _, entry := range hooks {
			if values, ok := entry.([]any); ok && len(values) == 0 {
				return "empties hooks for a nested Codex run"
			}
		}
	}
	return ""
}

// agentHookConfigCodexOverrideOnConfig applies one -c key.path=value the way
// Codex does (the value replaces whatever is at the path) to each readable
// Codex config this call can reach, and judges the resulting document.
func agentHookConfigCodexOverrideOnConfig(value string, guard *agentHookConfigGuard) string {
	key, rhs, ok := strings.Cut(value, "=")
	if !ok {
		return ""
	}
	var path []string
	for _, part := range strings.Split(strings.TrimSpace(key), ".") {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part == "" {
			return ""
		}
		path = append(path, part)
	}
	var leaf any = strings.TrimSpace(rhs)
	var parsed map[string]any
	if toml.Unmarshal([]byte("v = "+strings.TrimSpace(rhs)), &parsed) == nil {
		leaf = parsed["v"]
	}
	for _, file := range guard.files {
		if file.Format != gatewayconnector.AgentHookConfigCodexTOML {
			continue
		}
		before, ok := guard.read(file.Path)
		if !ok {
			continue
		}
		current := agentHookConfigDocument(gatewayconnector.AgentHookConfigCodexTOML, before)
		if current == nil {
			continue
		}
		after, err := toml.Marshal(agentHookConfigSetPath(current, path, leaf))
		if err != nil {
			continue
		}
		if why := agentHookConfigTurnsOff(gatewayconnector.AgentHookConfigCodexTOML, before, true, after, true); why != "" {
			return why + " for a nested Codex run"
		}
	}
	return ""
}

// agentHookConfigSetPath returns a copy of table with path set to value.
func agentHookConfigSetPath(table map[string]any, path []string, value any) map[string]any {
	out := make(map[string]any, len(table)+1)
	for key, existing := range table {
		out[key] = existing
	}
	if len(path) == 1 {
		out[path[0]] = value
		return out
	}
	child, _ := out[path[0]].(map[string]any)
	out[path[0]] = agentHookConfigSetPath(child, path[1:], value)
	return out
}

func agentHookConfigRunHomeAssignment(word string) bool {
	key, _, ok := strings.Cut(word, "=")
	if !ok {
		return false
	}
	switch key {
	case "CLAUDE_CONFIG_DIR", "CODEX_HOME", "OPENCODE_CONFIG_DIR", "OPENCODE_CONFIG", "XDG_CONFIG_HOME", "COPILOT_HOME", "HOME", "USERPROFILE":
		return true
	}
	return false
}

func agentHookConfigLiteralHomeOverride(key, value string, guard *agentHookConfigGuard, program string) string {
	path, literal := agentHookConfigLiteralHomePath(value, guard)
	if !literal {
		return ""
	}
	expected := agentHookConfigExpectedHome(key, program, guard)
	if expected == "" || path == filepath.Clean(expected) {
		return ""
	}
	return "runs an agent with a different literal hook configuration directory"
}

func agentHookConfigLiteralHomePath(value string, guard *agentHookConfigGuard) (string, bool) {
	if guard.home == "" {
		return "", false
	}
	for _, prefix := range []string{"$HOME", "${HOME}"} {
		if value == prefix {
			value = guard.home
		} else if strings.HasPrefix(value, prefix+"/") {
			value = filepath.Join(guard.home, value[len(prefix)+1:])
		}
	}
	if strings.ContainsAny(value, "$`*?[]{}") {
		return "", false
	}
	if value == "~" {
		return filepath.Clean(guard.home), true
	}
	if strings.HasPrefix(value, "~/") {
		return filepath.Clean(filepath.Join(guard.home, value[2:])), true
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), true
	}
	return "", false
}

func agentHookConfigExpectedHome(key, program string, guard *agentHookConfigGuard) string {
	if guard.home == "" {
		return ""
	}
	agent := strings.ToLower(filepath.Base(program))
	switch key {
	case "CLAUDE_CONFIG_DIR":
		if agent == "claude" || agent == "claude.exe" {
			return filepath.Join(guard.home, ".claude")
		}
	case "CODEX_HOME":
		if agent == "codex" || agent == "codex.exe" {
			return filepath.Join(guard.home, ".codex")
		}
	case "HOME":
		if agentHookConfigRunAgent([]string{program}) {
			return guard.home
		}
	case "USERPROFILE":
		return guard.home
	case "OPENCODE_CONFIG_DIR":
		if agent == "opencode" || agent == "opencode.exe" {
			return filepath.Join(guard.home, ".config", "opencode")
		}
	case "XDG_CONFIG_HOME":
		if agent == "opencode" || agent == "opencode.exe" {
			return filepath.Join(guard.home, ".config")
		}
	case "OPENCODE_CONFIG":
		if agent == "opencode" || agent == "opencode.exe" {
			return filepath.Join(guard.home, ".config", "opencode", "opencode.json")
		}
	case "COPILOT_HOME":
		if agent == "copilot" || agent == "copilot.exe" {
			return filepath.Join(guard.home, ".copilot")
		}
	}
	return ""
}

func agentHookConfigRunAgent(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch strings.ToLower(filepath.Base(argv[0])) {
	case "claude", "claude.exe", "codex", "codex.exe", "opencode", "opencode.exe", "copilot", "copilot.exe":
		return true
	}
	return false
}

// agentHookConfigLaunchedAgent follows a literal prefix chain to the agent
// that consumes the configuration. It does not inspect later arguments.
func agentHookConfigLaunchedAgent(argv []string) string {
	for len(argv) > 0 {
		word := argv[0]
		if agentHookConfigRunHomeAssignment(word) || word == "--" {
			argv = argv[1:]
			continue
		}
		program := strings.ToLower(filepath.Base(word))
		if agentHookConfigRunAgent([]string{program}) {
			return program
		}
		switch program {
		case "exec", "command", "nohup", "env":
			argv = argv[1:]
			for len(argv) > 0 && (strings.HasPrefix(argv[0], "-") || strings.Contains(argv[0], "=")) {
				argv = argv[1:]
			}
		case "timeout", "nice", "ionice", "stdbuf", "time", "sudo", "doas":
			argv = argv[1:]
			for len(argv) > 0 && strings.HasPrefix(argv[0], "-") {
				option := argv[0]
				argv = argv[1:]
				if (option == "-n" || option == "-u" || option == "-g" || option == "-o" || option == "-i") && len(argv) > 0 {
					argv = argv[1:]
				}
			}
			if (program == "timeout" || program == "nice" && len(argv) > 0 && len(argv[0]) > 0 && argv[0][0] >= '0' && argv[0][0] <= '9') && len(argv) > 0 {
				argv = argv[1:]
			}
		case "npx", "bunx", "pnpm", "npm", "yarn":
			for _, candidate := range argv[1:] {
				candidate = strings.TrimSuffix(candidate, "@latest")
				if strings.HasPrefix(candidate, "@anthropic-ai/claude-code") || candidate == "claude-code" {
					return "claude"
				}
				if strings.HasPrefix(candidate, "@openai/codex") || candidate == "codex" {
					return "codex"
				}
			}
			return ""
		default:
			return ""
		}
	}
	return ""
}

func agentHookConfigRunSettingsWritten(raw string, guard *agentHookConfigGuard, facts []actionfacts.Facts) bool {
	settingsPlaces := guard.places(raw)
	for _, fact := range facts {
		for _, path := range fact.Paths {
			switch path.Access {
			case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			default:
				continue
			}
			for _, candidate := range guard.places(firstNonEmpty(path.Resolved, path.Normalized, path.Value)) {
				if slices.Contains(settingsPlaces, candidate) {
					return true
				}
			}
		}
	}
	return false
}

func agentHookConfigPrefixOverrideOne(command string, guard *agentHookConfigGuard) (reason, target string) {
	if len(command) > 8192 || !strings.Contains(command, "=") {
		return "", ""
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return "", ""
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, 0, len(call.Args))
		for _, word := range call.Args {
			value, fixed := hookpaths.StaticWord(word, guard.home)
			if !fixed {
				return true
			}
			words = append(words, value)
		}
		program := agentHookConfigLaunchedAgent(words)
		if program == "" {
			return true
		}
		for _, word := range words {
			if !agentHookConfigRunHomeAssignment(word) {
				break
			}
			key, value, _ := strings.Cut(word, "=")
			if why := agentHookConfigLiteralHomeOverride(key, value, guard, program); why != "" {
				reason, target = why, program
			}
		}
		for _, assignment := range call.Assigns {
			if assignment.Name != nil && agentHookConfigRunHomeAssignment(assignment.Name.Value+"=x") {
				if agentHookConfigExpectedHome(assignment.Name.Value, program, guard) == "" {
					continue
				}
				value, fixed := hookpaths.StaticWord(assignment.Value, guard.home)
				if !fixed {
					continue
				}
				if path, literal := agentHookConfigLiteralHomePath(value, guard); literal && path == filepath.Clean(agentHookConfigExpectedHome(assignment.Name.Value, program, guard)) {
					continue
				}
				if value == "" {
					target = program
					continue
				}
				if why := agentHookConfigLiteralHomeOverride(assignment.Name.Value, value, guard, program); why != "" {
					reason, target = why, program
				} else if target == "" {
					target = program
				}
			}
		}
		return true
	})
	return reason, target
}
