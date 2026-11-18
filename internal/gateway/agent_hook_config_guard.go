// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	toml "github.com/pelletier/go-toml/v2"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
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
	// placeCache holds the places of each spelling already resolved in this
	// call: the owner checks walk the whole registration set per path.
	placeCache map[string][]string
	// gitIndexRedirected is set when the call names GIT_INDEX_FILE or GIT_DIR
	// anywhere (a prefix, env, export, declare): the index git reads is then
	// not <worktree>/.git/index, so a file the tree lacks is not known to be
	// absent from the index (rel-1-0-10:GAP-0789).
	gitIndexRedirected bool
	// links are the links the shell call itself makes, read lexically (they
	// do not exist yet when the hook runs). A write operand or a git -C
	// folder under one of them names its target too (rel-1-0-10:GAP-0718).
	links hookpaths.Links
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
	for _, name := range []string{"defenseclaw-hook", ".local"} {
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
		if physical, err := seamEvalSymlinks(guard.home); err == nil && physical != guard.home {
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
			if info, err := seamStat(place); err == nil && info.IsDir() {
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
			// A volume root (/, C:\) is its own parent: the walk ends there.
			if path == g.home || path == g.cwd || filepath.Dir(path) == path ||
				strings.HasPrefix(g.home, path+string(filepath.Separator)) ||
				strings.HasPrefix(g.cwd, path+string(filepath.Separator)) {
				break
			}
			add(path)
		}
	}
	if g.home != "" {
		for _, name := range []string{"defenseclaw-hook-user", "defenseclaw-hook-post"} {
			// The folders that hold an installed hook executable are removed
			// with it (rm -rf ~/.local/bin).
			for path := filepath.Join(g.home, ".local", "bin", name); path != g.home && filepath.IsAbs(path); path = filepath.Dir(path) {
				add(path)
			}
		}
	}
	return out
}

// places are the absolute spellings of a target: as written (~ and the
// working directory applied), and the file it reaches through links.
func (g *agentHookConfigGuard) places(raw string) []string {
	if cached, ok := g.placeCache[raw]; ok {
		return cached
	}
	resolved := g.resolvePlaces(raw)
	if g.placeCache == nil {
		g.placeCache = make(map[string][]string)
	}
	g.placeCache[raw] = resolved
	return resolved
}

func (g *agentHookConfigGuard) resolvePlaces(raw string) []string {
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
		if physical, err := seamEvalSymlinks(current); err == nil {
			places = append(places, physical)
			break
		}
		// A file that does not exist yet, or a link to one: the folder it
		// lands in, through its links, and the link's own target.
		info, err := seamLstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			link, err := seamReadlink(current)
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
		if dir, err := seamEvalSymlinks(filepath.Dir(current)); err == nil {
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
	file, err := seamOpen(places[0])
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
	// edits are an Edit or MultiEdit call's replacements.
	edits []agentHookConfigTextEdit
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
	return agentHookConfigChange{path: path, text: text.String(), edits: edits,
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
func agentHookConfigFindingsAs(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	if !request.EnforcementCapable {
		return findings
	}
	if isSandboxHookRequest(ctx) {
		return sandboxAgentHookConfigFindings(ctx, request, findings)
	}
	if request.SkipLocalFilesystemResolution {
		return findings
	}
	managed := ManagedEnterpriseActive()
	managedRaw := ""
	if managed {
		managedRaw = agentHookConfigRawShellCommand(request.Input)
		if managedRaw == "" || (!strings.Contains(managedRaw, "=") && !strings.Contains(managedRaw, "--settings") &&
			!strings.Contains(managedRaw, "--config") && !strings.Contains(managedRaw, " -c") &&
			!strings.Contains(managedRaw, "--setting-sources") && !strings.Contains(managedRaw, "env ") && !hookpaths.RegistrationWriteCandidate(managedRaw)) {
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
			if len(parts) > 1 && part.Command == managedRaw &&
				(strings.Contains(managedRaw, "cd ") || strings.Contains(managedRaw, "pushd ")) {
				continue
			}
			guard := newAgentHookConfigGuard(part.Dir, request.Input.ActiveHome)
			if hookpaths.RegistrationWriteCandidate(part.Command) {
				owned, _ := agentHookConfigReachedPaths(part, guard, agentHookConfigRegistrationPaths(guard))
				for _, path := range owned {
					add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", path)
				}
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
	rawCommand := agentHookConfigRawShellCommand(request.Input)
	guard.gitIndexRedirected = agentHookConfigRedirectsGitIndex(rawCommand)
	guard.links = hookpaths.CommandLinks("Bash", rawCommand, guard.cwd, guard.home)
	// A command that spells a link only through a variable (dest=LINK; then
	// the variable as an operand) never names the registered file in its
	// text; the shared reader resolves the values the command binds, as the
	// managed route does.
	namesByVariable := agentHookConfigBindsValues(rawCommand) && hookpaths.RegistrationWriteCandidate(rawCommand)
	if !guard.shellMentionsRegistryPath(text) && !namesByVariable &&
		!slices.ContainsFunc([]string{"git ", "patch ", "claude ", "codex ", "opencode ", "amp ", "copilot ", "kiro-cli ", "hermes ", "cursor-agent ", "devin ", "gemini ", "npx "},
			func(name string) bool { return strings.Contains(text, name) }) {
		return out
	}
	// The registration set is read by hookpaths' shared shell writer. A
	// placed statement carries its own directory, including after literal cd.
	parts := agentHookConfigPlacedCommands(rawCommand, guard.cwd, guard.home, 0)
	for _, part := range parts {
		if len(parts) > 1 && part.Command == rawCommand &&
			(strings.Contains(rawCommand, "cd ") || strings.Contains(rawCommand, "pushd ")) {
			continue
		}
		partGuard := guard
		if part.Dir != guard.cwd {
			partGuard = newAgentHookConfigGuard(part.Dir, guard.home)
			partGuard.gitIndexRedirected = guard.gitIndexRedirected
			partGuard.links = guard.links
		}
		// Every write operand the shell reading names is judged as the
		// managed route judges the resolved targets of the hook client: a
		// hook file of any project folder (agentHookConfigProjectFiles) or
		// of the home, as written and through a link the call makes. The
		// registration set below lists only the folders from the working
		// directory up to the home, so a write into another project folder,
		// or one that a cd the walk cannot place (cd $W) leaves in no listed
		// folder, reached none of it (rel-1-0-10:GAP-0718).
		for _, operand := range agentHookConfigShellWriteOperands(part.Command, part.Dir, guard.home) {
			for _, place := range append([]string{operand}, guard.links.AliasTargets(operand, false)...) {
				if guard.ownedFile(place) {
					add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", place)
				} else if guard.format(place) != "" {
					add(agentHookConfigWriteRuleID, "", place)
				}
			}
		}
		if hookpaths.RegistrationWriteCandidate(part.Command) {
			registered := agentHookConfigRegistrationPaths(partGuard)
			owned, other := agentHookConfigReachedPaths(part, partGuard, registered)
			for _, path := range owned {
				add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", path)
			}
			for _, path := range other {
				add(agentHookConfigWriteRuleID, "", path)
			}
			if folder := hookpaths.RegistrationArchivePossibleReach(part.Command, part.Dir, guard.home, registered); folder != "" {
				add(agentHookConfigWriteRuleID, "archive may replace a registered hook file", folder)
			}
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
		// The command facts carry the words after the assignments, so the
		// worktree a command-local GIT_DIR / GIT_WORK_TREE names is read
		// from the statement's own syntax.
		for _, argv := range agentHookConfigGitAssignedCommands(part.Command, guard.home) {
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

// sandboxAgentHookConfigFindings is the agent hook config guard of a sandbox
// call, by path alone (GAP-0282). The host guard (agentHookConfigFindingsAs)
// reads hook files, and resolves their links, on this host's file system,
// which a sandbox's paths never name, so it skips every sandbox request. The
// sandbox's own agent cannot be switched off through these files: its managed
// drop-in sets allowManagedHooksOnly. The threat is the pull-back: the
// project an actor writes is pulled into the person's laptop project, where
// a .claude/settings.json or another hook file planted in it takes effect in
// an agent without that lock, and where the laptop never sees an agent write
// it. Sandbox writes to a hook file of a project folder or of the guest home
// are judged by their lexical path in the guest's namespace, with no read of
// this host and no link followed:
//   - a native file tool call carries the document it leaves, so it keeps the
//     laptop's content judgment: a document that turns the hooks off is
//     tamper.agent_hook_config_disable, which blocks as on the laptop; one the
//     gateway cannot apply without the file (an Edit) whose text may turn them
//     off is tamper.agent_hook_config_write; any other document adds nothing;
//   - a shell write, whose content is not known, is
//     tamper.agent_hook_config_write as an alert only, never a block.
//
// The guard only adds findings. A file the laptop would read first is judged
// without that file, except the per-user file where the connector's setup
// registers DefenseClaw's hooks on the laptop
// (sandboxAgentHookRegistrations): a change there is judged against
// synthetic copies of that file, as the laptop judges its own (GAP-0433,
// GAP-0536).
func sandboxAgentHookConfigFindings(ctx context.Context, request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	ruleID, note, target := sandboxAgentHookConfigChange(request)
	if target == "" ||
		slices.ContainsFunc(findings, func(finding RuleFinding) bool { return finding.RuleID == ruleID }) {
		return findings
	}
	generation := snapshotRulePackGenerationFor(ctx, request.Connector)
	if generation == nil {
		return findings
	}
	_, rule, ok := trustedActionCatalogRule(generation, ruleID)
	if !ok {
		return findings
	}
	title := rule.Title
	enforcement := findingEnforcementAllowed
	if ruleID == agentHookConfigWriteRuleID && note == "" {
		enforcement = findingEnforcementAlertOnly
	}
	if note != "" {
		title += " (" + note + ")"
	}
	return append(append([]RuleFinding(nil), findings...), RuleFinding{
		RuleID: rule.ID, Title: title, Severity: rule.Severity, Confidence: rule.Confidence,
		Evidence: path.Base(target), Tags: append([]string(nil), rule.Tags...), LineNumber: 1,
		enforcement: enforcement,
		proof:       newExactFallbackFindingProof(rule.ID, true, true, true, true),
	})
}

// sandboxAgentHookConfigChange is the rule, its note and the hook file of the
// change a sandbox call makes, in the guest's namespace; target is "" when it
// changes none (sandboxAgentHookConfigFindings). note is set for a native
// tool call's document.
func sandboxAgentHookConfigChange(request trustedActionRequest) (ruleID, note, target string) {
	input := request.Input
	if request.SandboxGuestCWD != "" {
		input.CWD = request.SandboxGuestCWD
	}
	if changes, native := agentHookConfigFileChanges(input.Tool, input.Args); native {
		noRead := func(string) ([]byte, bool) { return nil, false }
		for _, change := range changes {
			target := strings.TrimSpace(change.path)
			// "~" is the guest's HOME, as the laptop guard reads it
			// against the account home (resolvePlaces).
			if home := input.ActiveHome; path.IsAbs(home) && (target == "~" || strings.HasPrefix(target, "~/")) {
				target = path.Join(home, target[1:])
			}
			if !path.IsAbs(target) && path.IsAbs(input.CWD) {
				target = path.Join(input.CWD, target)
			}
			format := sandboxAgentHookConfigFormat(target, input.ActiveHome)
			if format == "" {
				continue
			}
			if copies := sandboxAgentHookRegisteredCopies(request.Connector, target, input.ActiveHome); len(copies) > 0 {
				reason, judged := sandboxAgentHookRegisteredChange(format, change, copies, sandboxAgentHookRegisteredText(request.Connector))
				if reason != "" {
					return agentHookConfigDisableRuleID, reason + "; " + sandboxManagedHooksNote, target
				}
				if judged {
					continue
				}
			}
			after, afterExists, ok := change.after(noRead)
			if !ok {
				if agentHookConfigTextMayDisable(change.text) {
					return agentHookConfigWriteRuleID, "may turn the hooks off", target
				}
				continue
			}
			if reason := agentHookConfigTurnsOff(format, nil, false, after, afterExists); reason != "" {
				return agentHookConfigDisableRuleID, reason, target
			}
		}
		return "", "", ""
	}
	facts := actionfacts.Analyze(input)
	for _, candidate := range facts.Paths {
		switch candidate.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		default:
			continue
		}
		target := strings.TrimSpace(candidate.Resolved)
		if target == "" {
			target = strings.TrimSpace(candidate.Value)
		}
		if sandboxAgentHookConfigFormat(target, input.ActiveHome) != "" {
			return agentHookConfigWriteRuleID, "", target
		}
	}
	// Inline code (python3 -c "open(PATH, 'w')"), and the other writers the
	// path facts do not list, are read by the shared shell writer as the
	// laptop reads them (agentHookConfigReachedPaths), against the hook files
	// of the guest home and of the working folder and its parents
	// (substrate-1:GAP-0578).
	// The guest paths are not this host's; a stat of one that exists here
	// only adds this alert.
	if command := agentHookConfigRawShellCommand(input); command != "" && path.IsAbs(input.CWD) && path.IsAbs(input.ActiveHome) &&
		sandboxAgentHookConfigMentioned(command) && hookpaths.RegistrationWriteCandidate(command) {
		names := sandboxAgentHookConfigNames(input.CWD, input.ActiveHome)
		if reached := hookpaths.RegistrationWriteReached(command, input.CWD, input.ActiveHome, names); len(reached) > 0 {
			return agentHookConfigWriteRuleID, "", reached[0]
		}
		handed, _ := hookpaths.InlineHandedPaths(command, input.CWD, input.ActiveHome)
		for _, word := range handed {
			if !word.Dynamic && sandboxAgentHookConfigFormat(word.Path, input.ActiveHome) != "" {
				return agentHookConfigWriteRuleID, "", word.Path
			}
		}
	}
	return "", "", ""
}

// sandboxAgentHookConfigNames are the guest paths of the hook files a shell
// write is judged against: the per-user ones under the guest home and the
// project ones in the working folder and each folder above it.
func sandboxAgentHookConfigNames(cwd, home string) []string {
	var names []string
	for _, file := range agentHookConfigHomeFiles {
		names = append(names, path.Join(append([]string{path.Clean(home)}, file.parts...)...))
	}
	for folder := path.Clean(cwd); ; folder = path.Dir(folder) {
		for _, file := range agentHookConfigProjectFiles {
			if name := path.Join(folder, file.suffix); !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
		if folder == "/" {
			return names
		}
	}
}

// sandboxAgentHookConfigMentioned is the cheap prefilter of that reading: the
// command names a folder or file name of a hook file (sandboxAgentHookConfigNames).
func sandboxAgentHookConfigMentioned(command string) bool {
	var parts []string
	for _, file := range agentHookConfigHomeFiles {
		parts = append(parts, file.parts...)
	}
	for _, file := range agentHookConfigProjectFiles {
		parts = append(parts, strings.Split(strings.TrimPrefix(file.suffix, "/"), "/")...)
	}
	return slices.ContainsFunc(parts, func(part string) bool { return len(part) > 2 && strings.Contains(command, part) })
}

// sandboxAgentHookRegistrations are, per connector, the per-user files under
// the home where the connector's per-user setup registers DefenseClaw's hooks
// on a laptop (Claude Code: claudeCodeSettingsPath), with the "hooks" member
// that setup writes there. An actor keeps its hooks in managed settings, so
// its own copy holds none, and the gateway does not read it; the laptop reads
// its copy and blocks a change that drops or changes them (GAP-0433).
var sandboxAgentHookRegistrations = map[string]struct {
	files []string
	hooks string
}{
	"claudecode": {
		files: []string{".claude/settings.json"},
		hooks: `{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"~/.defenseclaw/hooks/claude-code-hook.sh","timeout":30}]}]}`,
	},
}

// sandboxAgentHookRegisteredCopies are, for a guest path that is under the
// guest home a file where connector registers DefenseClaw's hooks on a
// laptop, synthetic copies of that file as the laptop holds it: the
// registered hooks in the key order the hook docs use, compact, and as
// setup's encoder writes them (sorted keys, compact and indented). nil for
// any other path.
func sandboxAgentHookRegisteredCopies(connector, target, home string) [][]byte {
	registration, known := sandboxAgentHookRegistrations[connector]
	if !known || !path.IsAbs(home) {
		return nil
	}
	if !slices.ContainsFunc(registration.files, func(name string) bool {
		return path.Clean(target) == path.Join(path.Clean(home), name)
	}) {
		return nil
	}
	copies := [][]byte{[]byte(`{"hooks":` + registration.hooks + `}`)}
	var hooks any
	if json.Unmarshal([]byte(registration.hooks), &hooks) != nil {
		return copies
	}
	document := map[string]any{"hooks": hooks}
	if compact, err := json.Marshal(document); err == nil {
		copies = append(copies, compact)
	}
	if indented, err := json.MarshalIndent(document, "", "  "); err == nil {
		copies = append(copies, indented)
	}
	return copies
}

// sandboxAgentHookText is what a connector's registered hook entries are
// written with (sandboxAgentHookRegisteredText).
type sandboxAgentHookText struct {
	// words are the whole words: every key of the registered hooks member,
	// every event a hook contract of the connector registers, and the keys
	// that switch the hooks off. Matched as spelled: the agent reads its
	// keys that way, so an edit that renames one names it as written.
	words []string
	// values are the registered strings that are not one word ("*", the
	// hook command's file name), matched as substrings.
	values []string
}

var sandboxAgentHookTexts sync.Map

// sandboxAgentHookRegisteredText is the text of connector's registered hook
// entries (sandboxAgentHookRegistrations), read once per connector.
func sandboxAgentHookRegisteredText(connector string) sandboxAgentHookText {
	if cached, ok := sandboxAgentHookTexts.Load(connector); ok {
		return cached.(sandboxAgentHookText)
	}
	text := sandboxAgentHookText{words: []string{"disableAllHooks", "allowManagedHooksOnly"}}
	addWord := func(word string) {
		if word != "" && !slices.Contains(text.words, word) {
			text.words = append(text.words, word)
		}
	}
	var hooks any
	if registration, known := sandboxAgentHookRegistrations[connector]; known && json.Unmarshal([]byte(registration.hooks), &hooks) == nil {
		addWord("hooks")
		var walk func(value any)
		walk = func(value any) {
			switch typed := value.(type) {
			case map[string]any:
				for key, item := range typed {
					addWord(key)
					walk(item)
				}
			case []any:
				for _, item := range typed {
					walk(item)
				}
			case string:
				switch words := agentHookConfigWords(typed); {
				case len(words) == 1 && words[0] == typed:
					addWord(typed)
				case typed == "*":
					text.values = append(text.values, `"*"`)
				default:
					text.values = append(text.values, path.Base(typed))
				}
			}
		}
		walk(hooks)
	}
	for _, contract := range gatewayconnector.KnownHookContracts(connector) {
		for _, event := range contract.Events {
			addWord(event)
		}
	}
	sandboxAgentHookTexts.Store(connector, text)
	return text
}

// sandboxManagedHooksNote tells the person why a change to the actor's
// registered hook file is refused and what to do instead (GAP-0433, lead
// ruling: the actor is stricter than the laptop here in 1.0.10).
const sandboxManagedHooksNote = "in an actor DefenseClaw's hooks are managed by root-owned settings, so this file must keep DefenseClaw's hook entries as written: change other keys with Edit, or ask your administrator to change the managed settings"

// sandboxAgentHookRegisteredChange judges a change to a file that holds
// DefenseClaw's hooks on the laptop as the laptop judges it, against
// synthetic copies of that file (sandboxAgentHookRegisteredCopies): the
// change is applied to each copy it applies to and the laptop's before/after
// comparison (agentHookConfigTurnsOff) names how it turns them off. A Write
// that does not keep the registered entries (a decoy that only names
// DefenseClaw), an Edit that rewrites the hook command (kept old text
// included), renames the hooks or event key, or adds a later key that
// overrides them, all change the fingerprint.
//
// An Edit or MultiEdit that applies to no copy as a whole edits text the
// copies do not hold (another key, or the hooks in another layout), which
// the laptop applies to its own file (substrate-1:GAP-0577):
//   - each edit alone, and the edits in order that apply (each prefix), are
//     judged against each copy; so are the edits with the whitespace outside
//     strings dropped, and the change against each copy that also holds an
//     edit's old text as another member;
//   - an edit that applies to no copy alone and names what the registered
//     entries are written with, cuts into a word that may be one of them, or
//     names no key or string at all, or that sets a reserved hook process
//     variable, is taken to change them (sandboxAgentHookEditMayChangeHooks):
//     the actor is stricter than the laptop here (lead ruling).
//
// judged is false only for a change that applies to no copy and that the
// agent refuses on the laptop's file (an empty old text).
func sandboxAgentHookRegisteredChange(format string, change agentHookConfigChange, copies [][]byte, text sandboxAgentHookText) (reason string, judged bool) {
	for _, before := range copies {
		read := func(string) ([]byte, bool) { return before, true }
		after, afterExists, ok := change.after(read)
		if !ok {
			continue
		}
		judged = true
		if reason := agentHookConfigTurnsOff(format, before, true, after, afterExists); reason != "" {
			return reason, true
		}
	}
	if judged || len(change.edits) == 0 ||
		slices.ContainsFunc(change.edits, func(edit agentHookConfigTextEdit) bool { return edit.old == "" }) {
		return "", judged
	}
	placed := make([]bool, len(change.edits))
	// judge applies each edit alone (marking those that apply when mark is
	// set) and then the edits in order, skipping those that do not apply,
	// judging every document that leaves.
	judge := func(before []byte, edits []agentHookConfigTextEdit, mark, steps bool) string {
		for index := range edits {
			after, exists, ok := agentHookConfigApplyEdits(before, true, edits[index:index+1])
			if !ok {
				continue
			}
			if mark {
				placed[index] = true
			}
			if reason := agentHookConfigTurnsOff(format, before, true, after, exists); reason != "" {
				return reason
			}
		}
		document, moved := before, false
		for index := range edits {
			after, _, ok := agentHookConfigApplyEdits(document, true, edits[index:index+1])
			if !ok {
				continue
			}
			document, moved = after, true
			if steps {
				if reason := agentHookConfigTurnsOff(format, before, true, document, true); reason != "" {
					return reason
				}
			}
		}
		if moved && !steps {
			return agentHookConfigTurnsOff(format, before, true, document, true)
		}
		return ""
	}
	for _, before := range copies {
		if reason := judge(before, change.edits, true, true); reason != "" {
			return reason, true
		}
	}
	for _, inside := range []bool{false, true} {
		compact := make([]agentHookConfigTextEdit, len(change.edits))
		for index, edit := range change.edits {
			compact[index] = agentHookConfigTextEdit{old: agentHookConfigDropLayout(edit.old, inside), new: agentHookConfigDropLayout(edit.new, inside), all: edit.all}
		}
		if slices.Equal(compact, change.edits) || slices.ContainsFunc(compact, func(edit agentHookConfigTextEdit) bool { return edit.old == "" }) {
			continue
		}
		for _, before := range copies {
			if reason := judge(before, compact, false, true); reason != "" {
				return reason, true
			}
		}
	}
	for _, edit := range change.edits {
		for _, before := range copies {
			for _, held := range sandboxAgentHookCopiesHolding(before, edit.old) {
				if reason := judge(held, change.edits, false, false); reason != "" {
					return reason, true
				}
			}
		}
	}
	for index, edit := range change.edits {
		if placed[index] {
			continue
		}
		if sandboxAgentHookSetsReservedEnv(edit) {
			return "changes a reserved hook process environment variable", true
		}
		if sandboxAgentHookEditMayChangeHooks(edit, text) {
			return "removes or changes DefenseClaw's hook entries", true
		}
	}
	return "", true
}

// agentHookConfigWords are the words of text: its runs of letters, digits
// and underscores.
func agentHookConfigWords(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool { return !agentHookConfigWordByte(r) })
}

func agentHookConfigWordByte(r rune) bool {
	return r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
}

// agentHookConfigDropLayout drops the whitespace outside JSON strings from an
// edit's text, read as starting inside a string or not: the same text in
// the layout the synthetic copies use.
func agentHookConfigDropLayout(text string, inside bool) string {
	var out strings.Builder
	escaped := false
	for index := 0; index < len(text); index++ {
		char := text[index]
		switch {
		case inside && escaped:
			escaped = false
		case inside && char == '\\':
			escaped = true
		case char == '"':
			inside = !inside
		case !inside && (char == ' ' || char == '\t' || char == '\n' || char == '\r'):
			continue
		}
		out.WriteByte(char)
	}
	return out.String()
}

// sandboxAgentHookCopiesHolding are the copy with member, an edit's old
// text, added as another member before or after its hooks: the laptop's
// file holds that text too. Only the forms that stay a JSON document.
func sandboxAgentHookCopiesHolding(copy []byte, member string) [][]byte {
	body := bytes.TrimSpace(copy)
	member = strings.TrimSpace(member)
	if len(body) < 2 || body[0] != '{' || body[len(body)-1] != '}' || member == "" {
		return nil
	}
	inner := string(body[1 : len(body)-1])
	var held [][]byte
	for _, candidate := range []string{
		"{" + member + "," + inner + "}",
		"{" + strings.TrimSuffix(member, ",") + "," + inner + "}",
		"{" + inner + "," + member + "}",
		"{" + inner + "," + strings.TrimPrefix(member, ",") + "}",
	} {
		if json.Valid([]byte(candidate)) && !slices.ContainsFunc(held, func(seen []byte) bool { return string(seen) == candidate }) {
			held = append(held, []byte(candidate))
		}
	}
	return held
}

// sandboxAgentHookEnvPair is one "KEY": "value" pair of an edit's text.
var sandboxAgentHookEnvPair = lazyregexp.New(`"([^"\\]+)"\s*:\s*("(?:[^"\\]|\\.)*")`)

// sandboxAgentHookSetsReservedEnv reports whether an edit's new text sets a
// reserved hook process variable (agentHookConfigReservedEnvValue) its old
// text did not set to that value, as the laptop reads the env member.
func sandboxAgentHookSetsReservedEnv(edit agentHookConfigTextEdit) bool {
	for _, match := range sandboxAgentHookEnvPair.FindAllStringSubmatch(edit.new, -1) {
		var value string
		if json.Unmarshal([]byte(match[2]), &value) != nil {
			continue
		}
		if agentHookConfigReservedEnvValue(match[1], value) && !strings.Contains(edit.old, match[0]) {
			return true
		}
	}
	return false
}

// sandboxAgentHookEditMayChangeHooks reports whether an edit that applies to
// no synthetic copy may still change the registered entries in the laptop's
// own file, where they may be laid out otherwise:
//   - its old or new text names DefenseClaw, a word or a value of the
//     registered entries (sandboxAgentHookRegisteredText);
//   - an end of the edit changes a word the edit's text only partly holds
//     (old "ToolUse" for PreToolUse), or appends to the word before or after
//     it (old `" :[` new `Off" :[`), and that word may be one of them;
//   - its old text names no key, string or word beyond true, false, null and
//     numbers (`" :[{`, `30`), so where it lands is not known.
func sandboxAgentHookEditMayChangeHooks(edit agentHookConfigTextEdit, text sandboxAgentHookText) bool {
	if edit.old == edit.new {
		return false
	}
	for _, side := range []string{edit.old, edit.new} {
		if strings.Contains(strings.ToLower(side), "defenseclaw") ||
			slices.ContainsFunc(text.values, func(value string) bool { return strings.Contains(side, value) }) ||
			slices.ContainsFunc(agentHookConfigWords(side), func(word string) bool { return slices.Contains(text.words, word) }) {
			return true
		}
	}
	lead := func(side string) string {
		end := 0
		for end < len(side) && agentHookConfigWordByte(rune(side[end])) {
			end++
		}
		return side[:end]
	}
	trail := func(side string) string {
		start := len(side)
		for start > 0 && agentHookConfigWordByte(rune(side[start-1])) {
			start--
		}
		return side[start:]
	}
	if oldLead, newLead := lead(edit.old), lead(edit.new); oldLead != newLead {
		if oldLead == "" || slices.ContainsFunc(text.words, func(word string) bool {
			return strings.HasSuffix(word, oldLead) || oldLead == edit.old && strings.Contains(word, oldLead)
		}) {
			return true
		}
	}
	if oldTrail, newTrail := trail(edit.old), trail(edit.new); oldTrail != newTrail {
		if oldTrail == "" || slices.ContainsFunc(text.words, func(word string) bool { return strings.HasPrefix(word, oldTrail) }) {
			return true
		}
	}
	return !slices.ContainsFunc(agentHookConfigWords(edit.old), func(word string) bool {
		switch word {
		case "true", "false", "null":
			return false
		}
		return strings.Trim(word, "0123456789") != ""
	})
}

// sandboxAgentHookConfigFormat is the hook-file format of a sandbox path by
// its spelling alone: a project hook file (agentHookConfigProjectFiles) in
// any folder, or a per-user one (agentHookConfigHomeFiles) under the guest
// home. Sandboxes run Linux, so names are matched as spelled.
func sandboxAgentHookConfigFormat(target, home string) string {
	if !path.IsAbs(target) {
		return ""
	}
	target = path.Clean(target)
	for _, file := range agentHookConfigProjectFiles {
		if strings.HasSuffix(target, file.suffix) {
			return file.format
		}
	}
	if home = path.Clean(home); path.IsAbs(home) {
		for _, file := range agentHookConfigHomeFiles {
			if target == path.Join(append([]string{home}, file.parts...)...) {
				return file.format
			}
		}
	}
	return ""
}

// agentHookConfigShellWriteOperands lists the absolute write operands of a
// shell statement: the literal writers (cp, tee, mv, install, ...) and the
// output redirects, read in the directory of the statement.
func agentHookConfigShellWriteOperands(command, dir, home string) []string {
	if !filepath.IsAbs(dir) {
		return nil
	}
	operands := hookpaths.LiteralWriteOperands(command, dir, home)
	if strings.Contains(command, ">") {
		redirects, _, _ := hookpaths.ShellWriteOperands(command, dir, home)
		operands = append(operands, redirects...)
	}
	var out []string
	for _, operand := range operands {
		if filepath.IsAbs(operand) && !slices.Contains(out, operand) {
			out = append(out, operand)
		}
	}
	return out
}

// agentHookConfigReachedPaths lists the registered paths a statement writes,
// split into installed DefenseClaw artifacts (and the folders that hold them)
// and the other registration documents. The set is narrowed by halves in one
// reader, so only a statement that reaches it pays more than one read,
// whatever spelling (brace, glob, loop, find) names the path.
func agentHookConfigReachedPaths(part hookpaths.PlacedStatement, guard *agentHookConfigGuard, registered []string) (owned, other []string) {
	for _, path := range hookpaths.RegistrationWriteReached(part.Command, part.Dir, guard.home, registered) {
		if guard.ownedFile(path) || guard.ownedFolder(path) {
			owned = append(owned, path)
		} else {
			other = append(other, path)
		}
	}
	// Code that is not proven read-only is handed a hook config by a runner
	// the shared reader does not follow (sudo find -exec, su -c, ssh, uv run,
	// sh -c with $0 or $1, a brace word): the hand-off reading judges it
	// (rel-1-0-10:GAP-0365).
	handed, _ := hookpaths.InlineHandedPaths(part.Command, part.Dir, guard.home)
	for _, word := range handed {
		switch {
		case !word.Dynamic:
			if (slices.Contains(registered, word.Path) || guard.format(word.Path) != "") && !slices.Contains(other, word.Path) &&
				!slices.Contains(owned, word.Path) {
				other = append(other, word.Path)
			}
		default:
			for _, name := range registered {
				if hookpaths.CommandMentionsPath(part.Command, guard.home, name) && !slices.Contains(other, name) &&
					!slices.Contains(owned, name) {
					other = append(other, name)
				}
			}
		}
	}
	return owned, other
}

// agentHookConfigBindsValues reports whether a command can carry a name in a
// shell variable of its own: it expands one and binds one (an assignment, a
// loop, read, mapfile, readarray or printf -v). A command that only expands
// the environment names no path the reader could resolve beyond its text.
func agentHookConfigBindsValues(command string) bool {
	return strings.Contains(command, "$") &&
		slices.ContainsFunc([]string{"=", "for", "read", "mapfile", "readarray", "printf"},
			func(binder string) bool { return strings.Contains(command, binder) })
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
	// Any other key the trusted-action parser reads as the command (agy
	// run_command's CommandLine): read only under command and cmd, an
	// Antigravity command that stops or disables DefenseClaw, or rewrites an
	// agent's hook configuration, raised no guard finding where every other
	// hook connector blocks it.
	if command, ok := trustedShellCommandArgument(input.Args); ok {
		return command
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
				if file, err := syntax.NewParser().Parse(shellparse.Reader(statement.Command), ""); err == nil {
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

// agentHookConfigGitAssignedCommands lists the git commands of a statement
// that carry command-local assignments, each as its assignments followed by
// its words, the order agentHookConfigGitTarget reads.
func agentHookConfigGitAssignedCommands(command, home string) [][]string {
	if !strings.Contains(command, "git") || !strings.Contains(command, "=") {
		return nil
	}
	file, err := syntax.NewParser().Parse(shellparse.Reader(command), "")
	if err != nil {
		return nil
	}
	var out [][]string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Assigns) == 0 || len(call.Args) < 2 || len(out) >= 8 {
			return true
		}
		var argv []string
		for _, assignment := range call.Assigns {
			if assignment.Name == nil || assignment.Value == nil {
				return true
			}
			value, fixed := hookpaths.StaticWord(assignment.Value, home)
			if !fixed {
				return true
			}
			argv = append(argv, assignment.Name.Value+"="+value)
		}
		for _, word := range call.Args {
			value, fixed := hookpaths.StaticWord(word, home)
			if !fixed {
				return true
			}
			argv = append(argv, value)
		}
		out = append(out, argv)
		return true
	})
	return out
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
			// A folder that is a link this call makes is read at its target
			// (rel-1-0-10:GAP-0718). A target the hook cannot read now (not
			// on disk yet, or in a folder that a cd the walk cannot place
			// left the call in) is an unreadable worktree: it is returned as
			// is, and agentHookConfigGitTarget counts it as GAP-0572 counts
			// an unreadable folder.
			if _, err := os.Stat(root); err != nil {
				targets := guard.links.AliasTargets(root, false)
				for _, target := range targets {
					if info, err := os.Stat(target); err == nil && info.IsDir() {
						root = target
						break
					}
				}
				if _, err := os.Stat(root); err != nil && len(targets) > 0 {
					return index, root
				}
			}
			for dir := root; ; dir = filepath.Dir(dir) {
				if _, err := seamLstat(filepath.Join(dir, ".git")); err == nil {
					return index, dir
				}
				if dir == filepath.Dir(dir) {
					break
				}
			}
			// Without a repository there is no tracked registration file for
			// this Git call to rewrite. A worktree supplied explicitly above
			// remains eligible even when it is outside the hook directory.
			return -1, ""
		}
	}
	return -1, ""
}

// agentHookConfigAssignment is a leading NAME=value word of a command.
func agentHookConfigAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		letter := c == 0x5f || c >= 0x41 && c <= 0x5a || c >= 0x61 && c <= 0x7a
		if !letter && (i == 0 || c < 0x30 || c > 0x39) {
			return false
		}
	}
	return true
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

// agentHookConfigPathspecFolderHolds reports a registration file that a
// pathspec naming its folder (git checkout -- ., git restore src) can
// rewrite. guard.files lists every name a registration file could have from
// the cwd up to the home, so a folder pathspec reaches one only where the
// file is there. The reading holds only where the content comes from the
// index (fromIndex: no tree-ish, no --source, no --staged): that rewrites
// the files the index tracks, and recreates a tracked file that was deleted
// from the tree, but no file that is absent from both (rel-1-0-10:GAP-0572).
// A named ref or tree (git checkout other -- ., git restore --source=other .)
// brings in whatever files the ref holds, a settings file the tree lacks
// included, so every registration name under the folder counts
// (rel-1-0-10:GAP-0716). A pathspec that names the file itself is read as
// before. Where the folder cannot be read (a gateway behind ProtectHome, a
// closed folder) or the index is not understood, the file is not known absent
// and is counted.
func agentHookConfigPathspecFolderHolds(folder, path, worktree string, fromIndex bool) bool {
	if !fromIndex {
		return true
	}
	if info, err := os.Stat(folder); err != nil || !info.IsDir() {
		return true
	}
	if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
		return true
	}
	return agentHookConfigGitIndexMayTrack(worktree, path)
}

// agentHookConfigRedirectsGitIndex reports a call that names GIT_INDEX_FILE
// or GIT_DIR, the two variables that move the index git reads away from
// <worktree>/.git/index (rel-1-0-10:GAP-0789). Their value is not read: the
// index it names is not the one agentHookConfigGitIndexMayTrack opens.
func agentHookConfigRedirectsGitIndex(command string) bool {
	return strings.Contains(command, "GIT_INDEX_FILE") || strings.Contains(command, "GIT_DIR")
}

// agentHookConfigGitFromIndex reports a git checkout or restore whose
// files come from the index: a checkout with no word before -- (a branch or
// tree-ish, or the value of -b, -B, --orphan) and a restore with neither
// --source nor --staged. Anything else is read as a named source.
func agentHookConfigGitFromIndex(sub string, args []string) bool {
	switch sub {
	case "checkout":
		for _, arg := range args {
			if arg == "--" {
				return true
			}
			if !strings.HasPrefix(arg, "-") {
				return false
			}
		}
		return false
	case "restore":
		for _, arg := range args {
			if arg == "--" {
				return true
			}
			if arg == "--source" || arg == "--staged" || strings.HasPrefix(arg, "--source=") {
				return false
			}
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "sS") {
				return false
			}
		}
		return true
	}
	return false
}

// maxAgentHookConfigIndexBytes bounds the index file read.
const maxAgentHookConfigIndexBytes = 32 << 20

// agentHookConfigGitIndexMayTrack reports that the index of the repository at
// worktree may list path: it lists it, or is not in a form this reads (a
// version other than 2 or 3, a split or sparse index, a .git that is a file
// or a name this process cannot read, one over the bound). A repository with
// no index file tracks nothing.
func agentHookConfigGitIndexMayTrack(worktree, path string) bool {
	relative, err := filepath.Rel(worktree, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative = filepath.ToSlash(relative)
	gitDir := filepath.Join(worktree, ".git")
	if info, err := os.Lstat(gitDir); err != nil || !info.IsDir() {
		return true
	}
	file, err := os.Open(filepath.Join(gitDir, "index"))
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return true
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxAgentHookConfigIndexBytes+1))
	if err != nil || len(data) > maxAgentHookConfigIndexBytes || len(data) < 32 || string(data[:4]) != "DIRC" {
		return true
	}
	version, count := binary.BigEndian.Uint32(data[4:8]), binary.BigEndian.Uint32(data[8:12])
	if version != 2 && version != 3 {
		return true
	}
	end := len(data) - 20
	offset := 12
	for entry := uint32(0); entry < count; entry++ {
		if offset+62 > end {
			return true
		}
		flags := binary.BigEndian.Uint16(data[offset+60:])
		header := 62
		if version >= 3 && flags&0x4000 != 0 {
			header = 64
		}
		length := int(flags & 0xfff)
		if offset+header+length > end {
			return true
		}
		if length == 0xfff {
			cut := bytes.IndexByte(data[offset+header:end], 0)
			if cut < 0 {
				return true
			}
			length = cut
		}
		name := string(data[offset+header : offset+header+length])
		if name == relative || strings.HasSuffix(name, "/") && strings.HasPrefix(relative, name) {
			return true
		}
		offset += (header + length + 8) &^ 7
	}
	for offset+8 <= end {
		size := int64(binary.BigEndian.Uint32(data[offset+4:]))
		switch string(data[offset : offset+4]) {
		case "link", "sdir":
			return true
		}
		offset += 8 + int(size)
		if size > int64(end) {
			return true
		}
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
		// A pattern matches the tracked files of the tree, not every name a
		// registration file could have in this folder.
		if _, err := seamLstat(file.Path); err != nil {
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
	// GIT_WORK_TREE=dir (or GIT_DIR=dir/.git) before the command names the
	// worktree as --work-tree=dir does, whether the assignment is written
	// before git or passed through env or a process wrapper. env -i and
	// env -u drop what was assigned before them, as env does. Every pass
	// consumes at least one word, so the peel ends with the argv.
	rest, workTreeVar, gitDirVar := argv, "", ""
	// GIT_INDEX_FILE or GIT_DIR before the command, or in an env wrapper,
	// moves the index git reads (GAP-0789); so does one named elsewhere in
	// the call (guard.gitIndexRedirected).
	indexRedirected := guard.gitIndexRedirected
	for len(rest) > 0 {
		for len(rest) > 0 && agentHookConfigAssignment(rest[0]) {
			name, value, _ := strings.Cut(rest[0], "=")
			switch name {
			case "GIT_WORK_TREE":
				workTreeVar = value
			case "GIT_DIR":
				gitDirVar = value
			}
			if name == "GIT_INDEX_FILE" || name == "GIT_DIR" {
				indexRedirected = true
			}
			rest = rest[1:]
		}
		if len(rest) == 0 {
			break
		}
		if child, directory, unset, wrapper := agentHookConfigEnvChild(rest); wrapper {
			for _, name := range unset {
				if name == "*" || name == "GIT_WORK_TREE" {
					workTreeVar = ""
				}
				if name == "*" || name == "GIT_DIR" {
					gitDirVar = ""
				}
			}
			if directory != "" {
				if !filepath.IsAbs(directory) {
					directory = filepath.Join(guard.cwd, directory)
				}
				redirected, links := guard.gitIndexRedirected, guard.links
				guard = newAgentHookConfigGuard(directory, guard.home)
				guard.gitIndexRedirected, guard.links = redirected, links
			}
			rest = child
		} else if child, wrapper := agentHookConfigWrapperChild(rest); wrapper {
			rest = child
		} else {
			break
		}
	}
	workTree := workTreeVar
	if workTree == "" && filepath.Base(gitDirVar) == ".git" {
		workTree = filepath.Dir(gitDirVar)
	}
	if len(rest) != len(argv) {
		if len(rest) > 0 && filepath.Base(rest[0]) == "git" {
			argv = rest
			if workTree != "" {
				argv = append([]string{rest[0], "--work-tree=" + workTree}, rest[1:]...)
			}
		}
	}
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
			patch, err := seamReadFile(places[0])
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
	// A worktree that is a link the call makes, with a target the hook
	// cannot read, may hold any hook file: a rewrite of it counts unless
	// every pathspec names a file that is no hook file (rel-1-0-10:GAP-0718,
	// the GAP-0572 unreadable-folder reading).
	if _, err := os.Stat(worktree); err != nil && len(guard.links.AliasTargets(worktree, false)) > 0 &&
		!agentHookConfigGitFilePathspecsOnly(args, worktree, guard) {
		return worktree
	}
	// An explicit pathspec may name a file currently absent from this tree.
	fromIndex := agentHookConfigGitFromIndex(sub, args)
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
				if file.Path == candidate || strings.HasPrefix(file.Path, candidate+string(filepath.Separator)) &&
					agentHookConfigPathspecFolderHolds(candidate, file.Path, worktree, fromIndex && !indexRedirected) {
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
			info, err := seamLstat(candidate)
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
						if _, err := seamStat(file.Path); err == nil {
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
			if _, err := seamStat(file.Path); err == nil {
				return file.Path
			}
		}
	}
	for _, file := range agentHookConfigProjectFiles {
		path := filepath.Join(worktree, filepath.FromSlash(strings.TrimPrefix(file.suffix, "/")))
		if _, err := seamStat(path); err == nil {
			return path
		}
	}
	return ""
}

// agentHookConfigGitFilePathspecsOnly reports git arguments whose pathspecs
// (after --) all name a file with an extension that is no hook file: such a
// rewrite cannot replace a hook file, wherever its worktree is.
func agentHookConfigGitFilePathspecsOnly(args []string, worktree string, guard *agentHookConfigGuard) bool {
	start, saw := false, false
	for _, arg := range args {
		if arg == "--" {
			start = true
			continue
		}
		if !start || strings.HasPrefix(arg, "-") {
			continue
		}
		saw = true
		base := filepath.Base(arg)
		path := filepath.Join(worktree, arg)
		if strings.ContainsAny(arg, "*?[:") || filepath.Ext(base) == "" || base == "." || base == ".." ||
			guard.format(path) != "" || guard.ownedFile(path) {
			return false
		}
	}
	return saw
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
		assigned, command, unset, understood := agentHookConfigEnvSplit(argv)
		if !understood {
			// GNU env rejects the call, or it runs no command.
			return "", ""
		}
		var assignments []string
		for _, word := range assigned {
			if agentHookConfigRunHomeAssignment(word) {
				assignments = append(assignments, word)
			}
		}
		dropsHome := slices.Contains(unset, "*") || slices.Contains(unset, "HOME")
		reason, target = agentHookConfigRunOverride(command, guard, facts)
		if agent := agentHookConfigLaunchedAgent(command); reason == "" && target == "" && agent != "" {
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
	if program == "exec" || program == "command" || program == "nohup" {
		return agentHookConfigRunOverride(argv[1:], guard, facts)
	}
	if child, wrapper := agentHookConfigWrapperChild(argv); wrapper {
		return agentHookConfigRunOverride(child, guard, facts)
	}
	if child := agentHookConfigLauncherChild(argv); child != nil {
		return agentHookConfigRunOverride(child, guard, facts)
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
	if runtime.GOOS == "windows" {
		// Git Bash spells a drive as /c/...; any other rooted path is a
		// folder on the current drive, which is never the agent's home.
		value = actionfacts.MSYSDrivePath(value)
		if !filepath.IsAbs(value) && (strings.HasPrefix(value, "/") || strings.HasPrefix(value, `\`)) {
			return filepath.Clean(value), true
		}
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
		if child, wrapper := agentHookConfigWrapperChild(argv); wrapper {
			argv = child
			continue
		}
		if child := agentHookConfigLauncherChild(argv); child != nil {
			return strings.ToLower(child[0])
		}
		switch program {
		case "env":
			_, command, _, understood := agentHookConfigEnvSplit(argv)
			if !understood {
				return ""
			}
			argv = command
		case "exec", "command", "nohup":
			argv = argv[1:]
			for len(argv) > 0 && (strings.HasPrefix(argv[0], "-") || strings.Contains(argv[0], "=")) {
				argv = argv[1:]
			}
		default:
			return ""
		}
	}
	return ""
}

// agentHookConfigWrapperOptionArgs lists, for each literal process wrapper,
// the options that consume the next word. A long option written
// --name=value consumes none, and an attached short value (-k5) is one word.
var agentHookConfigWrapperOptionArgs = map[string][]string{
	"timeout": {"-k", "--kill-after", "-s", "--signal"},
	"nice":    {"-n", "--adjustment"},
	"ionice":  {"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"},
	"stdbuf":  {"-i", "--input", "-o", "--output", "-e", "--error"},
	"time":    {"-f", "--format", "-o", "--output"},
	"sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from", "-D", "--chdir",
		"-R", "--chroot", "-r", "--role", "-t", "--type", "-T", "--command-timeout", "-U", "--other-user"},
	"doas": {"-u", "-C"},
}

// agentHookConfigEnvLongOptions are the long options of GNU env; it accepts
// any unambiguous abbreviation of them (--ch is --chdir).
var agentHookConfigEnvLongOptions = []string{"ignore-environment", "null", "unset", "chdir", "split-string",
	"block-signal", "default-signal", "ignore-signal", "list-signal-handling", "debug", "argv0", "help", "version"}

// agentHookConfigWrapperLongNames lists the long option names of each
// process wrapper that takes a value, without the leading --.
var agentHookConfigWrapperLongNames = func() map[string][]string {
	names := map[string][]string{}
	for program, options := range agentHookConfigWrapperOptionArgs {
		for _, option := range options {
			if name, long := strings.CutPrefix(option, "--"); long {
				names[program] = append(names[program], name)
			}
		}
	}
	return names
}()

// agentHookConfigLongWord spells an abbreviated long option word in full,
// keeping an =value tail. A word that is not a long option of options, or is
// ambiguous, is returned as it is.
func agentHookConfigLongWord(word string, options []string) string {
	if !strings.HasPrefix(word, "--") || word == "--" {
		return word
	}
	name, value, joined := strings.Cut(word[2:], "=")
	option := hookpaths.ExpandLongOption(name, options)
	if option == "" {
		return word
	}
	if joined {
		return "--" + option + "=" + value
	}
	return "--" + option
}

// agentHookConfigEnvChild reads one GNU env call through its whole grammar
// and returns the words it runs: the NAME=value assignments it passes (kept
// in front, in the order agentHookConfigGitTarget reads) followed by the
// command, the folder -C/--chdir starts it in, and the variables it drops from
// the environment it received first (-u NAME; "*" for -i or a lone -).
// Options end at the first assignment, --, or command word, as env reads
// them. The grammar is: -i/--ignore-environment, -0/--null, -v/--debug,
// -u/--unset NAME, -C/--chdir DIR, -a/--argv0 NAME, -S/--split-string
// STRING (split into words that are read as if typed in its place), the
// signal options (--block-signal[=SIG], --default-signal[=SIG],
// --ignore-signal[=SIG], --list-signal-handling), any unambiguous long
// abbreviation and short cluster of these, and --. wrapper is false for what
// GNU env rejects, for --help and --version (no command runs), and for a
// split string that needs the environment to read (${NAME}).
func agentHookConfigEnvChild(argv []string) (child []string, directory string, unset []string, wrapper bool) {
	if len(argv) == 0 || strings.ToLower(filepath.Base(argv[0])) != "env" {
		return nil, "", nil, false
	}
	args := slices.Clone(argv[1:])
	var assigned []string
	optionsEnded := false
	for index := 0; index < len(args); index++ {
		word := args[index]
		switch {
		case optionsEnded && agentHookConfigAssignment(word):
			assigned = append(assigned, word)
			continue
		case optionsEnded:
			return append(assigned, args[index:]...), directory, unset, true
		case word == "--":
			optionsEnded = true
			continue
		case agentHookConfigAssignment(word):
			optionsEnded = true
			assigned = append(assigned, word)
			continue
		case word == "-":
			unset = append(unset, "*")
			continue
		case !strings.HasPrefix(word, "-"):
			return append(assigned, args[index:]...), directory, unset, true
		}
		// An option: one long word, or a short cluster. letter is the option
		// that takes an operand (u, C, a, S) and tail the part of the word
		// after it; the operand is the tail, or else the next word.
		letter, tail := byte(0), ""
		if long := agentHookConfigLongWord(word, agentHookConfigEnvLongOptions); strings.HasPrefix(long, "--") {
			name, joined, hasTail := strings.Cut(long[2:], "=")
			switch name {
			case "ignore-environment", "null", "debug", "list-signal-handling":
				if hasTail {
					return nil, "", nil, false
				}
				if name == "ignore-environment" {
					unset = append(unset, "*")
				}
				continue
			case "block-signal", "default-signal", "ignore-signal":
				continue
			case "unset":
				letter = 'u'
			case "chdir":
				letter = 'C'
			case "argv0":
				letter = 'a'
			case "split-string":
				letter = 'S'
			default:
				return nil, "", nil, false
			}
			tail = joined
		} else {
			for position := 1; position < len(word) && letter == 0; position++ {
				switch word[position] {
				case 'i':
					unset = append(unset, "*")
				case '0', 'v':
				case 'u', 'C', 'a', 'S':
					letter, tail = word[position], word[position+1:]
				default:
					return nil, "", nil, false
				}
			}
			if letter == 0 {
				continue
			}
		}
		last := index
		operand := tail
		if operand == "" {
			if index+1 >= len(args) {
				return nil, "", nil, false
			}
			last, operand = index+1, args[index+1]
		}
		switch letter {
		case 'u':
			unset = append(unset, operand)
		case 'C':
			directory = operand
		case 'S':
			fields, split := agentHookConfigSplitString(operand)
			if !split {
				return nil, "", nil, false
			}
			// The fields stand where -S STRING stood and are read in turn as
			// options, assignments and the command.
			args = slices.Concat(args[:index], fields, args[last+1:])
			index--
			continue
		}
		index = last
	}
	return assigned, directory, unset, true
}

// agentHookConfigSplitEscapes are the backslash letters env -S reads.
var agentHookConfigSplitEscapes = map[byte]byte{'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v'}

// agentHookConfigSplitString splits the STRING of env -S the way GNU env
// does: blanks separate words; a # at the start of a word starts a comment;
// single quotes keep their text, where a backslash reads only \\ and the
// quote and is otherwise a backslash; double quotes keep their text but read
// \" \\ \$ \# \' \_ (a blank) and the escape letters; outside quotes a
// backslash reads \_ (a word break), \c (end of string), the escape letters
// and the quote, backslash, # and $ characters. It returns false for what
// GNU env rejects and for ${NAME}, which needs the environment of the call
// (GNU env accepts no other unescaped $).
func agentHookConfigSplitString(text string) ([]string, bool) {
	var fields []string
	var current strings.Builder
	inWord := false
	flush := func() {
		if inWord {
			fields = append(fields, current.String())
			current.Reset()
			inWord = false
		}
	}
	// escape reads the character after a backslash at text[i]; done is true
	// for \c, which ends the string.
	escape := func(i int, quoted bool) (done, ok bool) {
		if i >= len(text) {
			return false, false
		}
		c := text[i]
		switch {
		case c == 'c':
			return !quoted, !quoted
		case c == '_':
			if quoted {
				current.WriteByte(0x20)
				inWord = true
			} else {
				flush()
			}
			return false, true
		case agentHookConfigSplitEscapes[c] != 0:
			current.WriteByte(agentHookConfigSplitEscapes[c])
		case c == 0x22 || c == 0x5c || c == 0x24 || c == 0x23 || c == 0x27:
			current.WriteByte(c)
		default:
			return false, false
		}
		inWord = true
		return false, true
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0b || c == 0x0c || c == 0x0d:
			flush()
		case c == 0x23 && !inWord:
			return fields, true
		case c == 0x24:
			return nil, false
		case c == 0x27:
			inWord = true
			closed := false
			for i++; i < len(text); i++ {
				if text[i] == 0x27 {
					closed = true
					break
				}
				if text[i] == 0x5c && i+1 < len(text) && (text[i+1] == 0x5c || text[i+1] == 0x27) {
					i++
				}
				current.WriteByte(text[i])
			}
			if !closed {
				return nil, false
			}
		case c == 0x22:
			inWord = true
			for i++; i < len(text) && text[i] != 0x22; i++ {
				switch text[i] {
				case 0x24:
					return nil, false
				case 0x5c:
					i++
					if _, ok := escape(i, true); !ok {
						return nil, false
					}
				default:
					current.WriteByte(text[i])
				}
			}
			if i >= len(text) {
				return nil, false
			}
		case c == 0x5c:
			i++
			done, ok := escape(i, false)
			if !ok {
				return nil, false
			}
			if done {
				flush()
				return fields, true
			}
		default:
			current.WriteByte(c)
			inWord = true
		}
	}
	flush()
	return fields, true
}

// agentHookConfigEnvSplit reads one env call through agentHookConfigEnvChild
// and separates the NAME=value words it passes from the command it runs.
// understood is false for an option the reader does not know.
func agentHookConfigEnvSplit(argv []string) (assigned, command, unset []string, understood bool) {
	child, _, unset, understood := agentHookConfigEnvChild(argv)
	if !understood {
		return nil, nil, nil, false
	}
	cut := 0
	for cut < len(child) && agentHookConfigAssignment(child[cut]) {
		cut++
	}
	return child[:cut], child[cut:], unset, true
}

// agentHookConfigWrapperChild reads one literal process wrapper (timeout,
// nice, sudo ...) and returns the command it runs, found past the options
// that take a value and the duration word of timeout. The launched agent
// and the per-run overrides on it are read from this one place.
func agentHookConfigWrapperChild(argv []string) ([]string, bool) {
	if len(argv) == 0 {
		return nil, false
	}
	program := strings.ToLower(filepath.Base(argv[0]))
	options, wrapper := agentHookConfigWrapperOptionArgs[program]
	if !wrapper {
		return nil, false
	}
	index := 1
	for index < len(argv) {
		word := argv[index]
		if word == "--" {
			index++
			continue
		}
		if !strings.HasPrefix(word, "-") {
			break
		}
		index++
		word = agentHookConfigLongWord(word, agentHookConfigWrapperLongNames[program])
		if slices.Contains(options, word) {
			index++
		}
	}
	if index < len(argv) && (program == "timeout" || program == "nice" && argv[index] != "" && argv[index][0] >= 0x30 && argv[index][0] <= 0x39) {
		index++
	}
	if index >= len(argv) {
		return nil, true
	}
	return argv[index:], true
}

// agentHookConfigLauncherChild reads a package runner (npx, bunx, pnpm dlx,
// npm exec, yarn dlx) and returns the agent command it starts, with the
// program name of the agent first; nil when it starts no known agent.
func agentHookConfigLauncherChild(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	start := 0
	switch program := strings.ToLower(filepath.Base(argv[0])); {
	case program == "npx" || program == "npx.cmd" || program == "bunx" || program == "bunx.cmd":
		start = 1
	case (program == "pnpm" || program == "yarn") && len(argv) > 1 && argv[1] == "dlx":
		start = 2
	case program == "npm" && len(argv) > 1 && (argv[1] == "exec" || argv[1] == "x"):
		start = 2
	}
	if start == 0 {
		return nil
	}
	for index := start; index < len(argv); index++ {
		word := argv[index]
		switch {
		case word == "--":
			continue
		case word == "-p" || word == "--package":
			index++
			continue
		case strings.HasPrefix(word, "-"):
			continue
		}
		if at := strings.LastIndex(word, "@"); at > 0 {
			word = word[:at]
		}
		switch word {
		case "@anthropic-ai/claude-code", "claude-code", "claude":
			return append([]string{"claude"}, argv[index+1:]...)
		case "@openai/codex", "codex":
			return append([]string{"codex"}, argv[index+1:]...)
		}
		return nil
	}
	return nil
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
	file, err := syntax.NewParser().Parse(shellparse.Reader(command), "")
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
