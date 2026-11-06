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
		if !set || value == true {
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
			!strings.Contains(managedRaw, "--setting-sources")) {
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
		guard := newAgentHookConfigGuard(request.Input.CWD, request.Input.ActiveHome)
		facts := []actionfacts.Facts{actionfacts.Analyze(request.Input)}
		for _, command := range facts[0].Commands {
			if reason, target := agentHookConfigRunOverride(agentHookConfigExactWords(command), guard, facts); reason != "" {
				add(agentHookConfigDisableRuleID, reason, target)
			}
		}
		if reason, target := agentHookConfigPrefixOverride(managedRaw, facts, guard); reason != "" {
			add(agentHookConfigDisableRuleID, reason, target)
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
	var receiverFacts *actionfacts.Facts
	for operand, resolved := range request.ResolvedWriteTargets {
		if strings.HasPrefix(operand, "\x00") || !filepath.IsAbs(resolved) ||
			!guard.shellTarget(resolved) && !guard.ownedFile(resolved) {
			continue
		}
		if guard.format(resolved) == "" && !guard.ownedFile(resolved) {
			if receiverFacts == nil {
				facts := actionfacts.Analyze(request.Input)
				receiverFacts = &facts
			}
			if agentHookConfigFolderOnlyReceives(operand, *receiverFacts, guard) {
				continue
			}
		}
		{
			if guard.ownedFile(resolved) {
				add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", resolved)
			} else {
				add(agentHookConfigWriteRuleID, "", resolved)
			}
		}
	}
	text := strings.ToLower(request.LegacyText + "\n" + request.Input.Command + "\n" + string(request.Input.Args) + "\n" + strings.Join(request.Input.Argv, "\n"))
	if !guard.shellMentionsRegistryPath(text) &&
		!slices.ContainsFunc([]string{"git ", "patch ", "claude ", "codex ", "opencode ", "amp ", "copilot ", "kiro-cli ", "hermes ", "cursor-agent ", "devin ", "gemini ", "npx "},
			func(name string) bool { return strings.Contains(text, name) }) {
		return out
	}
	shellFacts := []actionfacts.Facts{actionfacts.Analyze(request.Input)}
	// Read shell destinations with the same shared extractors used by the
	// protected state write rule, including ordered values and placed cd.
	if command := agentHookConfigRawShellCommand(request.Input); command != "" && guard.shellMentionsRegistryPath(text) {
		for _, target := range agentHookConfigSharedShellTargets(command, guard, 0) {
			if folder, ok := strings.CutPrefix(target, "\x00folder:"); ok {
				if guard.shellTarget(folder) {
					add(agentHookConfigWriteRuleID, "", folder)
				}
				continue
			}
			if guard.ownedFile(target) {
				add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", target)
			} else if guard.format(target) != "" {
				add(agentHookConfigWriteRuleID, "", target)
			}
		}
	}
	for _, facts := range shellFacts {
		for _, command := range facts.Commands {
			argv := agentHookConfigExactWords(command)
			if len(argv) > 0 && filepath.Base(argv[0]) == "patch" {
				for _, source := range facts.Paths {
					if source.CommandID != command.ID || source.Access != actionfacts.PathAccessRead {
						continue
					}
					path := firstNonEmpty(source.Resolved, source.Normalized, source.Value)
					body, err := os.ReadFile(path)
					if err != nil || len(body) > agentHookConfigMaxBytes {
						continue
					}
					if target, _ := agentHookConfigPatchTarget(body, guard); target != "" {
						add(agentHookConfigWriteRuleID, "", target)
					}
				}
			}
			if reason, target := agentHookConfigRunOverride(argv, guard, shellFacts); reason != "" {
				add(agentHookConfigDisableRuleID, reason, target)
			} else if target != "" {
				add(agentHookConfigWriteRuleID, "", target)
			}
			if target := agentHookConfigGitTarget(argv, guard); target != "" {
				add(agentHookConfigWriteRuleID, "", target)
			}
			if target := agentHookConfigDirectoryCopyTarget(argv, guard); target != "" {
				if guard.ownedFile(target) {
					add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", target)
				} else {
					add(agentHookConfigWriteRuleID, "", target)
				}
			}
			if target := agentHookConfigMovedOwnedSource(argv, guard); target != "" {
				add(agentHookConfigDisableRuleID, "moves a registered DefenseClaw hook file", target)
			}
			if target := agentHookConfigFolderCommandTarget(argv, guard); target != "" {
				add(agentHookConfigWriteRuleID, "", target)
			}
			if target := agentHookConfigModeTarget(command, guard); target != "" {
				if guard.ownedFile(target) {
					add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", target)
				} else {
					add(agentHookConfigWriteRuleID, "", target)
				}
			}
		}
		for _, target := range facts.Paths {
			modeTarget := false
			if target.Access == actionfacts.PathAccessMetadata {
				for _, command := range facts.Commands {
					if command.ID == target.CommandID && agentHookConfigModeCommand(command.Argv) {
						modeTarget = true
						break
					}
				}
			}
			switch target.Access {
			case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
			default:
				if !modeTarget {
					continue
				}
			}
			candidate := firstNonEmpty(target.Resolved, target.Normalized, target.Value)
			if strings.ContainsAny(target.Value, "*?[") {
				for _, spelling := range guard.places(target.Value) {
					matches, err := filepath.Glob(spelling)
					if err != nil || len(matches) > 64 {
						continue
					}
					for _, match := range matches {
						if guard.ownedFile(match) {
							add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", match)
						} else if guard.format(match) != "" {
							add(agentHookConfigWriteRuleID, "", match)
						}
					}
				}
			}
			if runtime.GOOS == "windows" && target.Flavor == actionfacts.PathFlavorPOSIX {
				if host, ok := windowsHostPathOfPOSIXOperand(target.Value, request.Input.CWD, request.Input.ActiveHome, false); ok {
					candidate = filepath.FromSlash(host)
				}
			}
			if target.Access != actionfacts.PathAccessDelete && guard.format(filepath.FromSlash(candidate)) == "" &&
				!guard.ownedFile(filepath.FromSlash(candidate)) {
				if info, err := os.Stat(filepath.FromSlash(candidate)); err == nil && info.IsDir() {
					receiver := false
					for _, command := range facts.Commands {
						if command.ID == target.CommandID && len(command.Argv) > 0 {
							switch filepath.Base(command.Argv[0]) {
							case "mv", "cp", "install", "ln":
								receiver = true
							}
						}
					}
					if receiver {
						continue
					}
				}
			}
			if guard.format(filepath.FromSlash(candidate)) == "" && !guard.ownedFile(filepath.FromSlash(candidate)) {
				// A folder counts only when the command replaces or removes
				// the folder itself; creating entries inside it is ordinary.
				mutatesFolder := false
				for _, command := range facts.Commands {
					if command.ID == target.CommandID && agentHookConfigFolderCommandTarget(agentHookConfigExactWords(command), guard) != "" {
						mutatesFolder = true
						break
					}
				}
				if !mutatesFolder {
					continue
				}
			}
			if guard.shellTarget(filepath.FromSlash(candidate)) || guard.ownedFile(filepath.FromSlash(candidate)) {
				if guard.ownedFile(filepath.FromSlash(candidate)) {
					add(agentHookConfigDisableRuleID, "changes a registered DefenseClaw hook file", candidate)
				} else {
					add(agentHookConfigWriteRuleID, "", candidate)
				}
			}
		}
	}
	if reason, target := agentHookConfigPrefixOverride(agentHookConfigRawShellCommand(request.Input), shellFacts, guard); reason != "" {
		add(agentHookConfigDisableRuleID, reason, target)
	} else if target != "" {
		add(agentHookConfigWriteRuleID, "", target)
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

// agentHookConfigSharedShellTargets is the gx048 shell write leg. The
// operand readers in hookpaths are shared with tamper.detector_state_write;
// this replaces the earlier private argv-only target reading for shell
// writes. Directory receivers are judged separately from file operands.
func agentHookConfigSharedShellTargets(command string, guard *agentHookConfigGuard, depth int) []string {
	if depth > 3 || len(command) > 8192 {
		return nil
	}
	registered := make([]string, 0, len(guard.files))
	seen := make(map[string]bool)
	for _, file := range guard.files {
		for path := filepath.Clean(file.Path); filepath.IsAbs(path); path = filepath.Dir(path) {
			if path == guard.home || path == guard.cwd || path == string(filepath.Separator) ||
				strings.HasPrefix(guard.home, path+string(filepath.Separator)) ||
				strings.HasPrefix(guard.cwd, path+string(filepath.Separator)) {
				break
			}
			if !seen[path] {
				registered = append(registered, path)
				seen[path] = true
			}
			if path == filepath.Dir(path) {
				break
			}
		}
	}
	read := func(body, cwd string) []string {
		out := hookpaths.LiteralWriteOperands(body, cwd, guard.home)
		if redirects, ok, _ := hookpaths.ShellWriteOperands(body, cwd, guard.home); ok {
			out = append(out, redirects...)
		}
		if bounded, _ := hookpaths.BoundedShellWriteOperands(body, cwd, guard.home); len(bounded) != 0 {
			out = append(out, bounded...)
		}
		if hookpaths.ProtectedReach(body, cwd, guard.home, registered) {
			for _, path := range registered {
				if !hookpaths.ProtectedReach(body, cwd, guard.home, []string{path}) {
					continue
				}
				if guard.format(path) == "" && !guard.ownedFile(path) {
					out = append(out, "\x00folder:"+path)
				} else {
					out = append(out, path)
				}
			}
		}
		return out
	}
	out := read(command, guard.cwd)
	if strings.Contains(command, "cd ") || strings.Contains(command, "cd\t") {
		if statements, ok := hookpaths.TopLevelStatements(command, guard.cwd, guard.home); ok {
			for _, statement := range statements {
				out = append(out, read(statement.Command, statement.Dir)...)
			}
		}
	}
	if !strings.Contains(command, " -c") && !strings.Contains(command, " -lc") {
		return out
	}
	input := actionfacts.Input{Tool: "Bash", Command: command, CWD: guard.cwd, ActiveHome: guard.home}
	for _, fact := range actionfacts.Analyze(input).Commands {
		words := agentHookConfigExactWords(fact)
		if len(words) > 0 {
			static := make([]bool, len(words))
			for i := range static {
				static[i] = words[i] != "" && (i >= len(fact.Arguments) || !fact.Arguments[i].Expands)
			}
			if run, ok := actionfacts.StaticPrefixWrapperChild(words, static); ok &&
				!run.DirUnknown && run.Dir == "" && !run.ChangesResolution {
				words = words[run.Index:]
			}
		}
		if body := hookpaths.NestedShellBody(words); body != "" {
			out = append(out, agentHookConfigSharedShellTargets(body, guard, depth+1)...)
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

func agentHookConfigFolderCommandTarget(argv []string, guard *agentHookConfigGuard) string {
	if len(argv) < 2 {
		return ""
	}
	switch filepath.Base(argv[0]) {
	case "rm", "rmdir", "unlink":
		for _, arg := range argv[1:] {
			if !strings.HasPrefix(arg, "-") && guard.shellTarget(arg) {
				return arg
			}
		}
	case "mv":
		// A move removes its sources; the destination folder only receives.
		var operands []string
		targetDir := false
		for index := 1; index < len(argv); index++ {
			arg := argv[index]
			if arg == "-t" || arg == "--target-directory" {
				targetDir = true
				index++
				continue
			}
			if strings.HasPrefix(arg, "--target-directory=") {
				targetDir = true
				continue
			}
			if arg != "--" && !strings.HasPrefix(arg, "-") {
				operands = append(operands, arg)
			}
		}
		if !targetDir && len(operands) > 0 {
			operands = operands[:len(operands)-1]
		}
		for _, arg := range operands {
			if guard.shellTarget(arg) {
				return arg
			}
		}
	case "tar":
		extract := slices.Contains(argv, "--extract") || slices.Contains(argv, "--get")
		for _, arg := range argv[1:] {
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "x") {
				extract = true
			}
		}
		if !extract {
			return ""
		}
		for index, arg := range argv[1:] {
			if (arg == "-C" || arg == "--directory") && index+2 < len(argv) && guard.shellTarget(argv[index+2]) {
				return argv[index+2]
			}
			if path, ok := strings.CutPrefix(arg, "--directory="); ok && guard.shellTarget(path) {
				return path
			}
		}
	case "unzip":
		for index, arg := range argv[1:] {
			if arg == "-d" && index+2 < len(argv) && guard.shellTarget(argv[index+2]) {
				return argv[index+2]
			}
		}
	}
	return ""
}

func agentHookConfigMovedOwnedSource(argv []string, guard *agentHookConfigGuard) string {
	if len(argv) < 3 || filepath.Base(argv[0]) != "mv" {
		return ""
	}
	var operands []string
	for _, arg := range argv[1:] {
		if arg == "--" || strings.HasPrefix(arg, "-") {
			continue
		}
		operands = append(operands, arg)
	}
	for _, source := range operands[:max(0, len(operands)-1)] {
		if guard.ownedFile(source) {
			return source
		}
	}
	return ""
}

func agentHookConfigModeCommand(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch filepath.Base(argv[0]) {
	case "chmod", "chown", "chgrp", "setfacl", "chattr":
		return true
	}
	return false
}

func agentHookConfigModeTarget(command actionfacts.CommandFact, guard *agentHookConfigGuard) string {
	if !agentHookConfigModeCommand(command.Argv) {
		return ""
	}
	for _, arg := range command.Arguments[1:] {
		candidate := arg.Value
		if candidate == "" && !strings.ContainsAny(arg.StaticGlob, "*?[]{}$`\\") {
			candidate = arg.StaticGlob
		}
		if candidate != "" && (guard.shellTarget(candidate) || guard.ownedFile(candidate)) {
			return candidate
		}
	}
	return ""
}

func agentHookConfigDirectoryCopyTarget(argv []string, guard *agentHookConfigGuard) string {
	if len(argv) < 3 {
		return ""
	}
	program := filepath.Base(argv[0])
	if program != "cp" && program != "mv" && program != "install" && program != "rsync" {
		return ""
	}
	var operands []string
	destination := ""
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		if (arg == "-t" || arg == "--target-directory") && index+1 < len(argv) {
			destination = argv[index+1]
			index++
			continue
		}
		if path, ok := strings.CutPrefix(arg, "--target-directory="); ok {
			destination = path
			continue
		}
		if arg != "--" && !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
		}
	}
	if destination == "" {
		if len(operands) < 2 {
			return ""
		}
		destination = operands[len(operands)-1]
		operands = operands[:len(operands)-1]
	} else if len(operands) == 0 {
		return ""
	}
	if guard.format(destination) != "" || guard.ownedFile(destination) {
		return destination
	}
	for _, source := range operands {
		base := filepath.Base(strings.TrimSuffix(source, string(filepath.Separator)))
		if base != "." && (guard.format(filepath.Join(destination, base)) != "" || guard.ownedFile(filepath.Join(destination, base))) {
			return destination
		}
		// Recursive copy of a directory's contents can replace a registered
		// file even though the destination operand names only its folder.
		for _, place := range guard.places(source) {
			info, err := os.Stat(place)
			if err != nil || !info.IsDir() {
				continue
			}
			for _, file := range guard.files {
				for _, dest := range guard.places(destination) {
					rel, err := filepath.Rel(dest, file.Path)
					if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
						continue
					}
					if _, err := os.Stat(filepath.Join(place, rel)); err == nil {
						return destination
					}
				}
			}
		}
	}
	return ""
}

// A client write fact can name the existing directory that merely receives
// an ordinary entry. Only the receiving operand is excluded; the source of
// a move and a directory copy that reaches a registration remain writes.
func agentHookConfigFolderOnlyReceives(operand string, facts actionfacts.Facts, guard *agentHookConfigGuard) bool {
	same := func(a, b string) bool {
		pa, pb := guard.places(a), guard.places(b)
		return len(pa) != 0 && len(pb) != 0 && pa[0] == pb[0]
	}
	for _, command := range facts.Commands {
		argv := agentHookConfigExactWords(command)
		if len(argv) == 0 {
			continue
		}
		program := filepath.Base(argv[0])
		switch program {
		case "mkdir", "touch":
			for _, arg := range argv[1:] {
				if same(arg, operand) {
					return true
				}
			}
		case "mv", "cp", "install", "ln":
			if program == "cp" && agentHookConfigDirectoryCopyTarget(argv, guard) != "" {
				continue
			}
			if program == "ln" && slices.ContainsFunc(argv, func(arg string) bool {
				return strings.HasPrefix(arg, "-") && strings.Contains(arg, "f") && strings.Contains(arg, "n")
			}) {
				continue
			}
			var operands []string
			for _, arg := range argv[1:] {
				if arg != "--" && !strings.HasPrefix(arg, "-") {
					operands = append(operands, arg)
				}
			}
			if len(operands) != 0 && same(operands[len(operands)-1], operand) {
				return true
			}
		case "find":
			for i := 1; i+3 < len(argv); i++ {
				if argv[i] != "-exec" || filepath.Base(argv[i+1]) != "mv" {
					continue
				}
				for j := i + 2; j < len(argv); j++ {
					if argv[j] == ";" || argv[j] == "+" {
						if j > i+2 && same(argv[j-1], operand) {
							return true
						}
						break
					}
				}
			}
		}
	}
	return false
}

// gitGlobalSubcommand reads Git's global options before deciding whether a
// subcommand can update the worktree. The returned root follows -C and
// --work-tree, rather than assuming that the hook's cwd is the Git worktree.
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
	program := strings.ToLower(filepath.Base(argv[0]))
	if program == "env" {
		var assignments []string
		for index := 1; index < len(argv); index++ {
			if argv[index] == "--" {
				continue
			}
			if strings.HasPrefix(argv[index], "-") || strings.Contains(argv[index], "=") {
				if agentHookConfigRunHomeAssignment(argv[index]) {
					assignments = append(assignments, argv[index])
				}
				continue
			}
			reason, target = agentHookConfigRunOverride(argv[index:], guard, facts)
			if reason == "" && target == "" && agentHookConfigRunAgent(argv[index:]) {
				for _, assignment := range assignments {
					key, value, _ := strings.Cut(assignment, "=")
					expected := agentHookConfigExpectedHome(key, argv[index], guard)
					if expected == "" {
						continue
					}
					if strings.HasPrefix(value, "~") {
						return "", argv[index]
					}
					if path, literal := agentHookConfigLiteralHomePath(value, guard); literal && path == filepath.Clean(expected) {
						continue
					}
					if why := agentHookConfigLiteralHomeOverride(key, value, guard, argv[index]); why != "" {
						return why, argv[index]
					}
					return "", argv[index]
				}
			}
			return reason, target
		}
		return "", ""
	}
	if program == "exec" || program == "command" || program == "nohup" {
		return agentHookConfigRunOverride(argv[1:], guard, facts)
	}
	launcherStart := 0
	if program == "npx" || program == "npx.cmd" || program == "bunx" || program == "bunx.cmd" {
		launcherStart = 1
	} else if program == "pnpm" && len(argv) > 1 && argv[1] == "dlx" {
		launcherStart = 2
	}
	if launcherStart > 0 {
		for index := launcherStart; index < len(argv); index++ {
			if argv[index] == "-y" || argv[index] == "--yes" {
				continue
			}
			packageName := argv[index]
			if at := strings.LastIndex(packageName, "@"); at > 0 {
				packageName = packageName[:at]
			}
			switch packageName {
			case "@anthropic-ai/claude-code", "claude-code":
				return agentHookConfigRunOverride(append([]string{"claude"}, argv[index+1:]...), guard, facts)
			case "@openai/codex":
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
	case "CLAUDE_CONFIG_DIR", "CODEX_HOME", "HOME":
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
	if guard.home == "" || strings.ContainsAny(value, "$`*?[]{}") {
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
	}
	return ""
}

func agentHookConfigRunAgent(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	switch strings.ToLower(filepath.Base(argv[0])) {
	case "claude", "claude.exe", "codex", "codex.exe", "opencode", "opencode.exe":
		return true
	}
	return false
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

// Prefix assignments belong to the launched process, not to the hook
// request's environment. Parse the shell grammar so quoted text and comments
// cannot be mistaken for a per-run home change.
func agentHookConfigPrefixOverride(command string, facts []actionfacts.Facts, guard *agentHookConfigGuard) (reason, target string) {
	if reason, target = agentHookConfigPrefixOverrideOne(command, guard); reason != "" || target != "" {
		return reason, target
	}
	for _, fact := range facts {
		for _, command := range fact.Commands {
			if reason, target = agentHookConfigPrefixOverrideOne(hookpaths.NestedShellBody(agentHookConfigExactWords(command)), guard); reason != "" || target != "" {
				return reason, target
			}
		}
	}
	return "", ""
}

func agentHookConfigPrefixOverrideOne(command string, guard *agentHookConfigGuard) (reason, target string) {
	if len(command) > 8192 {
		return "", ""
	}
	file, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil {
		return "", ""
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || !agentHookConfigRunAgent([]string{agentHookConfigLiteralWord(call.Args[0])}) {
			return true
		}
		program := agentHookConfigLiteralWord(call.Args[0])
		for _, assignment := range call.Assigns {
			if assignment.Name != nil && agentHookConfigRunHomeAssignment(assignment.Name.Value+"=x") {
				if agentHookConfigExpectedHome(assignment.Name.Value, program, guard) == "" {
					continue
				}
				value := agentHookConfigLiteralWord(assignment.Value)
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

func agentHookConfigLiteralWord(word *syntax.Word) string {
	if word == nil || len(word.Parts) != 1 {
		return ""
	}
	switch part := word.Parts[0].(type) {
	case *syntax.Lit:
		return part.Value
	case *syntax.SglQuoted:
		return part.Value
	}
	return ""
}
