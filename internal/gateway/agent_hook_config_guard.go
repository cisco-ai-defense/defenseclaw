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
	"runtime"
	"slices"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	gatewayconnector "github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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

// agentHookConfigNames are the base names of every guarded file: a shell
// call that names none of them, and whose hook client resolved no write
// target, writes no hook file under the name it gives.
var agentHookConfigNames = []string{
	"settings.json", "settings.local.json", "config.toml", "hooks.json", "defenseclaw.js",
	"config.json", "opencode.json", "opencode.jsonc", "defenseclaw.json", "hooks.v1.json",
	"defenseclaw.ts", "config.yaml", "cli.json", ".claude", ".codex", ".opencode", ".kiro", ".gemini", ".hermes", "plugins", "hooks", "agents",
}

func agentHookConfigFoldCase() bool {
	return runtime.GOOS == "darwin" || runtime.GOOS == "windows"
}

// agentHookConfigGuard classifies the write targets of one call.
type agentHookConfigGuard struct {
	cwd, home, physicalHome string
	files                   []gatewayconnector.AgentHookConfigFile
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
			if place == g.home || place == g.cwd || place == string(filepath.Separator) {
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
		if old != nil && old["chat.defaultAgent"] != updated["chat.defaultAgent"] {
			return "changes the Kiro default agent"
		}
	}
	if format == gatewayconnector.AgentHookConfigClaudeSettings || format == gatewayconnector.AgentHookConfigCopilotSettings {
		oldEnv, _ := old["env"].(map[string]any)
		newEnv, _ := updated["env"].(map[string]any)
		for key, value := range newEnv {
			if agentHookConfigReservedEnv(key) && oldEnv[key] != value {
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
	case "PATH", "HOME", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "IFS", "CDPATH", "GLOBIGNORE", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "NODE_OPTIONS", "NODE_PATH", "RUBYOPT", "PERL5OPT", "ZDOTDIR", "COMSPEC", "PATHEXT":
		return true
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
	if !request.EnforcementCapable || ManagedEnterpriseActive() ||
		request.SkipLocalFilesystemResolution || isSandboxHookRequest(ctx) {
		return findings
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
	guard := newAgentHookConfigGuard(request.Input.CWD, request.Input.ActiveHome)
	if changes, native := agentHookConfigFileChanges(request.Input.Tool, request.Input.Args); native {
		for _, change := range changes {
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
		if !strings.HasPrefix(operand, "\x00") && filepath.IsAbs(resolved) && guard.shellTarget(resolved) {
			add(agentHookConfigWriteRuleID, "", resolved)
			return out
		}
	}
	text := strings.ToLower(request.LegacyText + "\n" + request.Input.Command + "\n" + string(request.Input.Args) + "\n" + strings.Join(request.Input.Argv, "\n"))
	if !slices.ContainsFunc(agentHookConfigNames, func(name string) bool { return strings.Contains(text, name) }) &&
		!slices.ContainsFunc([]string{"git ", "claude ", "codex ", "opencode ", "amp ", "copilot ", "kiro-cli ", "hermes ", "cursor-agent ", "devin ", "gemini "},
			func(name string) bool { return strings.Contains(text, name) }) {
		return out
	}
	facts := actionfacts.Analyze(request.Input)
	for _, command := range facts.Commands {
		if reason, target := agentHookConfigRunOverride(command.Argv, guard); reason != "" {
			add(agentHookConfigDisableRuleID, reason, target)
		} else if target != "" {
			add(agentHookConfigWriteRuleID, "", target)
		}
		if target := agentHookConfigGitTarget(command.Argv, guard); target != "" {
			add(agentHookConfigWriteRuleID, "", target)
		}
		if target := agentHookConfigDirectoryCopyTarget(command.Argv, guard); target != "" {
			add(agentHookConfigWriteRuleID, "", target)
		}
	}
	for _, target := range facts.Paths {
		switch target.Access {
		case actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		default:
			continue
		}
		candidate := firstNonEmpty(target.Resolved, target.Normalized, target.Value)
		if runtime.GOOS == "windows" && target.Flavor == actionfacts.PathFlavorPOSIX {
			if host, ok := windowsHostPathOfPOSIXOperand(target.Value, request.Input.CWD, request.Input.ActiveHome, false); ok {
				candidate = filepath.FromSlash(host)
			}
		}
		if guard.shellTarget(filepath.FromSlash(candidate)) {
			add(agentHookConfigWriteRuleID, "", candidate)
			return out
		}
	}
	return out
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
	for _, arg := range argv[1:] {
		if arg != "--" && !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
		}
	}
	if len(operands) < 2 {
		return ""
	}
	destination := operands[len(operands)-1]
	if guard.shellTarget(destination) {
		return destination
	}
	for _, source := range operands[:len(operands)-1] {
		base := filepath.Base(strings.TrimSuffix(source, string(filepath.Separator)))
		if base != "." && guard.format(filepath.Join(destination, base)) != "" {
			return destination
		}
	}
	return ""
}

func agentHookConfigGitTarget(argv []string, guard *agentHookConfigGuard) string {
	if len(argv) < 2 || filepath.Base(argv[0]) != "git" {
		return ""
	}
	index := 1
	for index < len(argv) && argv[index] == "-C" && index+1 < len(argv) {
		index += 2
	}
	if index >= len(argv) {
		return ""
	}
	sub := argv[index]
	switch sub {
	case "restore", "checkout", "reset", "stash", "apply":
	default:
		return ""
	}
	if sub == "stash" && !slices.Contains(argv, "pop") && !slices.Contains(argv, "apply") {
		return ""
	}
	if sub == "reset" && !slices.Contains(argv, "--hard") && !slices.Contains(argv, "--merge") {
		return ""
	}
	if sub == "restore" && slices.Contains(argv, "--staged") && !slices.Contains(argv, "--worktree") {
		return ""
	}
	if sub == "apply" && (slices.Contains(argv, "--check") || slices.Contains(argv, "--cached") || slices.Contains(argv, "--stat")) {
		return ""
	}
	if sub == "apply" {
		for _, arg := range argv[index+1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			places := guard.places(arg)
			if len(places) == 0 {
				break
			}
			patch, err := os.ReadFile(places[0])
			if err != nil || len(patch) > agentHookConfigMaxBytes {
				break
			}
			for _, line := range strings.Split(string(patch), "\n") {
				for _, prefix := range []string{"+++ b/", "--- a/", "rename to ", "rename from "} {
					if path, ok := strings.CutPrefix(line, prefix); ok && guard.shellTarget(strings.TrimSpace(path)) {
						return path
					}
				}
			}
			return "" // A readable patch with no registration target.
		}
	}
	// Explicit pathspecs are write operands for restore and checkout.
	pathspec := sub == "restore"
	for _, arg := range argv[index+1:] {
		if arg == "--" {
			pathspec = true
			continue
		}
		if pathspec && !strings.HasPrefix(arg, "-") && guard.shellTarget(arg) {
			return arg
		}
	}
	// A whole-worktree rewrite can replace any tracked hook document.
	for _, file := range guard.files {
		if strings.HasPrefix(file.Path, guard.cwd+string(filepath.Separator)) {
			if _, err := os.Stat(file.Path); err == nil {
				return file.Path
			}
		}
	}
	return ""
}

func agentHookConfigRunOverride(argv []string, guard *agentHookConfigGuard) (reason, target string) {
	if len(argv) < 2 {
		return "", ""
	}
	program := strings.ToLower(filepath.Base(argv[0]))
	if program == "env" {
		for index := 1; index < len(argv); index++ {
			if argv[index] == "--" {
				continue
			}
			if strings.HasPrefix(argv[index], "-") || strings.Contains(argv[index], "=") {
				continue
			}
			return agentHookConfigRunOverride(argv[index:], guard)
		}
		return "", ""
	}
	if program == "exec" || program == "command" || program == "nohup" {
		return agentHookConfigRunOverride(argv[1:], guard)
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
		if arg == "--settings" || arg == "--settings-file" || arg == "--config" || arg == "-c" {
			if index+1 >= len(argv) {
				continue
			}
			value = argv[index+1]
			index++
		} else if key, rest, ok := strings.Cut(arg, "="); ok && (key == "--settings" || key == "--settings-file" || key == "--config") {
			arg, value = key, rest
		} else {
			continue
		}
		if arg == "-c" && format == gatewayconnector.AgentHookConfigCodexTOML {
			key, setting, assigned := strings.Cut(value, "=")
			key = strings.TrimSpace(key)
			setting = strings.TrimSpace(setting)
			if assigned && (key == "features.hooks" || key == "features.codex_hooks") && setting != "true" {
				return "turns off hooks for a nested agent run", program
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(value), "{") {
			if why := agentHookConfigTurnsOff(format, nil, false, []byte(value), true); why != "" {
				return why, program
			}
			if document := agentHookConfigDocument(format, []byte(value)); document != nil {
				member := "hooks"
				if format == gatewayconnector.AgentHookConfigOpenCodeConfig {
					member = "plugin"
				}
				if entry, present := document[member]; present && len(agentHookConfigFingerprint(entry)) == 0 {
					return "omits DefenseClaw registration in per-run settings", program
				}
			}
			continue
		}
		if guard.shellTarget(value) || arg == "--settings" || arg == "--settings-file" || arg == "--config" {
			return "", value
		}
	}
	return "", ""
}
