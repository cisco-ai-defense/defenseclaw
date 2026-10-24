// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GitHub Copilot in VS Code runs agent-mode hooks in its Local harness. That
// harness does not read Copilot's machine policy.d directory, so DefenseClaw
// governs it with a per-user hook file and, where the lock is wanted, a
// per-user plugin that managed settings enable:
//
//   - ~/.copilot/hooks/defenseclaw-vscode.json: PascalCase events, each
//     running the administrator's hook binary with --hook-surface
//     vscode-local. The Copilot CLI also reads this directory and runs the
//     command field, so the gateway collapses the CLI's second delivery of
//     one tool call (see the gateway's Copilot dedupe).
//   - ~/.copilot/installed-plugins/defenseclaw/defenseclaw/: the same hooks
//     as a plugin, which VS Code keeps running when allowManagedHooksOnly
//     drops user hook files.
//
// Both are rendered from the administrator's hook binary only, so the guard
// recognizes every handler as DefenseClaw's by exact command equality (the
// current render, or the one 1.0.0 wrote until the guardian rewrites it).

// CopilotVSCodeLocalHookFileName is the per-user Local harness hook file.
const CopilotVSCodeLocalHookFileName = "defenseclaw-vscode.json"

// CopilotPluginMarketplace and CopilotPluginName name DefenseClaw's
// per-user Copilot plugin (enabledPlugins key "defenseclaw@defenseclaw").
const (
	CopilotPluginMarketplace = "defenseclaw"
	CopilotPluginName        = "defenseclaw"
	CopilotPluginKey         = CopilotPluginName + "@" + CopilotPluginMarketplace
)

// copilotVSCodeLocalHookTimeout is the handler timeout VS Code honors
// (seconds); the hook's gateway request finishes inside it.
const copilotVSCodeLocalHookTimeout = 30

// CopilotVSCodeLocalHookFilePath is the Local hook file under home.
func CopilotVSCodeLocalHookFilePath(home string) string {
	return filepath.Join(home, ".copilot", "hooks", CopilotVSCodeLocalHookFileName)
}

// CopilotPluginDir is DefenseClaw's plugin directory under home.
func CopilotPluginDir(home string) string {
	return filepath.Join(home, ".copilot", "installed-plugins", CopilotPluginMarketplace, CopilotPluginName)
}

// CopilotPluginHooksPath is the hook document of DefenseClaw's plugin under
// home.
func CopilotPluginHooksPath(home string) string {
	return filepath.Join(CopilotPluginDir(home), "hooks", "hooks.json")
}

// RenderCopilotVSCodeLocalHooks renders the Local harness hook document for
// the administrator's hook binary on goos.
func RenderCopilotVSCodeLocalHooks(goos, hookBinary string) ([]byte, error) {
	if strings.TrimSpace(hookBinary) == "" {
		return nil, errors.New("copilot vscode local hooks: hook binary is empty")
	}
	hooks := newObject()
	for _, event := range connector.CopilotVSCodeLocalHookEvents {
		handler := newObject()
		handler.set("type", "command")
		handler.set("command", connector.CopilotVSCodeLocalManagedHookCommand(goos, hookBinary, event))
		handler.set("timeout", copilotVSCodeLocalHookTimeout)
		hooks.set(event, []any{handler})
	}
	doc := newObject()
	doc.set("hooks", hooks)
	return encodeOrdered(doc)
}

// renderCopilotPluginManifest is the plugin's manifest; hooks load from the
// plugin's hooks/hooks.json.
func renderCopilotPluginManifest() ([]byte, error) {
	doc := newObject()
	doc.set("name", CopilotPluginName)
	doc.set("description", "DefenseClaw guardrail hooks")
	doc.set("version", "1.0.0")
	doc.set("hooks", "hooks/hooks.json")
	return encodeOrdered(doc)
}

// copilotVSCodeLocalCommandOwned reports whether command is exactly the
// Local harness command DefenseClaw renders for one of its events, or the
// one DefenseClaw 1.0.0 rendered for the same binary
// (connector.CopilotVSCodeLocalPriorReleaseHookCommand): an upgraded
// install rewrites that one instead of keeping it, and the foreign-hook
// guard never blocks it (GAP-1232).
func copilotVSCodeLocalCommandOwned(goos, hookBinary, command string) bool {
	if strings.TrimSpace(hookBinary) == "" || command == "" {
		return false
	}
	for _, event := range connector.CopilotVSCodeLocalHookEvents {
		if command == strings.TrimSpace(connector.CopilotVSCodeLocalManagedHookCommand(goos, hookBinary, event)) ||
			command == strings.TrimSpace(connector.CopilotVSCodeLocalPriorReleaseHookCommand(goos, hookBinary, event)) {
			return true
		}
	}
	return false
}

// CopilotVSCodeUserResult reports one user's Local hook file and plugin.
type CopilotVSCodeUserResult struct {
	HookFile   string   `json:"hook_file,omitempty"`
	PluginDir  string   `json:"plugin_dir,omitempty"`
	Changed    []string `json:"changed,omitempty"`
	Removed    []string `json:"removed,omitempty"`
	Kept       []string `json:"kept,omitempty"`
	PluginOK   bool     `json:"plugin_ok,omitempty"`
	HookFileOK bool     `json:"hook_file_ok,omitempty"`
	// CreatedDirs are the folders below the home this call created for
	// the files (~/.copilot, ~/.copilot/hooks and the like). The caller
	// keeps them and passes them back as RemoveDirs, so the removal takes
	// them out again once they are empty.
	CreatedDirs []string `json:"created_dirs,omitempty"`
}

// CopilotVSCodeUserRequest selects what the user's home should hold. It runs
// as the user (the Unix per-user worker, or the Windows target-user
// impersonation), never as the administrator in a user's home.
type CopilotVSCodeUserRequest struct {
	Home       string
	GOOS       string
	HookBinary string
	// HookFile keeps the Local hook file; false removes DefenseClaw's copy.
	HookFile bool
	// Plugin keeps the plugin; false removes DefenseClaw's copy.
	Plugin bool
	// DryRun reports in Changed and Removed what would change, touching
	// nothing (verify).
	DryRun bool
	// RemoveDirs are folders below Home an earlier call created
	// (CreatedDirs); each one still empty after this call is removed.
	RemoveDirs []string
}

// EnsureCopilotVSCodeUser writes or removes DefenseClaw's Local hook file
// and plugin under Home. Regular hook documents can contain independent
// handlers even at DefenseClaw's file name; those handlers are preserved on
// removal and prevent a setup from claiming the file as its own render.
// Non-file entries at the dedicated Local hook path are replaced as before.
func EnsureCopilotVSCodeUser(req CopilotVSCodeUserRequest) (CopilotVSCodeUserResult, error) {
	var result CopilotVSCodeUserResult
	home := strings.TrimSpace(req.Home)
	if home == "" || !filepath.IsAbs(home) {
		return result, fmt.Errorf("copilot vscode: home %q is not absolute", req.Home)
	}
	goos := req.GOOS
	if goos == "" {
		goos = runtimeGOOS()
	}
	hooks, err := RenderCopilotVSCodeLocalHooks(goos, req.HookBinary)
	if err != nil {
		return result, err
	}
	manifest, err := renderCopilotPluginManifest()
	if err != nil {
		return result, err
	}
	result.HookFile = CopilotVSCodeLocalHookFilePath(home)
	result.PluginDir = CopilotPluginDir(home)
	pluginHooks := CopilotPluginHooksPath(home)
	pluginManifest := filepath.Join(result.PluginDir, "plugin.json")
	var missing []string
	if !req.DryRun {
		home = filepath.Clean(home)
		for _, path := range []string{result.HookFile, pluginHooks, pluginManifest} {
			missing = append(missing, missingDirsBelow(home, path)...)
		}
	}
	var errs []error
	if ok, err := ensureCopilotHookDocument(&result, result.HookFile, hooks, goos, req.HookBinary, true, req.HookFile, req.DryRun); err != nil {
		errs = append(errs, err)
	} else {
		result.HookFileOK = ok
	}
	hooksOK, err := ensureCopilotHookDocument(&result, pluginHooks, hooks, goos, req.HookBinary, false, req.Plugin, req.DryRun)
	if err != nil {
		errs = append(errs, err)
	}
	manifestOK := false
	if !slices.Contains(result.Kept, pluginHooks) {
		manifestOK, err = ensureOwnedUserFile(&result, pluginManifest, manifest, false, nil, req.Plugin, req.DryRun)
		if err != nil {
			errs = append(errs, err)
		}
	}
	result.PluginOK = req.Plugin && hooksOK && manifestOK
	if !req.Plugin && !req.DryRun {
		// Remove the now-empty plugin directories we created.
		for _, dir := range []string{filepath.Join(result.PluginDir, "hooks"), result.PluginDir, filepath.Dir(result.PluginDir)} {
			_ = os.Remove(dir)
		}
	}
	for _, dir := range missing {
		if info, err := os.Lstat(dir); err == nil && info.IsDir() && !slices.Contains(result.CreatedDirs, dir) {
			result.CreatedDirs = append(result.CreatedDirs, dir)
		}
	}
	if !req.DryRun {
		removeEmptyDirsBelow(home, req.RemoveDirs)
	}
	return result, errors.Join(errs...)
}

// stripCopilotVSCodeOwnedHooks removes only the commands rendered for this
// binary by the current or the released 1.0.0 Local hook contract.
func stripCopilotVSCodeOwnedHooks(data []byte, goos, hookBinary string) ([]byte, bool, bool, error) {
	doc, err := decodeOrderedObject(data)
	if err != nil {
		return nil, false, false, err
	}
	foreignTopLevel := false
	for _, key := range doc.keys {
		if key != "hooks" && key != "version" {
			foreignTopLevel = true
		}
	}
	value, present := doc.get("hooks")
	if !present || value == nil {
		if !foreignTopLevel {
			return nil, true, false, nil
		}
		return data, false, foreignTopLevel, nil
	}
	hooks, ok := value.(*object)
	if !ok {
		return nil, false, false, errors.New("hooks is not an object")
	}
	owned, foreign := false, foreignTopLevel
	for _, event := range append([]string(nil), hooks.keys...) {
		value, _ := hooks.get(event)
		list, ok := value.([]any)
		if !ok {
			return nil, false, false, fmt.Errorf("event %s is not a handler list", event)
		}
		remaining := make([]any, 0, len(list))
		for _, handler := range list {
			if !copilotVSCodeHandlerOwned(handler, goos, hookBinary) {
				foreign = true
				remaining = append(remaining, handler)
				continue
			}
			owned = true
		}
		if len(remaining) == 0 && len(list) > 0 {
			hooks.delete(event)
		} else if len(remaining) != len(list) {
			hooks.set(event, remaining)
		}
	}
	if !owned {
		if !foreign {
			// An empty copy at DefenseClaw's own plugin path is a
			// truncated or cleared hook document, not an independent hook.
			return nil, true, false, nil
		}
		return data, false, foreign, nil
	}
	if hooks.len() == 0 {
		doc.delete("hooks")
	}
	if doc.len() == 0 || (doc.len() == 1 && doc.keys[0] == "version") {
		return nil, true, false, nil
	}
	remaining, err := encodeOrdered(doc)
	return remaining, true, true, err
}

func copilotVSCodeHandlerOwned(handler any, goos, hookBinary string) bool {
	entry, ok := handler.(*object)
	if !ok || stringField(entry, "type") != "command" ||
		!copilotVSCodeLocalCommandOwned(goos, hookBinary, stringField(entry, "command")) {
		return false
	}
	for _, key := range entry.keys {
		if key != "type" && key != "command" && key != "timeout" && key != "timeoutSec" {
			return false
		}
	}
	return true
}

// repairMalformedCopilotHookDocument salvages root-level independent content
// from a damaged document. A parseable independent handler makes the file
// ambiguous, so the caller leaves it untouched.
func repairMalformedCopilotHookDocument(current, want []byte, goos, hookBinary string) (repaired, admin []byte, repairable bool, err error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return want, nil, true, nil
	}
	value, _ := doc.get("hooks")
	if hooks, ok := value.(*object); ok {
		for _, event := range hooks.keys {
			value, _ := hooks.get(event)
			list, ok := value.([]any)
			if !ok {
				continue
			}
			for _, handler := range list {
				if !copilotVSCodeHandlerOwned(handler, goos, hookBinary) {
					return nil, nil, false, nil
				}
			}
		}
	}
	doc.delete("hooks")
	if doc.len() > 0 && (doc.len() != 1 || doc.keys[0] != "version") {
		admin, err = encodeOrdered(doc)
		if err != nil {
			return nil, nil, false, err
		}
	}
	wantDoc, err := decodeOrderedObject(want)
	if err != nil {
		return nil, nil, false, err
	}
	wantHooks, _ := wantDoc.get("hooks")
	doc.set("hooks", wantHooks)
	repaired, err = encodeOrdered(doc)
	return repaired, admin, true, err
}

func ensureCopilotHookDocument(result *CopilotVSCodeUserResult, path string, want []byte, goos, hookBinary string, outright, keep, dryRun bool) (bool, error) {
	current, exists, regular, err := readUserFile(path, int64(policyFileLimit))
	if err != nil {
		return false, err
	}
	if exists && !regular {
		if outright {
			return ensureOwnedUserFile(result, path, want, true, nil, keep, dryRun)
		}
		result.Kept = append(result.Kept, path)
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	if !exists {
		if !keep {
			return false, nil
		}
		return ensureOwnedUserFile(result, path, want, outright, nil, true, dryRun)
	}
	if len(bytes.TrimSpace(current)) == 0 {
		if keep {
			return ensureOwnedUserFile(result, path, want, outright, nil, true, dryRun)
		}
		return ensureOwnedUserFile(result, path, want, outright, func([]byte) bool { return true }, false, dryRun)
	}
	admin, owned, foreign, err := stripCopilotVSCodeOwnedHooks(current, goos, hookBinary)
	if err != nil {
		repaired, remaining, repairable, repairErr := repairMalformedCopilotHookDocument(current, want, goos, hookBinary)
		if repairErr != nil {
			return false, repairErr
		}
		if repairable {
			if keep {
				return ensureOwnedUserFile(result, path, repaired, true, nil, true, dryRun)
			}
			if len(remaining) == 0 {
				return ensureOwnedUserFile(result, path, want, true, nil, false, dryRun)
			}
			if !dryRun {
				if err := writePrivateUserFile(path, remaining); err != nil {
					return false, err
				}
			}
			result.Removed = append(result.Removed, path)
			return false, nil
		}
		result.Kept = append(result.Kept, path)
		return false, nil
	}
	if keep {
		if foreign {
			result.Kept = append(result.Kept, path)
			return false, nil
		}
		return ensureOwnedUserFile(result, path, want, outright, func([]byte) bool { return owned }, true, dryRun)
	}
	if !owned {
		if foreign {
			result.Kept = append(result.Kept, path)
		}
		return false, nil
	}
	if len(bytes.TrimSpace(admin)) != 0 {
		// The plugin still needs its manifest for the independent hooks.
		result.Kept = append(result.Kept, path)
	}
	if dryRun {
		result.Removed = append(result.Removed, path)
		return false, nil
	}
	if len(bytes.TrimSpace(admin)) == 0 {
		if err := os.Remove(path); err != nil {
			return false, err
		}
	} else if err := writePrivateUserFile(path, admin); err != nil {
		return false, err
	}
	result.Removed = append(result.Removed, path)
	return false, nil
}

// missingDirsBelow returns the missing folders between home and path,
// deepest first.
func missingDirsBelow(home, path string) []string {
	var missing []string
	for dir := filepath.Dir(filepath.Clean(path)); strictlyBelow(home, dir); dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			break
		}
		missing = append(missing, dir)
	}
	return missing
}

// removeEmptyDirsBelow removes, deepest first, each of dirs that is strictly
// below home and still an empty folder reached through real folders from
// home; anything else stays.
func removeEmptyDirsBelow(home string, dirs []string) {
	home = filepath.Clean(home)
	sorted := append([]string(nil), dirs...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, dir := range sorted {
		dir = filepath.Clean(dir)
		if !strictlyBelow(home, dir) {
			continue
		}
		real := true
		for current := dir; current != home; current = filepath.Dir(current) {
			if info, err := os.Lstat(current); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				real = false
				break
			}
		}
		if real {
			_ = os.Remove(dir) // only an empty folder goes
		}
	}
}

// strictlyBelow reports whether path is inside root and not root itself.
func strictlyBelow(root, path string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

// ensureOwnedUserFile makes path hold want (keep) or not exist (!keep). An
// outright path is DefenseClaw's own name: whatever is there (edited
// content, or a link, directory or other entry) is replaced or removed.
// Any other path is touched only when it is absent, holds want, or mine
// (nil: never) claims its other content as DefenseClaw's. It reports
// whether path now holds want.
func ensureOwnedUserFile(result *CopilotVSCodeUserResult, path string, want []byte, outright bool, mine func([]byte) bool, keep, dryRun bool) (bool, error) {
	limit := int64(policyFileLimit)
	if outright {
		limit = int64(len(want))
	}
	current, exists, regular, err := readUserFile(path, limit)
	var tooLarge *readLimitError
	if outright && errors.As(err, &tooLarge) {
		err = nil // larger than want, so not current
	}
	if err != nil {
		return false, err
	}
	if exists && !outright {
		if !regular {
			result.Kept = append(result.Kept, path)
			return false, fmt.Errorf("%s is not a regular file", path)
		}
		if !bytes.Equal(current, want) && (mine == nil || !mine(current)) {
			result.Kept = append(result.Kept, path)
			return false, nil
		}
	}
	if !keep {
		if exists {
			if !dryRun {
				if err := os.RemoveAll(path); err != nil {
					return false, err
				}
			}
			result.Removed = append(result.Removed, path)
		}
		return false, nil
	}
	if exists && regular && bytes.Equal(current, want) {
		return true, nil
	}
	if dryRun {
		result.Changed = append(result.Changed, path)
		return false, nil
	}
	// An outright path is cleared first: the rename in writePrivateUserFile
	// cannot replace a file a user marked read-only on Windows, and
	// os.Remove clears that attribute.
	if exists && (!regular || outright) {
		if err := os.RemoveAll(path); err != nil {
			return false, err
		}
	}
	if err := writePrivateUserFile(path, want); err != nil {
		return false, err
	}
	result.Changed = append(result.Changed, path)
	return true, nil
}

// readUserFile reads a file a user controls without following a final
// link, blocking on a FIFO or reading past limit: the guardian runs as root
// (SYSTEM on Windows) over these paths. exists reports an entry at path;
// regular reports that it is a regular file (data is read only then).
func readUserFile(path string, limit int64) (data []byte, exists, regular bool, err error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, false, false, nil
	}
	if err != nil {
		return nil, false, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, false, nil
	}
	file, err := openGuardFile(path)
	if err != nil {
		// Swapped for a link or another entry since the Lstat.
		return nil, true, false, err
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, true, false, err
	}
	data, err = readBounded(file, limit)
	return data, true, true, err
}

// ownedHooksDocument reports a flat hook document whose every handler is
// DefenseClaw's own (an earlier render for another binary path is not).
func (r GuardRequest) ownedHooksDocument(data []byte) bool {
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return false
	}
	for _, key := range doc.keys {
		if key != "hooks" && key != "version" {
			return false
		}
	}
	value, _ := doc.get("hooks")
	hooks, ok := value.(*object)
	if !ok {
		return false
	}
	handlers := 0
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, handler := range list {
			if !r.ownedHandler(handler) {
				return false
			}
			handlers++
		}
	}
	return handlers > 0
}

// CopilotVSCodeUserFilesLeft reports, read-only, whether home still holds
// DefenseClaw's Local hook file or plugin: what removing the user's Copilot
// row takes out. Their hook command is an encoded PowerShell bridge on
// Windows, which the generic hook-command search cannot read (GAP-2098).
func CopilotVSCodeUserFilesLeft(home, goos, hookBinary string) (bool, error) {
	result, err := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: goos, HookBinary: hookBinary, DryRun: true})
	return len(result.Removed) > 0, err
}

// CopilotVSCodeUserState reports, read-only, whether home holds
// DefenseClaw's current Local hook file and plugin (verify and status).
func CopilotVSCodeUserState(home, goos, hookBinary string) (hookFile, plugin bool) {
	hooks, err := RenderCopilotVSCodeLocalHooks(goos, hookBinary)
	if err != nil {
		return false, false
	}
	manifest, _ := renderCopilotPluginManifest()
	same := func(path string, want []byte) bool {
		data, _, regular, err := readUserFile(path, int64(len(want)))
		return err == nil && regular && bytes.Equal(data, want)
	}
	return same(CopilotVSCodeLocalHookFilePath(home), hooks),
		same(CopilotPluginHooksPath(home), hooks) && same(filepath.Join(CopilotPluginDir(home), "plugin.json"), manifest)
}

// copilotVSCodeUserKept reports, read-only, the Local hook and plugin files
// that the guardian leaves in place because they hold independent content
// (an earlier DefenseClaw render is replaced, not kept).
func copilotVSCodeUserKept(home, goos, hookBinary string) []string {
	result, _ := EnsureCopilotVSCodeUser(CopilotVSCodeUserRequest{Home: home, GOOS: goos, HookBinary: hookBinary, HookFile: true, Plugin: true, DryRun: true})
	return result.Kept
}
