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

// Package legacyconnector handles the connector ID DefenseClaw used before
// Windsurf was renamed Devin Desktop (Cognition).
//
// Windsurf was renamed Devin Desktop (Cognition). This is the only place
// DefenseClaw names the former connector ID and the pre-rename vendor paths
// Devin Desktop still reads; see docs.devin.ai/desktop/cascade/{hooks,memories,skills},
// checked 2026-09-26.
//
// The package has two jobs:
//
//   - Migration: config that still names the retired ID is moved to the
//     "devin" connector, whose Devin CLI hook contract Devin Desktop's default
//     agent (Devin Local) shares.
//   - Cleanup: hook entries an older DefenseClaw release wrote into the legacy
//     Cascade hooks file are removed, touching nothing DefenseClaw did not
//     write.
//
// It depends only on the standard library and internal/safefile so both the
// config loader and the connector package can import it.
package legacyconnector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	// RetiredDesktopID is the connector ID DefenseClaw used for the product
	// now called Devin Desktop. It is accepted only so old config and host
	// state can be migrated and cleaned up.
	RetiredDesktopID = "windsurf"
	// Replacement is the connector that now covers Devin Desktop.
	Replacement = "devin"

	// VendorToken is the vendor name third-party detection still matches.
	// Un-upgraded installs of the pre-rename app still exist on hosts.
	VendorToken = "windsurf"
	// ProcessName is the pre-rename desktop app's process name.
	ProcessName = "windsurf"
	// PublisherToken is the pre-rename publisher name vendor detection still
	// matches.
	PublisherToken = "codeium"

	// Headline starts every operator message about the rename.
	Headline = "Windsurf is now Devin Desktop"

	// maxCascadeHooksBytes bounds how much of the legacy hooks file is read.
	maxCascadeHooksBytes = 4 << 20
)

// InventoryDotDirs are the pre-rename per-user vendor directories. The
// vendor still reads them, so inventory and access-control code keeps them.
var InventoryDotDirs = []string{".windsurf", ".codeium"}

// DesktopDataName is the pre-rename app's user-data folder name (under the
// platform's application-support directory). Devin Desktop installs from
// before the rename keep their extension state there.
const DesktopDataName = "Windsurf"

// The vendor's IDE plugins still carry the pre-rename ids. The IDE inventory
// flags them as Devin plugins.
var (
	VSCodeExtensionIDs = []string{"codeium.codeium"}
	JetBrainsPluginIDs = []string{"com.codeium.intellij"}
	VimPlugins         = []string{"codeium.vim", "codeium.nvim", "windsurf.vim", "windsurf.nvim"}
)

// Canonical maps the retired Desktop ID to its replacement. The comparison
// ignores case and surrounding or embedded whitespace. Any other name is
// returned unchanged with migrated=false.
func Canonical(name string) (canonical string, migrated bool) {
	if isRetired(name) {
		return Replacement, true
	}
	return name, false
}

// IsRetired reports whether name is the retired Desktop ID.
func IsRetired(name string) bool { return isRetired(name) }

func isRetired(name string) bool {
	folded := strings.ToLower(strings.Join(strings.Fields(name), ""))
	return folded == RetiredDesktopID
}

// MigrateConnectorKeys applies the rename to a primary connector name and the
// keys of a per-connector settings map.
//
// Rule: an explicit replacement key wins, and every retired key is dropped
// (returned in dropped so the caller can tell the operator). Otherwise the
// first retired key, in sorted order, is renamed to the replacement so its
// settings (mode, fail_mode, enabled, ...) are kept; any further retired keys
// are dropped. rename maps each old key to the replacement.
func MigrateConnectorKeys(primary string, keys []string) (newPrimary string, rename map[string]string, dropped []string) {
	newPrimary, _ = Canonical(primary)
	var retired []string
	explicit := false
	for _, key := range keys {
		switch {
		case isRetired(key):
			retired = append(retired, key)
		case strings.EqualFold(strings.TrimSpace(key), Replacement):
			explicit = true
		}
	}
	if len(retired) == 0 {
		return newPrimary, nil, nil
	}
	sort.Strings(retired)
	if explicit {
		return newPrimary, nil, retired
	}
	rename = map[string]string{retired[0]: Replacement}
	if len(retired) > 1 {
		dropped = append(dropped, retired[1:]...)
	}
	return newPrimary, rename, dropped
}

// Notice describes one config migration for the operator.
func Notice(configPath string, dropped []string) string {
	where := strings.TrimSpace(configPath)
	if where == "" {
		where = "config"
	}
	msg := fmt.Sprintf("%s: moved connector %q to %q in %s", Headline, RetiredDesktopID, Replacement, where)
	if len(dropped) > 0 {
		msg += fmt.Sprintf(" (kept the existing %q settings and dropped %s)", Replacement, strings.Join(quoteAll(dropped), ", "))
	}
	return msg
}

func quoteAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, fmt.Sprintf("%q", v))
	}
	return out
}

// CascadeUserHooksPath is the legacy per-user Cascade hooks file. It is used
// only to remove entries an older DefenseClaw release wrote there.
func CascadeUserHooksPath(home string) string {
	return filepath.Join(home, ".codeium", "windsurf", "hooks.json")
}

// Pre-rename machine-level Cascade hooks folder names, which Devin Desktop
// still reads when no Devin one exists (docs.devin.ai/desktop/cascade/hooks):
// /Library/Application Support/Windsurf on macOS, /etc/windsurf on Linux and
// %ProgramData%\Windsurf on Windows.
const (
	CascadeMachineFolder     = "Windsurf"
	CascadeMachineFolderUnix = "windsurf"
)

// DesktopBundledCLIDir is where a Devin Desktop app keeps the Devin CLI it
// bundles, relative to the app's resources/app folder: the pre-rename
// extension folder extensions/windsurf/devin (from the 3.10 packages).
func DesktopBundledCLIDir() string {
	return filepath.Join("extensions", VendorToken, "devin")
}

// DesktopLegacyRulePaths are pre-rename rule locations Devin Desktop still
// loads. They are read-only inventory inputs.
func DesktopLegacyRulePaths(home, workspace string) []string {
	var out []string
	if strings.TrimSpace(home) != "" {
		out = append(out, filepath.Join(home, ".codeium", "windsurf", "memories", "global_rules.md"))
	}
	if ws := strings.TrimSpace(workspace); ws != "" {
		out = append(out,
			filepath.Join(ws, ".windsurf", "rules"),
			filepath.Join(ws, ".windsurfrules"),
		)
	}
	return out
}

// DesktopLegacySkillPaths are pre-rename skill locations Devin Desktop still
// loads. They are read-only inventory inputs.
func DesktopLegacySkillPaths(home, workspace string) []string {
	var out []string
	if strings.TrimSpace(home) != "" {
		out = append(out, filepath.Join(home, ".codeium", "windsurf", "skills"))
	}
	if ws := strings.TrimSpace(workspace); ws != "" {
		out = append(out, filepath.Join(ws, ".windsurf", "skills"))
	}
	return out
}

// OwnedHookScripts are the hook scripts an older DefenseClaw release installed
// for the retired connector.
func OwnedHookScripts(dataDir string) []string {
	if strings.TrimSpace(dataDir) == "" {
		return nil
	}
	hooks := filepath.Join(dataDir, "hooks")
	return []string{
		filepath.Join(hooks, RetiredDesktopID+"-hook.sh"),
		filepath.Join(hooks, RetiredDesktopID+"-hook.ps1"),
	}
}

// BackupDir is where an older release kept its pre-setup backup for the
// retired connector.
func BackupDir(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		return ""
	}
	return filepath.Join(dataDir, "connector_backups", RetiredDesktopID)
}

// NativeHookCommand is the exact PowerShell command pre-rename Windows builds
// wrote into the legacy hooks file for the retired connector.
func NativeHookCommand(hookBinary string) string {
	return "& " + powershellQuote(hookBinary) + " hook --connector " + RetiredDesktopID
}

// ownedCommands lists every exact command string DefenseClaw has written into
// the legacy Cascade hooks file.
func ownedCommands(dataDir string, hookBinaries []string) []string {
	var out []string
	for _, script := range OwnedHookScripts(dataDir) {
		out = append(out,
			script,
			shellQuote(script),
			`"`+script+`"`,
			"& "+powershellQuote(script),
			`& "`+script+`"`,
		)
	}
	for _, bin := range hookBinaries {
		if strings.TrimSpace(bin) == "" {
			continue
		}
		out = append(out, NativeHookCommand(bin))
	}
	return out
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func powershellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func commandMatches(command string, owned []string) bool {
	command = strings.TrimSpace(command)
	if command == "" {
		return false
	}
	for _, candidate := range owned {
		if runtime.GOOS == "windows" {
			if strings.EqualFold(command, candidate) {
				return true
			}
			continue
		}
		if command == candidate {
			return true
		}
	}
	return false
}

// ownedEntry reports whether one hook entry is a DefenseClaw registration.
func ownedEntry(raw interface{}, owned []string) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"command", "powershell", "bash"} {
		if value, ok := entry[key].(string); ok && commandMatches(value, owned) {
			return true
		}
	}
	return false
}

// readCascadeHooks returns the decoded file, its mode, and whether it exists.
func readCascadeHooks(path string) (map[string]interface{}, os.FileMode, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, true, fmt.Errorf("legacy hooks file %s is not a regular file", path)
	}
	data, err := safefile.ReadRegularFileBounded(path, maxCascadeHooksBytes)
	if err != nil {
		return nil, 0, true, err
	}
	var cfg map[string]interface{}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, info.Mode().Perm(), true, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, 0, true, fmt.Errorf("parse legacy hooks file %s: %w", path, err)
	}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	return cfg, info.Mode().Perm(), true, nil
}

// pruneOwned removes owned entries from every event list and drops event keys
// left empty. It returns how many entries were removed.
func pruneOwned(cfg map[string]interface{}, owned []string) int {
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return 0
	}
	removed := 0
	for event, raw := range hooks {
		list, ok := raw.([]interface{})
		if !ok {
			continue
		}
		kept := make([]interface{}, 0, len(list))
		for _, item := range list {
			if ownedEntry(item, owned) {
				removed++
				continue
			}
			kept = append(kept, item)
		}
		if len(kept) == len(list) {
			continue
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}
	return removed
}

// CountOwnedCascadeHooks reports how many DefenseClaw entries remain in the
// legacy hooks file. A missing file counts as zero.
func CountOwnedCascadeHooks(path, dataDir string, hookBinaries ...string) (int, error) {
	if strings.TrimSpace(path) == "" {
		return 0, nil
	}
	cfg, _, exists, err := readCascadeHooks(path)
	if err != nil || !exists {
		return 0, err
	}
	return pruneOwned(cfg, ownedCommands(dataDir, hookBinaries)), nil
}

// RemoveOwnedCascadeHooks strips the DefenseClaw entries an older release
// wrote into the legacy Cascade hooks file at path.
//
// An entry is DefenseClaw's only when its command, powershell or bash field
// is exactly one of the forms DefenseClaw wrote for a script in
// OwnedHookScripts(dataDir), or the native hook command for one of
// hookBinaries. Foreign entries are kept; event keys left empty are dropped.
// The file is rewritten atomically with its original permission bits. A
// missing file is a no-op, malformed JSON is left untouched and reported, and
// a second call removes nothing.
func RemoveOwnedCascadeHooks(path, dataDir string, hookBinaries ...string) (removed int, err error) {
	if strings.TrimSpace(path) == "" {
		return 0, nil
	}
	cfg, mode, exists, err := readCascadeHooks(path)
	if err != nil || !exists {
		return 0, err
	}
	removed = pruneOwned(cfg, ownedCommands(dataDir, hookBinaries))
	if removed == 0 {
		return 0, nil
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return 0, fmt.Errorf("encode legacy hooks file %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := safefile.Write(path, data); err != nil {
		return 0, fmt.Errorf("write legacy hooks file %s: %w", path, err)
	}
	if runtime.GOOS != "windows" && mode != 0 {
		if err := os.Chmod(path, mode); err != nil {
			return removed, fmt.Errorf("restore mode on legacy hooks file %s: %w", path, err)
		}
	}
	return removed, nil
}
