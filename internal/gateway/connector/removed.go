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

package connector

// until 1.1 (the last release that upgrades a 1.0.2 to 1.0.4 host):
// DefenseClaw no longer supports OpenHands or OmniGent. A host an older
// release set up may still have what that setup wrote for them. The teardown
// of these teardown-only connectors removes exactly that, by identity (what
// DefenseClaw wrote is DefenseClaw's, the rule uninstall uses for every
// connector), and nothing else:
//
//   - its entries in the agent configs: OpenHands hooks whose command runs
//     DefenseClaw's hook script by its path (<data>/hooks/openhands-hook.sh or
//     a hook script path the lock entry records), any file that carries
//     DefenseClaw's OpenHands hook marker (such as a hard link or copy of it),
//     or the native launcher's OpenHands connector. A name alone is not
//     identity: an operator's own openhands-hook.sh elsewhere stays; OmniGent's policy_modules entry and the
//     policies whose handler is in DefenseClaw's policy module. Every other
//     entry of the file stays;
//   - once no agent config runs or imports it: the hook script or policy
//     module under <data>/hooks when it carries DefenseClaw's marker (any
//     release, including the 1.0.4 stub), DefenseClaw's line in OmniGent's
//     import-path file, the setup receipts under connector_backups/<name> and
//     the connector's hook contract lock entry;
//   - its tokens and its .hookcfg record.
//
// Nothing blocks: DefenseClaw no longer guards these agents. Teardown and
// VerifyClean never fail on what is left (an upgrade, ensure, repair or
// uninstall must not stop on a leftover reference); RemovedConnectorLeftovers
// lists it as information, under RemovedConnectorNotice, for status, doctor,
// uninstall and the installers.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// RemovedConnectorNotice is the one line every surface prints for a host an
// older release set up for OpenHands or OmniGent.
const RemovedConnectorNotice = "OpenHands/OmniGent support was removed in 1.0.5; DefenseClaw no longer guards it."

const (
	removedOpenHandsID         = "openhands"
	removedOpenHandsHookScript = "openhands-hook.sh"
	removedOmnigentID          = "omnigent"
	removedOmnigentModuleName  = "defenseclaw_omnigent_policy"
	removedOmnigentPolicyKey   = "defenseclaw_guardrail"
	// removedScriptReadLimit bounds the read of a hook script: anything
	// larger is not one DefenseClaw wrote.
	removedScriptReadLimit = 1 << 20
	// removedMarkerLines is how many leading lines may hold the marker.
	removedMarkerLines = 3
)

// removedConfigReadLimit bounds the read of an agent config; a larger one is
// listed for a check by hand. A var for tests.
var removedConfigReadLimit = 256 << 20

// removedOnlyConnector is the teardown-only connector of a removed connector.
type removedOnlyConnector struct {
	name, label string
	// script is the hook script or policy module an older setup wrote under
	// <data>/hooks; marker starts one of its first lines.
	script, marker string
	configStep     string
}

// removedOpenHandsLauncherFlag is how a Windows hooks.json command names the
// OpenHands connector of the native launcher (defenseclaw-hook --connector
// openhands).
var removedOpenHandsLauncherFlag = regexp.MustCompile(`(?i)--connector(?:\s*=\s*|\s+)["']?open[-_]?hands\b`)

var (
	removedOpenHands = removedOnlyConnector{
		name: removedOpenHandsID, label: "OpenHands",
		script: removedOpenHandsHookScript, marker: "# defenseclaw-managed-hook v",
		configStep: "remove every hook whose command runs " + removedOpenHandsHookScript +
			" (or defenseclaw-hook --connector openhands) from this file, then restart OpenHands",
	}
	removedOmnigent = removedOnlyConnector{
		name: removedOmnigentID, label: "OmniGent",
		script: removedOmnigentModuleName + ".py", marker: "# defenseclaw-managed-policy v",
		configStep: "remove " + removedOmnigentModuleName + " from policy_modules and the " + removedOmnigentPolicyKey +
			" policy (handler " + removedOmnigentModuleName + ".defenseclaw_policy) from this file, then restart OmniGent",
	}
)

// removedConnector returns the teardown-only connector for a removed
// connector ID, or false.
func removedConnector(name string) (Connector, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return nil, false
	}
	return c, true
}

func removedConnectorFor(name string) (removedOnlyConnector, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case removedOpenHandsID, "open-hands", "open_hands":
		return removedOpenHands, true
	case removedOmnigentID:
		return removedOmnigent, true
	}
	return removedOnlyConnector{}, false
}

// IsRemovedConnector reports whether name is OpenHands or OmniGent.
func IsRemovedConnector(name string) bool {
	_, ok := removedConnectorFor(name)
	return ok
}

func (c removedOnlyConnector) Name() string { return c.name }

func (c removedOnlyConnector) Description() string {
	return c.label + " is no longer supported; teardown only"
}

func (c removedOnlyConnector) ToolInspectionMode() ToolInspectionMode { return ToolModePreExecution }

func (c removedOnlyConnector) SubprocessPolicy() SubprocessPolicy { return SubprocessNone }

func (c removedOnlyConnector) Setup(context.Context, SetupOpts) error {
	return fmt.Errorf("connector %q is no longer supported; choose a supported connector", c.name)
}

func (c removedOnlyConnector) Authenticate(*http.Request) bool { return false }

func (c removedOnlyConnector) Route(*http.Request, []byte) (*ConnectorSignals, error) {
	return nil, fmt.Errorf("connector %q was removed", c.name)
}

func (c removedOnlyConnector) SetCredentials(string, string) {}

func (c removedOnlyConnector) scriptPath(dataDir string) string {
	return filepath.Join(dataDir, "hooks", c.script)
}

// Teardown removes what an older setup wrote for the connector (see the file
// comment). It never fails: what it cannot remove stays and is listed by
// RemovedConnectorLeftovers.
func (c removedOnlyConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	defer RemoveIdleFileLockSentinels()
	// The config paths come from the setup receipts and the lock entry, so
	// they are read before either goes.
	configs := c.configPaths(opts)
	names := c.namesFor(opts)
	for _, path := range configs {
		_ = c.removeEntries(path, names, opts.DataDir)
	}
	hooks := filepath.Join(opts.DataDir, "hooks")
	_ = RemoveHookAPIToken(opts.DataDir, c.name)
	token := filepath.Join(hooks, otlpPathTokenFileName(OTLPPathTokenScope(c.name)))
	for _, path := range []string{token, token + ".tmp"} {
		_ = removeOwnedOTLPPathTokenFile(path)
	}
	_ = removeRegularFile(filepath.Join(hooks, hookConfigSidecarName+"."+c.name))
	if len(c.liveRegistrations(configs, names)) > 0 {
		// A valid config still runs or imports the script in a form this
		// cleanup does not remove: the script, receipts and lock entry stay
		// for it, and the leftover list names the file.
		return nil
	}
	if c.name == removedOmnigentID {
		_ = removeOmnigentImportPath(opts.DataDir)
		pycache, _ := filepath.Glob(filepath.Join(hooks, "__pycache__", removedOmnigentModuleName+".*.pyc"))
		for _, path := range pycache {
			_ = removeRegularFile(path)
		}
	}
	if c.ownsScript(c.scriptPath(opts.DataDir)) {
		_ = removeRegularFile(c.scriptPath(opts.DataDir))
	}
	c.removeReceipts(opts.DataDir)
	_ = ClearHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise)
	return nil
}

// VerifyClean never fails: nothing a removed connector leaves guards or
// blocks anything, and RemovedConnectorLeftovers lists it.
func (c removedOnlyConnector) VerifyClean(SetupOpts) error { return nil }

// removeRegularFile removes path when it is a regular file (never a link or a
// folder).
func removeRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// removeReceipts removes the setup receipts (connector_backups/<name>/*.json)
// and DefenseClaw's own recovery records there, then the folder when nothing
// else is in it. Anything else (a copy 1.0.4 saved of an edited module) stays
// and is listed.
func (c removedOnlyConnector) removeReceipts(dataDir string) {
	dir := filepath.Join(dataDir, "connector_backups", c.name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".defenseclaw-cas-") {
			_ = removeRegularFile(filepath.Join(dir, name))
		}
	}
	_ = os.Remove(dir)
}

// ownsScript reports whether path is a regular file of DefenseClaw's: its
// marker is in its first lines.
func (c removedOnlyConnector) ownsScript(path string) bool {
	data, ok := readMarkedCandidate(path)
	return ok && removedHasMarker(data, c.marker)
}

// readMarkedCandidate reads a regular file (through links, as the agent
// does) up to removedScriptReadLimit; false for anything else.
func readMarkedCandidate(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit {
		return nil, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// removedHasMarker reports whether one of the first lines of data starts with
// marker.
func removedHasMarker(data []byte, marker string) bool {
	lines := bytes.SplitN(data, []byte("\n"), removedMarkerLines+1)
	if len(lines) > removedMarkerLines {
		lines = lines[:removedMarkerLines]
	}
	for _, line := range lines {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte(marker)) {
			return true
		}
	}
	return false
}

// namesFor returns the identity rule for one host's agent configs: whether
// one config text (a command, a module name) is DefenseClaw's. For OpenHands
// a command is DefenseClaw's only when it runs DefenseClaw's hook script by
// its path (ownedHookPaths), runs a file that carries DefenseClaw's
// OpenHands hook marker, or names the native launcher's OpenHands
// connector. The script name alone is not identity: an operator's own
// ~/scripts/openhands-hook.sh or my-openhands-hook.sh stays (GAP-1842). For
// OmniGent the text names DefenseClaw's policy module.
func (c removedOnlyConnector) namesFor(opts SetupOpts) func(string) bool {
	if c.name == removedOmnigentID {
		return func(text string) bool { return strings.Contains(strings.ToLower(text), removedOmnigentModuleName) }
	}
	paths := c.ownedHookPaths(opts)
	return func(text string) bool {
		return removedOpenHandsLauncherFlag.MatchString(text) || removedRunsPath(text, paths) || removedRunsMarkedHook(text)
	}
}

// ownedHookPaths are the paths an older setup wrote the hook script to, as
// a command names them: <data>/hooks/<script> and the hook script paths of
// that name the lock entry records, each also as ~/... when under the home.
func (c removedOnlyConnector) ownedHookPaths(opts SetupOpts) []string {
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	paths := []string{c.scriptPath(removedAbsolute(opts.DataDir))}
	if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
		for _, path := range entry.Locations.HookScriptPaths {
			if filepath.Base(path) == c.script {
				paths = append(paths, removedAbsolute(path))
			}
		}
	}
	home := homePath()
	for _, path := range paths {
		if rel, err := filepath.Rel(home, path); home != "" && err == nil && rel != ".." &&
			!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			paths = append(paths, "~/"+filepath.ToSlash(rel))
		}
	}
	return uniqueNonEmptyStrings(paths)
}

// removedWordEdge are the bytes that may stand next to a path in a command.
const removedWordEdge = " \t\r\n\"'`=;&|()"

// removedRunsPath reports whether a command names one of paths whole: the
// bare path (which may hold spaces, as an older setup wrote it) or the path
// in quotes, never a longer name that ends with it.
func removedRunsPath(command string, paths []string) bool {
	fold := func(text string) string {
		if runtime.GOOS == "windows" {
			return strings.ToLower(strings.ReplaceAll(text, `\`, "/"))
		}
		return text
	}
	text := fold(command)
	for _, path := range paths {
		word := fold(path)
		for from := 0; word != "" && from < len(text); {
			i := strings.Index(text[from:], word)
			if i < 0 {
				break
			}
			start, end := from+i, from+i+len(word)
			if (start == 0 || strings.IndexByte(removedWordEdge, text[start-1]) >= 0) &&
				(end == len(text) || strings.IndexByte(removedWordEdge, text[end]) >= 0) {
				return true
			}
			from = start + 1
		}
	}
	return false
}

// removedRunsMarkedHook reports whether a command runs a file (an absolute
// or ~ path among its words) that holds DefenseClaw's OpenHands hook: its
// hook marker in its first lines and the OpenHands name. A hard link or copy
// of openhands-hook.sh under any name is DefenseClaw's hook.
func removedRunsMarkedHook(command string) bool {
	for _, word := range strings.Fields(command) {
		word = strings.Trim(word, `"';,`)
		if !filepath.IsAbs(word) && !strings.HasPrefix(word, "~/") {
			continue
		}
		data, ok := readMarkedCandidate(removedAbsolute(word))
		if ok && removedHasMarker(data, removedOpenHands.marker) && bytes.Contains(bytes.ToLower(data), []byte("openhands")) {
			return true
		}
	}
	return false
}

// configNames reports whether an agent config still names DefenseClaw's
// entries, in its bytes or its decoded values (JSON for hooks.json, YAML for
// config.yaml). The error says why a file that does not name them could not
// be checked: too large, or not JSON or YAML.
func (c removedOnlyConnector) configNames(data []byte, names func(string) bool) (bool, error) {
	if names(string(data)) {
		return true, nil
	}
	if len(data) > removedConfigReadLimit {
		return false, fmt.Errorf("it is larger than %d MiB", removedConfigReadLimit>>20)
	}
	doc, err := c.decode(data)
	if err != nil {
		return false, err
	}
	return removedValueNames(doc, names), nil
}

// decode parses an agent config (nil for an empty one).
func (c removedOnlyConnector) decode(data []byte) (any, error) {
	body := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil
	}
	var doc any
	if c.name == removedOpenHandsID {
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("it is not JSON: %w", err)
		}
	} else if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("it is not YAML: %w", err)
	}
	return doc, nil
}

// removeEntries removes DefenseClaw's entries from one agent config. A file
// that cannot be read or parsed is left as it is (the agent cannot load it
// either); the file keeps its mode and, where the platform allows, its owner.
// A file the setup made (its receipt says it did not exist before) and that
// holds nothing else goes, so no empty "{}" config is left behind.
func (c removedOnlyConnector) removeEntries(path string, names func(string) bool, dataDir string) error {
	data, err := readRemovedConfig(path)
	if err != nil || len(data) > removedConfigReadLimit {
		return err
	}
	if named, _ := c.configNames(data, names); !named {
		return nil
	}
	var updated []byte
	var changed bool
	if c.name == removedOmnigentID {
		updated, changed, err = removedOmnigentConfigWithout(data)
	} else {
		updated, changed, err = removedOpenHandsConfigWithout(data, names)
	}
	if err != nil || !changed {
		return err
	}
	if removedEmptyConfig(updated) && c.setupMadeConfig(dataDir, path) {
		return removeRegularFile(path)
	}
	// The agent reads its config through links; the file it reads is the
	// one changed.
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	if err := atomicWriteFile(target, updated, info.Mode().Perm()); err != nil {
		return err
	}
	return removedKeepOwner(target, info)
}

// removedEmptyConfig reports whether a rewritten agent config holds nothing:
// an empty mapping with no comment.
func removedEmptyConfig(data []byte) bool {
	return strings.TrimSpace(string(data)) == "{}"
}

// setupMadeConfig reports whether the setup receipt names path as a file
// that did not exist before the setup, and path is still a regular file (not
// a link someone put there since).
func (c removedOnlyConnector) setupMadeConfig(dataDir, path string) bool {
	if strings.TrimSpace(dataDir) == "" {
		return false
	}
	b, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, c.name, "config"))
	if err != nil || b.Existed || b.Connector != c.name || !sameManagedTargetPath(b.Path, path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

// liveRegistrations are the valid agent configs that still run or import the
// script after removeEntries.
func (c removedOnlyConnector) liveRegistrations(configs []string, names func(string) bool) []string {
	var live []string
	for _, path := range configs {
		data, err := readRemovedConfig(path)
		if err != nil || len(data) > removedConfigReadLimit {
			continue
		}
		doc, err := c.decode(data)
		if err != nil {
			continue
		}
		if removedValueNames(doc, names) {
			live = append(live, path)
		}
	}
	return live
}

// RemovedLeftover is one thing a removed connector's teardown left on the
// host: what it is and how to remove it by hand. Information only.
type RemovedLeftover struct {
	Path string `json:"path"`
	What string `json:"what"`
	Step string `json:"step"`
}

// RemovedConnectorLeftovers lists what is left of a removed connector on this
// host; false when name is not a removed connector. It only reads.
func RemovedConnectorLeftovers(name string, opts SetupOpts) ([]RemovedLeftover, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return nil, false
	}
	return c.leftovers(opts), true
}

func (c removedOnlyConnector) leftovers(opts SetupOpts) []RemovedLeftover {
	var out []RemovedLeftover
	add := func(path, what, step string) {
		out = append(out, RemovedLeftover{Path: path, What: what, Step: step})
	}
	names := c.namesFor(opts)
	for _, path := range c.configPaths(opts) {
		data, err := readRemovedConfig(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			add(path, fmt.Sprintf("could not be read (%v)", err), "check it by hand: "+c.configStep)
			continue
		}
		named, checkErr := c.configNames(data, names)
		switch {
		case named:
			add(path, "still names DefenseClaw's "+c.label+" entries, which DefenseClaw could not remove", c.configStep)
		case checkErr != nil:
			add(path, fmt.Sprintf("could not be checked (%v)", checkErr), "check it by hand: "+c.configStep)
		}
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return out
	}
	hooks := filepath.Join(opts.DataDir, "hooks")
	if c.name == removedOmnigentID {
		if pth := managedFileBackupTargetPath(opts.DataDir, c.name, "pth", ""); pth != "" && removedPthHasLine(pth, hooks) {
			add(pth, "adds DefenseClaw's hook folder to OmniGent's Python import path",
				"remove only the line "+hooks+" from this file (delete the file when that was its only line)")
		}
	}
	if script := c.scriptPath(opts.DataDir); c.ownsScript(script) {
		add(script, "DefenseClaw's old "+c.label+" "+c.scriptKind(), "delete it once nothing above runs it")
	}
	if path, err := HookAPITokenFilePath(opts.DataDir, c.name); err == nil {
		if _, err := os.Lstat(path); err == nil {
			add(path, "a DefenseClaw token for "+c.label+"; nothing accepts it", "delete it")
		}
	}
	if path := filepath.Join(hooks, otlpPathTokenFileName(OTLPPathTokenScope(c.name))); fileExists(path) {
		add(path, "a DefenseClaw token for "+c.label+"; nothing accepts it", "delete it")
	}
	if path := filepath.Join(hooks, hookConfigSidecarName+"."+c.name); fileExists(path) {
		add(path, "DefenseClaw's old "+c.label+" hook settings; nothing reads them", "delete it")
	}
	backups := filepath.Join(opts.DataDir, "connector_backups", c.name)
	if fileExists(backups) {
		add(backups, "files DefenseClaw saved when it set up "+c.label, "copy back what you need, then delete this folder")
	}
	return out
}

func (c removedOnlyConnector) scriptKind() string {
	if c.name == removedOmnigentID {
		return "policy module"
	}
	return "hook script"
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// FormatRemovedLeftovers renders leftovers as the lines status, uninstall and
// teardown print: RemovedConnectorNotice, then one line for each item ("" for
// none).
func FormatRemovedLeftovers(_ string, leftovers []RemovedLeftover) string {
	if len(leftovers) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(RemovedConnectorNotice + "\n")
	for _, item := range leftovers {
		fmt.Fprintf(&b, "  - %s: %s. To remove: %s.\n", item.Path, item.What, item.Step)
	}
	return b.String()
}

// removedValueNames reports whether a string or key anywhere in a decoded
// JSON or YAML value names the script.
func removedValueNames(value any, names func(string) bool) bool {
	switch v := value.(type) {
	case string:
		return names(v)
	case []any:
		for _, item := range v {
			if removedValueNames(item, names) {
				return true
			}
		}
	case map[string]any:
		for key, item := range v {
			if names(key) || removedValueNames(item, names) {
				return true
			}
		}
	case map[any]any:
		for key, item := range v {
			if names(fmt.Sprint(key)) || removedValueNames(item, names) {
				return true
			}
		}
	}
	return false
}

// configPaths are the agent config files an older setup may have changed:
// the one its backup record names, the ones the hook contract lock names,
// the explicit config home and the agent's default (both), for OpenHands the
// pinned workspace's, and for OmniGent the files OMNIGENT_CONFIG and
// OMNIGENT_CONFIG_HOME select.
func (c removedOnlyConnector) configPaths(opts SetupOpts) []string {
	file, defaultDir := "hooks.json", ".openhands"
	if c.name == removedOmnigentID {
		file, defaultDir = "config.yaml", ".omnigent"
	}
	var paths []string
	workspaces := []string{opts.WorkspaceDir}
	if strings.TrimSpace(opts.DataDir) != "" {
		paths = append(paths, managedFileBackupTargetPath(opts.DataDir, c.name, "config", ""))
		if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
			for _, path := range entry.Locations.HookConfigPaths {
				if strings.EqualFold(filepath.Base(path), file) {
					paths = append(paths, removedAbsolute(path))
				}
			}
			if entry.RegistrationPosture != nil {
				workspaces = append(workspaces, entry.RegistrationPosture.WorkspaceDir)
			}
		}
	}
	if home := strings.TrimSpace(opts.ConfigHome); home != "" {
		paths = append(paths, filepath.Join(removedAbsolute(home), file))
	}
	paths = append(paths, homePath(defaultDir, file))
	if c.name == removedOpenHandsID {
		// A 1.0.x setup with a pinned workspace wrote the repo-local
		// <workspace>/.openhands/hooks.json, unless the workspace was inside
		// the data directory.
		for _, root := range workspaces {
			if root = removedAbsolute(root); root != "" && workspaceRootOutsideDataDir(root, opts.DataDir) {
				paths = append(paths, filepath.Join(root, defaultDir, file))
			}
		}
	}
	if c.name == removedOmnigentID {
		paths = append(paths, removedAbsolute(os.Getenv("OMNIGENT_CONFIG")))
		if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" {
			paths = append(paths, filepath.Join(removedAbsolute(home), file))
		}
	}
	var unique []string
	for _, path := range uniqueNonEmptyStrings(paths) {
		seen := false
		for _, kept := range unique {
			if sameManagedTargetPath(kept, path) {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, path)
		}
	}
	return unique
}

// removedAbsolute resolves ~ and a relative path the way an older setup
// read it ("" stays "").
func removedAbsolute(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return ""
	case value == "~":
		return homePath()
	case strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`):
		return filepath.Join(homePath(), value[2:])
	}
	if absolute, err := filepath.Abs(value); err == nil {
		return absolute
	}
	return filepath.Clean(value)
}

// readRemovedConfig reads an agent config through links, as the agent does,
// up to one byte past removedConfigReadLimit (more is a file too large to
// check).
func readRemovedConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(file, int64(removedConfigReadLimit)+1))
}

// removedOmnigentConfigWithout returns an OmniGent config.yaml without
// DefenseClaw's entries: the policy module in policy_modules and every policy
// whose handler is in that module. A key left empty by that goes too.
// Comments and every other entry stay.
func removedOmnigentConfigWithout(data []byte) ([]byte, bool, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, false, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, false, errors.New("not a YAML mapping")
	}
	ownedModule := func(node *yaml.Node) bool {
		return node.Kind == yaml.ScalarNode && strings.TrimSpace(node.Value) == removedOmnigentModuleName
	}
	ownedPolicy := func(node *yaml.Node) bool {
		if node.Kind != yaml.MappingNode {
			return false
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "handler" && node.Content[i+1].Kind == yaml.ScalarNode &&
				strings.HasPrefix(strings.TrimSpace(node.Content[i+1].Value), removedOmnigentModuleName+".") {
				return true
			}
		}
		return false
	}
	keep := func(items []*yaml.Node, owned func(*yaml.Node) bool) ([]*yaml.Node, bool) {
		kept := make([]*yaml.Node, 0, len(items))
		removed := false
		for _, item := range items {
			if owned(item) {
				removed = true
				continue
			}
			kept = append(kept, item)
		}
		return kept, removed
	}
	root := document.Content[0]
	changed := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		value := root.Content[i+1]
		removed, drop := false, false
		switch root.Content[i].Value {
		case "policy_modules":
			switch value.Kind {
			case yaml.ScalarNode:
				drop = ownedModule(value)
			case yaml.SequenceNode:
				value.Content, removed = keep(value.Content, ownedModule)
				drop = removed && len(value.Content) == 0
			}
		case "policies":
			switch value.Kind {
			case yaml.MappingNode:
				kept := make([]*yaml.Node, 0, len(value.Content))
				for j := 0; j+1 < len(value.Content); j += 2 {
					if ownedPolicy(value.Content[j+1]) {
						removed = true
						continue
					}
					kept = append(kept, value.Content[j], value.Content[j+1])
				}
				value.Content = kept
				drop = removed && len(kept) == 0
			case yaml.SequenceNode:
				value.Content, removed = keep(value.Content, ownedPolicy)
				drop = removed && len(value.Content) == 0
			}
		}
		changed = changed || removed || drop
		if drop {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			i -= 2
		}
	}
	if !changed {
		return nil, false, nil
	}
	out, err := yaml.Marshal(&document)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// removedOpenHandsConfigWithout returns an OpenHands hooks.json without
// DefenseClaw's hooks: every handler whose command names is true for, with
// every matcher group and event list left empty by that. Every other hook
// stays.
func removedOpenHandsConfigWithout(data []byte, names func(string) bool) ([]byte, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return nil, false, err
	}
	pruned, changed, drop := removedPruneHooks(document, names)
	if !changed {
		return nil, false, nil
	}
	if drop || pruned == nil {
		pruned = map[string]any{}
	}
	out, err := json.MarshalIndent(pruned, "", "  ")
	if err != nil {
		return nil, false, err
	}
	return append(out, '\n'), true, nil
}

// removedPruneHooks removes DefenseClaw's hooks from a decoded hooks.json
// value; drop means the value itself goes from its parent (a handler of
// DefenseClaw's, a command string of DefenseClaw's in a list, or a matcher
// group whose hooks all went and that holds nothing but its matcher).
func removedPruneHooks(value any, names func(string) bool) (out any, changed, drop bool) {
	switch v := value.(type) {
	case map[string]any:
		if command, ok := v["command"].(string); ok && names(command) {
			return nil, true, true
		}
		pruned := make(map[string]any, len(v))
		for key, child := range v {
			next, childChanged, childDrop := removedPruneHooks(child, names)
			if childDrop {
				changed = true
				continue
			}
			if childChanged {
				changed = true
				if list, ok := next.([]any); ok && len(list) == 0 {
					continue // emptied by the removal
				}
			}
			pruned[key] = next
		}
		if !changed {
			return v, false, false
		}
		if _, had := v["hooks"]; had {
			if _, kept := pruned["hooks"]; !kept {
				for key := range pruned {
					if key != "matcher" {
						// The operator's own fields stay, with no hooks.
						pruned["hooks"] = []any{}
						return pruned, true, false
					}
				}
				return nil, true, true
			}
		}
		return pruned, true, false
	case []any:
		pruned := make([]any, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok && names(text) {
				changed = true
				continue
			}
			next, itemChanged, itemDrop := removedPruneHooks(item, names)
			if itemDrop {
				changed = true
				continue
			}
			changed = changed || itemChanged
			pruned = append(pruned, next)
		}
		if !changed {
			return v, false, false
		}
		return pruned, true, false
	}
	return value, false, false
}

// removedPthHasLine reports whether OmniGent's import-path file holds
// DefenseClaw's line (its hooks folder).
func removedPthHasLine(pth, hooks string) bool {
	data, err := readRemovedConfig(pth)
	if err != nil || len(data) > removedConfigReadLimit {
		return false
	}
	for _, line := range strings.Split(string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") && sameManagedTargetPath(line, hooks) {
			return true
		}
	}
	return false
}

// removeOmnigentImportPath removes DefenseClaw's line (its hooks folder) from
// the import-path file an older OmniGent setup wrote, and the file when
// nothing else is in it. A file that is not a regular file or cannot be read
// is left (and listed).
func removeOmnigentImportPath(dataDir string) error {
	pth := managedFileBackupTargetPath(dataDir, removedOmnigentID, "pth", "")
	if pth == "" {
		return nil
	}
	info, err := os.Lstat(pth)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	data, err := readRemovedConfig(pth)
	if err != nil || len(data) > removedConfigReadLimit {
		return nil
	}
	hooks := filepath.Join(dataDir, "hooks")
	var kept []string
	own, other := false, false
	for _, line := range strings.Split(string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed != "" && !strings.HasPrefix(trimmed, "#") && sameManagedTargetPath(trimmed, hooks):
			own = true
			continue
		case trimmed != "" && !strings.HasPrefix(trimmed, "#"):
			other = true
		}
		kept = append(kept, line)
	}
	switch {
	case !own:
		return nil
	case !other:
		if err := os.Remove(pth); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove the import-path file %s: %w", pth, err)
		}
		return nil
	}
	if err := atomicWriteFile(pth, []byte(strings.Join(kept, "\n")), info.Mode().Perm()); err != nil {
		return fmt.Errorf("remove DefenseClaw's line from the import-path file %s: %w", pth, err)
	}
	return removedKeepOwner(pth, info)
}
