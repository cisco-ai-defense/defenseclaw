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

// until 1.1: the uninstall step of a removed connector (OpenHands, OmniGent;
// see removed.go). While DefenseClaw stays installed, the teardown leaves the
// agent's own files as they are and the stub blocks every call. When
// DefenseClaw itself is uninstalled, that stub would keep blocking the agent
// with nothing left to protect it, so the uninstall also removes what an
// older setup wrote for the connector: its entries in the agent configs
// (OpenHands' hooks that run its hook script or the native launcher's
// OpenHands connector; OmniGent's policy_modules entry and the policies that
// call its module), then, once no config runs or imports it, the stub and
// DefenseClaw's line in OmniGent's import-path file. A config that cannot be
// read, parsed or checked keeps its entries and the stub stays (a block with
// the reason, not a missing script or module); RemovedConnectorLeftovers
// lists it with its step. Every other entry, file, backup and saved copy
// stays.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RemovedConnectorUninstallEnv set to "1" in the environment of
// `defenseclaw-gateway connector teardown` marks the teardown as part of an
// uninstall (defenseclaw uninstall and reset, Windows Setup /uninstall). Only
// that command reads it. An older gateway ignores it: its own teardown of
// these connectors already put the agent files back. until 1.1.
const RemovedConnectorUninstallEnv = "DEFENSECLAW_REMOVED_CONNECTOR_UNINSTALL"

// UninstallRemovedConnector is the uninstall step of a removed connector,
// run after its Teardown succeeded (see the file comment). false when name is
// not a removed connector.
func UninstallRemovedConnector(name string, opts SetupOpts) (bool, error) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return false, nil
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return true, fmt.Errorf("%s uninstall: empty data directory", c.name)
	}
	defer RemoveIdleFileLockSentinels()
	if err := c.removeRegistrations(opts); err != nil {
		return true, fmt.Errorf("%s uninstall: %w; the stub that blocks every call was kept", c.name, err)
	}
	if len(c.liveRegistrations(opts)) > 0 {
		// Listed with its step; the stub stays for it.
		return true, nil
	}
	if c.name == removedOmnigentID {
		if err := removeOmnigentImportPath(opts.DataDir); err != nil {
			return true, fmt.Errorf("%s uninstall: %w", c.name, err)
		}
	}
	path := c.scriptPath(opts.DataDir)
	state, _, _, _, err := c.scriptStateAndLinks(path)
	if err != nil {
		return true, fmt.Errorf("%s uninstall: read %s: %w", c.name, path, err)
	}
	if state == removedScriptStub {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, fmt.Errorf("%s uninstall: remove the stub %s: %w", c.name, path, err)
		}
	}
	if err := c.sealStub(opts); err != nil {
		return true, fmt.Errorf("%s uninstall: %w", c.name, err)
	}
	return true, nil
}

// removeRegistrations removes DefenseClaw's entries from every agent config
// the connector's teardown checks (configPaths). A file that cannot be read
// or parsed is left as it is (the agent cannot load it either). A valid
// config that still runs or imports the script afterwards, or one too large
// to check, is an error: the uninstall must not go on to remove the data the
// registration still needs.
func (c removedOnlyConnector) removeRegistrations(opts SetupOpts) error {
	var errs []error
	for _, path := range c.configPaths(opts) {
		data, err := readRemovedConfig(path)
		if err != nil {
			continue
		}
		if len(data) > removedConfigReadLimit {
			errs = append(errs, fmt.Errorf("%s is larger than %d MiB, so DefenseClaw cannot check it for its entries; %s, then run the uninstall again",
				path, removedConfigReadLimit>>20, c.configStep))
			continue
		}
		if names, _ := c.configNames(data); !names {
			continue
		}
		var updated []byte
		var changed bool
		if c.name == removedOmnigentID {
			updated, changed, err = removedOmnigentConfigWithout(data)
		} else {
			updated, changed, err = removedOpenHandsConfigWithout(data, c.textNames)
		}
		if err != nil {
			continue
		}
		result := data
		if changed {
			result = updated
		}
		if c.decodedNames(result) {
			errs = append(errs, fmt.Errorf("%s still runs or imports %s in a form the uninstall does not remove; %s, then run the uninstall again",
				path, c.script, c.configStep))
			continue
		}
		if !changed {
			continue
		}
		// The agent reads its config through links; the file it reads is
		// the one changed.
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve %s: %w", path, err))
			continue
		}
		info, err := os.Stat(target)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspect %s: %w", path, err))
			continue
		}
		if err := atomicWriteFile(target, updated, info.Mode().Perm()); err != nil {
			errs = append(errs, fmt.Errorf("remove DefenseClaw's entries from %s: %w", path, err))
		}
	}
	return errors.Join(errs...)
}

// decodedNames reports whether a parsed agent config still runs or imports
// the script in one of its values (comments do not count).
func (c removedOnlyConnector) decodedNames(data []byte) bool {
	body := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	var doc any
	if c.name == removedOpenHandsID {
		if json.Unmarshal(body, &doc) != nil {
			return false
		}
	} else if yaml.Unmarshal(body, &doc) != nil {
		return false
	}
	return removedValueNames(doc, c.scriptNames)
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
				kept := make([]*yaml.Node, 0, len(value.Content))
				for _, item := range value.Content {
					if ownedModule(item) {
						removed = true
						continue
					}
					kept = append(kept, item)
				}
				value.Content = kept
				drop = removed && len(kept) == 0
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
				kept := make([]*yaml.Node, 0, len(value.Content))
				for _, item := range value.Content {
					if ownedPolicy(item) {
						removed = true
						continue
					}
					kept = append(kept, item)
				}
				value.Content = kept
				drop = removed && len(kept) == 0
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
// DefenseClaw's hooks: every handler whose command names the hook script or
// the native launcher's OpenHands connector (names), with every matcher group
// and event list left empty by that. Every other hook stays.
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
	return nil
}
