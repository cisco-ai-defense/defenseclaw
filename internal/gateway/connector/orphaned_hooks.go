// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// OrphanedHookConfigPaths returns the agent config files that still hold a
// DefenseClaw hook entry of conn for this data directory: an entry that runs
// one of conn's hook scripts under opts.DataDir/hooks (in any wrapping, such
// as the Claude Code missing-script guard), or the exact entry Setup writes
// for the native launcher on Windows. The caller has decided that conn is not
// configured, so each such entry is an orphan. A rollback restored a data
// directory from before the connector was set up, and Claude Code then ran a
// hook script that no longer existed and blocked every prompt (GAP-0009). A
// plugin-file connector (OpenCode, Amp) is registered by its managed plugin
// file instead, which is reported when it is DefenseClaw's plugin for this
// data directory (orphanedPluginArtifact): it read its credential from
// opts.DataDir/hooks, which the restored install does not have, so it refused
// every tool call. A config file that cannot be read or parsed is an error,
// so nothing is removed on a guess.
func OrphanedHookConfigPaths(conn Connector, opts SetupOpts) ([]string, error) {
	var found []string
	if plugin, ok := conn.(interface {
		orphanedPluginArtifact(SetupOpts) (string, error)
	}); ok {
		path, err := plugin.orphanedPluginArtifact(opts)
		if err != nil {
			return nil, err
		}
		if path != "" {
			found = append(found, path)
		}
	}
	exact := ownedHookCommandNeedles(opts, conn)
	scripts := ownedHookScriptPaths(conn, opts)
	if len(exact) == 0 && len(scripts) == 0 {
		return found, nil
	}
	paths := HookConfigPathsForConnector(conn, opts)
	if hermes, ok := conn.(*hookOnlyConnector); ok && hermes.name == "hermes" {
		other, err := hermes.orphanedOtherHermesHomes(opts)
		if err != nil {
			return nil, err
		}
		found = append(found, other...)
	}
	for _, path := range paths {
		if slices.Contains(found, path) {
			continue
		}
		decoded, err := decodeHookConfigFile(path)
		if err != nil {
			return nil, err
		}
		if decoded == nil {
			continue
		}
		if structuredHookCommandReferences(decoded, exact) || hookCommandRunsScript(decoded, scripts) {
			found = append(found, path)
		}
	}
	return found, nil
}

// maxOrphanedPluginBytes bounds the read of a managed plugin, as Teardown's.
const maxOrphanedPluginBytes = 4 << 20

// orphanedPluginArtifact returns c's managed plugin file when it is
// DefenseClaw's plugin for opts.DataDir: a regular file (not a link) whose
// first line is a DefenseClaw ownership marker, the test Teardown removes it
// by, and whose credential file is in opts.DataDir/hooks. The operator's other
// plugins, another data directory's plugin and a sandbox render (it reads no
// credential file) are not, and "" is returned for them.
func (c *hookOnlyConnector) orphanedPluginArtifact(opts SetupOpts) (string, error) {
	if c == nil || !c.pluginArtifact || strings.TrimSpace(opts.DataDir) == "" {
		return "", nil
	}
	path := c.configPath(opts)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("%s inspect plugin %s: %w", c.name, path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > maxOrphanedPluginBytes {
		return "", nil
	}
	data, err := safefile.ReadRegularFileBounded(path, maxOrphanedPluginBytes)
	if os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("%s read plugin %s: %w", c.name, path, err)
	}
	firstLine, _, _ := bytes.Cut(data, []byte("\n"))
	if !validManagedPluginOwnershipMarker(bytes.TrimSuffix(firstLine, []byte("\r"))) {
		return "", nil
	}
	tokenFile, ok := managedPluginTokenFile(data)
	if !ok {
		return "", nil
	}
	hookDir, err := filepath.Abs(filepath.Join(opts.DataDir, "hooks"))
	if err != nil || !sameManagedTargetPath(filepath.Dir(tokenFile), hookDir) {
		return "", nil
	}
	return path, nil
}

// managedPluginTokenFile returns the absolute credential path a rendered
// managed plugin reads, the string of its `const DC_TOKEN_FILE = "...";` line
// (the TypeScript render has no semicolon).
func managedPluginTokenFile(data []byte) (string, bool) {
	declaration := []byte("const DC_TOKEN_FILE = ")
	for rest := data; len(rest) > 0; {
		var line []byte
		line, rest, _ = bytes.Cut(rest, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if !bytes.HasPrefix(line, declaration) {
			continue
		}
		var tokenFile string
		if err := json.Unmarshal(bytes.TrimSuffix(line[len(declaration):], []byte(";")), &tokenFile); err != nil ||
			!filepath.IsAbs(tokenFile) {
			return "", false
		}
		return tokenFile, true
	}
	return "", false
}

// ownedHookScriptPaths lists the absolute paths of conn's Unix hook scripts in
// opts.DataDir. Windows registers the native launcher instead.
func ownedHookScriptPaths(conn Connector, opts SetupOpts) []string {
	owner, ok := conn.(HookScriptOwner)
	if !ok || runtime.GOOS == "windows" || strings.TrimSpace(opts.DataDir) == "" {
		return nil
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	var paths []string
	for _, name := range owner.HookScriptNames(opts) {
		if name = strings.TrimSpace(name); name != "" {
			paths = append(paths, filepath.Join(hookDir, name))
		}
	}
	return paths
}

// hookCommandRunsScript reports whether a hook command anywhere in raw names
// one of scripts as a whole path (not a prefix of a longer file name).
func hookCommandRunsScript(raw interface{}, scripts []string) bool {
	if len(scripts) == 0 {
		return false
	}
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if hookCommandRunsScript(item, scripts) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			if key == "command" || key == "bash" || key == "handler" {
				if command, ok := item.(string); ok && commandNamesScript(command, scripts) {
					return true
				}
			}
			if hookCommandRunsScript(item, scripts) {
				return true
			}
		}
	}
	return false
}

func commandNamesScript(command string, scripts []string) bool {
	for _, script := range scripts {
		for rest := command; ; {
			index := strings.Index(rest, script)
			if index < 0 {
				break
			}
			rest = rest[index+len(script):]
			if rest == "" || !strings.ContainsAny(rest[:1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/") {
				return true
			}
		}
	}
	return false
}

// orphanedOtherHermesHomes returns the Hermes configs besides the resolved
// one (otherHermesHomes: an earlier Setup's home, the profile default) that
// hold this data directory's hooks or approvals.
func (c *hookOnlyConnector) orphanedOtherHermesHomes(opts SetupOpts) ([]string, error) {
	configPath := hermesConfigPath(opts)
	if validateHermesWindowsConfigPath(configPath) != nil {
		return nil, nil
	}
	bound, profileDefault, err := otherHermesHomes(opts, configPath)
	if err != nil {
		return nil, err
	}
	hookScript := c.hookCommand(opts)
	command := hermesConfiguredHookCommand(hookScript, opts.HookExecutable)
	var found []string
	for _, other := range []string{bound, profileDefault} {
		if other == "" {
			continue
		}
		hooks, approvals, err := hermesHomeHoldsOwnedEntries(other, hookScript, command)
		if err != nil {
			return nil, err
		}
		if hooks || approvals {
			found = append(found, other)
		}
	}
	return found, nil
}
