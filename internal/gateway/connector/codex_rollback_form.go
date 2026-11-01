// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strings"
)

// convertCodexWindowsHookForms rewrites, in place, every per-user Codex
// handler under hooks that is exactly a command this release renders for
// launcher, event and hook contract, between the two forms:
//
//   - toBridge: the direct system cmd.exe start this release writes
//     (windowsCmdDirectHookCommand, GAP-1908) becomes the encoded system
//     PowerShell bridge releases 1.0.1 to 1.0.4 write and own
//     (windowsNativePowerShellHookCommandForCodexEvent). 1.0.4 read the
//     direct form as a foreign handler, so after a rollback its setup added
//     its own handler beside it and doctor failed (GAP-2553).
//   - !toBridge: the bridge becomes the direct start again (an aborted
//     rollback, "connector prepare-rollback --restore").
//
// Ownership is byte-for-byte equality with the rendered command, in both
// command and command_windows, for the event the handler is registered
// under; any other handler is left as it is. Codex trusts a handler by the
// hash of its normalized identity at its position (hooks.state); a trust
// record that proved the old command moves to the new command, and a record
// that did not is left untouched. It returns how many handlers it rewrote.
func convertCodexWindowsHookForms(hooks map[string]interface{}, keySource, launcher string, toBridge bool) (int, error) {
	if strings.TrimSpace(launcher) == "" {
		return 0, nil
	}
	state, _ := hooks["state"].(map[string]interface{})
	if rawState, present := hooks["state"]; present && state == nil {
		return 0, fmt.Errorf("hooks.state has unsupported type %T", rawState)
	}
	changed := 0
	for eventType, rawGroups := range hooks {
		if eventType == "state" {
			continue
		}
		groups, ok := rawGroups.([]interface{})
		if !ok {
			continue
		}
		eventKey := codexHookEventKeyLabel(eventType)
		for groupIndex, rawGroup := range groups {
			group, ok := rawGroup.(map[string]interface{})
			if !ok {
				continue
			}
			handlers, _ := group["hooks"].([]interface{})
			for handlerIndex, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]interface{})
				if !ok {
					continue
				}
				command, _ := handler["command"].(string)
				commandWindows, _ := handler["command_windows"].(string)
				if command == "" || command != commandWindows {
					continue
				}
				replacement, ok := codexWindowsHookFormReplacement(command, eventType, launcher, toBridge)
				if !ok {
					continue
				}
				oldHash, err := codexCommandHookHashForPlatform("windows", eventKey, group["matcher"], handler)
				if err != nil {
					return 0, fmt.Errorf("%s: hash handler %d:%d: %w", eventType, groupIndex, handlerIndex, err)
				}
				handler["command"] = replacement
				handler["command_windows"] = replacement
				newHash, err := codexCommandHookHashForPlatform("windows", eventKey, group["matcher"], handler)
				if err != nil {
					return 0, fmt.Errorf("%s: hash handler %d:%d: %w", eventType, groupIndex, handlerIndex, err)
				}
				key := codexHookStateKey(keySource, eventKey, groupIndex, handlerIndex)
				if entry, ok := state[key].(map[string]interface{}); ok {
					if trusted, _ := entry["trusted_hash"].(string); trusted == oldHash {
						entry["trusted_hash"] = newHash
					}
				}
				changed++
			}
		}
	}
	return changed, nil
}

// codexWindowsHookFormReplacement returns the other form of command when
// command is exactly the direct start (toBridge) or the bridge (!toBridge)
// of launcher for eventType and the hook contract it names.
func codexWindowsHookFormReplacement(command, eventType, launcher string, toBridge bool) (string, bool) {
	if toBridge {
		match := windowsCodexDirectBoundArgumentsPattern.FindStringSubmatch(command)
		if match == nil || match[1] != eventType {
			return "", false
		}
		direct, ok := windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", eventType, match[2], nil))
		if !ok || direct != command {
			return "", false
		}
		return windowsNativePowerShellHookCommandForCodexEvent(eventType, match[2], launcher), true
	}
	prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(command, prefix) {
		return "", false
	}
	script, decoded := powershellDecodedCommand(strings.TrimPrefix(command, prefix))
	if !decoded {
		return "", false
	}
	for _, match := range windowsCodexBoundArgumentsPattern.FindAllStringSubmatch(script, -1) {
		event := strings.ReplaceAll(match[1], "''", "'")
		contract := strings.ReplaceAll(match[2], "''", "'")
		if event != eventType || command != windowsNativePowerShellHookCommandForCodexEvent(event, contract, launcher) {
			continue
		}
		return windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", event, contract, nil))
	}
	return "", false
}

// codexWindowsHookFormConversion parses one per-user Codex config.toml and
// returns it with convertCodexWindowsHookForms applied, edited in place so
// the operator settings, comments and layout stay as they are.
func codexWindowsHookFormConversion(configPath, launcher string, toBridge bool) func([]byte) ([]byte, int, error) {
	keySource := codexHookStateKeySource(configPath)
	return func(raw []byte) ([]byte, int, error) {
		if len(strings.TrimSpace(string(raw))) == 0 {
			return nil, 0, nil
		}
		cfg := map[string]interface{}{}
		if err := parseCodexTOML(raw, &cfg); err != nil {
			return nil, 0, fmt.Errorf("parse Codex config %s: %w", configPath, err)
		}
		hooks, ok := cfg["hooks"].(map[string]interface{})
		if !ok {
			return nil, 0, nil
		}
		changed, err := convertCodexWindowsHookForms(hooks, keySource, launcher, toBridge)
		if err != nil || changed == 0 {
			return nil, 0, err
		}
		out, err := editCodexOwnedTOML(raw, cfg)
		if err != nil {
			return nil, 0, fmt.Errorf("edit Codex config %s: %w", configPath, err)
		}
		return out, changed, nil
	}
}

// convertCodexConfigHookForms applies codexWindowsHookFormConversion to the
// per-user config.toml under its lock and keeps a copy of the file before a
// rollback conversion. Managed installs register their hooks in the machine
// requirements, not here.
func convertCodexConfigHookForms(opts SetupOpts, toBridge bool, keepCopy func(dataDir string, data []byte) error) (int, error) {
	if opts.ManagedEnterprise {
		return 0, nil
	}
	configPath := codexConfigPath()
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read Codex config %s: %w", configPath, err)
	}
	launcher := strings.TrimSpace(opts.HookExecutable)
	if launcher == "" {
		launcher = defenseclawHookBinary()
	}
	convert := codexWindowsHookFormConversion(configPath, launcher, toBridge)
	if _, changed, err := convert(data); err != nil || changed == 0 {
		return 0, err
	}
	converted := 0
	err = withFileLockMode(configPath, false, func() error {
		return atomicTransformFileWithStateDir(configPath, opts.DataDir, 0o600,
			func(current []byte, exists bool) (atomicTransformResult, error) {
				if !exists {
					return atomicTransformResult{Remove: true}, nil
				}
				out, changed, err := convert(current)
				if err != nil || changed == 0 {
					return atomicTransformResult{Data: current}, err
				}
				if keepCopy != nil {
					if err := keepCopy(opts.DataDir, current); err != nil {
						return atomicTransformResult{}, fmt.Errorf("keep a copy of the Codex config: %w", err)
					}
				}
				converted = changed
				return atomicTransformResult{Data: out}, nil
			})
	})
	if err != nil {
		return 0, fmt.Errorf("rewrite Codex hooks in %s: %w", configPath, err)
	}
	return converted, nil
}
