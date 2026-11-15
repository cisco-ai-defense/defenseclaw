// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strings"
)

// convertCodexWindowsHookForms rewrites, in place, every per-user Codex
// handler under hooks that is exactly a command this release renders, or
// writes for a rollback, for launcher, the event it is registered under and
// the hook contract it names:
//
//   - toEarlier: a form this release writes (the direct system cmd.exe start,
//     GAP-1908; the guarded start or the answering bridge, rel-1-0-6
//     GAP-0676; the bridge with the 1.0.8 fallback end, which earlier
//     rollbacks wrote for every target) becomes the exact command the
//     rollback target release writes (codexWindowsRollbackTargetCommand).
//     A target that writes the forms of this release needs no rewrite.
//   - !toEarlier: a form a rollback writes becomes the form this release
//     renders again (an aborted rollback, "connector prepare-rollback
//     --restore").
//
// Ownership is byte-for-byte equality with a rendered command, in both
// command and command_windows; any other handler is left as it is. Codex
// trusts a handler by the hash of its normalized identity at its position
// (hooks.state); a trust record that proved the old command moves to the new
// command, and a record that did not is left untouched. It returns how many
// handlers it rewrote.
func convertCodexWindowsHookForms(hooks map[string]interface{}, keySource, launcher, target string, toEarlier bool) (int, error) {
	if strings.TrimSpace(launcher) == "" || (toEarlier && rollbackTargetOwns(target, releaseLauncherStartAnswer)) {
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
				replacement, ok := codexWindowsHookFormReplacement(command, eventType, launcher, target, toEarlier)
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

// codexWindowsRollbackTargetCommand is the per-user Codex command the
// rollback target release writes for launcher, event and contract (every
// release tag rendered: testdata/codex_windows_release_hook_forms.json):
//
//   - 1.0.5 to 1.0.8: the direct cmd.exe start of the launcher (GAP-1908),
//     or for a launcher path that form cannot carry the bridge, with the
//     fallback end of that release;
//   - 1.0.0 to 1.0.4, and an unknown target: the bridge with the earlier
//     fallback end (legacyWindowsAwaitedHookCommand), the one form every
//     release owns.
//
// 1.0.9 and later write the forms of this release (releaseLauncherStartAnswer).
func codexWindowsRollbackTargetCommand(target, event, contract, launcher string) string {
	if rollbackTargetOwns(target, releaseCodexDirectStart) {
		if direct, ok := windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", event, contract, nil)); ok {
			return direct
		}
	}
	bridge := windowsNativePowerShellHookCommandForCodexEvent(event, contract, launcher)
	if rollbackTargetOwns(target, releaseCurrentAwaitedFallback) {
		return bridge
	}
	if legacy, ok := legacyWindowsAwaitedHookCommand(bridge); ok {
		return legacy
	}
	return bridge
}

// codexWindowsRollbackForms are the commands a rollback converter of this
// release or of 1.0.9 writes for launcher, event and contract: the direct
// start, the bridge with the 1.0.8 fallback end and the bridge with the
// earlier end.
func codexWindowsRollbackForms(event, contract, launcher string) []string {
	bridge := windowsNativePowerShellHookCommandForCodexEvent(event, contract, launcher)
	forms := []string{bridge}
	if legacy, ok := legacyWindowsAwaitedHookCommand(bridge); ok {
		forms = append(forms, legacy)
	}
	if direct, ok := windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", event, contract, nil)); ok {
		forms = append(forms, direct)
	}
	return forms
}

// codexWindowsHookContract is the hook contract command names for eventType
// in the direct, guarded or bridge form, or "" when it names none or another
// event.
func codexWindowsHookContract(command, eventType string) string {
	if match := windowsCodexDirectBoundArgumentsPattern.FindStringSubmatch(command); match != nil {
		if match[1] == eventType {
			return match[2]
		}
		return ""
	}
	prefix := windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand "
	if !strings.HasPrefix(command, prefix) {
		return ""
	}
	script, decoded := powershellDecodedCommand(strings.TrimPrefix(command, prefix))
	if !decoded {
		return ""
	}
	for _, match := range windowsCodexBoundArgumentsPattern.FindAllStringSubmatch(script, -1) {
		if powershellLiteralValue(match[1]) == eventType {
			return powershellLiteralValue(match[2])
		}
	}
	return ""
}

// codexWindowsHookFormReplacement returns the other form of command when
// command is exactly a form this release writes (toEarlier) or a form a
// rollback writes (!toEarlier) for launcher, eventType and the hook contract
// it names: the command the target release writes, or the form this release
// renders now.
func codexWindowsHookFormReplacement(command, eventType, launcher, target string, toEarlier bool) (string, bool) {
	contract := codexWindowsHookContract(command, eventType)
	if contract == "" {
		return "", false
	}
	var replacement string
	var from []string
	if toEarlier {
		replacement = codexWindowsRollbackTargetCommand(target, eventType, contract, launcher)
		from = windowsCodexPerUserHookCommands(eventType, contract, launcher)
	} else {
		replacement = windowsCodexHookCommandForBinaryEvent(eventType, contract, launcher)
		from = codexWindowsRollbackForms(eventType, contract, launcher)
	}
	if command == replacement {
		return "", false
	}
	for _, owned := range from {
		if owned == command {
			return replacement, true
		}
	}
	return "", false
}

// codexWindowsHookFormConversion parses one per-user Codex config.toml and
// returns it with convertCodexWindowsHookForms applied, edited in place so
// the operator settings, comments and layout stay as they are.
func codexWindowsHookFormConversion(configPath, launcher, target string, toEarlier bool) func([]byte) ([]byte, int, error) {
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
		changed, err := convertCodexWindowsHookForms(hooks, keySource, launcher, target, toEarlier)
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
func convertCodexConfigHookForms(opts SetupOpts, toEarlier bool, keepCopy func(dataDir string, data []byte) error) (int, error) {
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
	convert := codexWindowsHookFormConversion(configPath, launcher, opts.RollbackTargetVersion, toEarlier)
	_, wanted, err := convert(data)
	if err != nil || wanted == 0 {
		return 0, err
	}
	converted := 0
	err = withFileLockMode(configPath, false, func() error {
		if toEarlier {
			// A file nobody edited since setup gets its saved bytes back and
			// needs no conversion (restoreUneditedForRollback).
			var keep func([]byte) error
			if keepCopy != nil {
				keep = func(current []byte) error { return keepCopy(opts.DataDir, current) }
			}
			if done, err := restoreUneditedForRollback(opts.DataDir, "codex", configPath, keep); err != nil || done {
				if err == nil {
					converted = wanted
				}
				return err
			}
		}
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
