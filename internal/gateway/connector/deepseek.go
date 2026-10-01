// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const deepseekSource = "https://github.com/deepseek-ai/deepseek-harness/blob/639ed015397290b3745d163aafe02ffee4aa3f84/packages/hooks/hooks-claude-code/src/index.ts"
const deepseekPatchID = "defenseclaw-deepseek"

var deepseekEvents = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop", "SubagentStart", "SubagentStop"}
var deepseekBlockEvents = []string{"UserPromptSubmit", "PreToolUse"}

// DeepSeekConnector registers the vendor's shipped Claude-compatible bridge.
// It owns a separate hook file and one Cordis insertion, never Claude settings.
// Vendor infrastructure failures are fail-open; managed enrollment is refused.
type DeepSeekConnector struct{ *hookOnlyConnector }

func NewDeepSeekConnector() *DeepSeekConnector {
	return &DeepSeekConnector{&hookOnlyConnector{
		name: "deepseek", description: "DeepSeek Harness command-hook bridge (preview; upstream failures fail open)",
		apiPath: "/api/v1/deepseek/hook", scriptName: "deepseek-hook.sh", configPath: deepseekHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock: true, CanAskNative: true, AskEvents: []string{"PreToolUse"},
				BlockEvents: append([]string(nil), deepseekBlockEvents...), SupportsFailClosed: false,
				Scope: "user", ConfigPath: deepseekHooksPath(opts),
			}
		},
	}}
}

func deepseekHome(opts SetupOpts) string {
	if opts.ConfigHome != "" {
		return filepath.Clean(opts.ConfigHome)
	}
	if root := strings.TrimSpace(os.Getenv("DSH_HOME")); filepath.IsAbs(root) {
		return filepath.Clean(root)
	}
	return homePath(".dsh")
}
func deepseekHooksPath(opts SetupOpts) string {
	return filepath.Join(deepseekHome(opts), "defenseclaw-hooks.json")
}
func deepseekPatchPath(opts SetupOpts) string {
	return filepath.Join(deepseekHome(opts), "cordis.patch.yml")
}

func (c *DeepSeekConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if opts.ManagedEnterprise {
		return fmt.Errorf("deepseek: enterprise enrollment is unsupported: the vendor bridge fails open and user patches can disable it")
	}
	if opts.ConfigHome != "" && !filepath.IsAbs(opts.ConfigHome) {
		return fmt.Errorf("deepseek: config home must be absolute")
	}
	if root := os.Getenv("DSH_HOME"); opts.ConfigHome == "" && root != "" && !filepath.IsAbs(root) {
		return fmt.Errorf("deepseek: DSH_HOME must be absolute")
	}
	if _, err := CheckPlatformSupportOnHost("deepseek"); err != nil {
		return err
	}
	path := deepseekPatchPath(opts)
	// Validate before publishing any hook; reject ambiguous or foreign ownership.
	current, err := readHookConfigFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if _, err := deepseekPatch(current, opts, false); err != nil {
		return err
	}
	snapshots := map[string]openCodeFileSnapshot{}
	for _, target := range []string{deepseekHooksPath(opts), path, managedFileBackupPath(opts.DataDir, c.name, "config"), managedFileBackupPath(opts.DataDir, c.name, "cordis.patch.yml")} {
		snapshot, err := snapshotOpenCodeRegistrationFile(target)
		if err != nil {
			return err
		}
		snapshots[target] = snapshot
	}
	rollback := func(cause error) error {
		for target, snapshot := range snapshots {
			cause = errors.Join(cause, restoreOpenCodeRegistrationFile(target, snapshot))
		}
		return cause
	}
	for logical, target := range map[string]string{"config": deepseekHooksPath(opts), "cordis.patch.yml": path} {
		if err := rebaseDeepSeekBackup(opts, logical, target, c.hookCommand(opts)); err != nil {
			return rollback(err)
		}
	}
	if err := captureManagedFileBackup(opts.DataDir, c.name, "cordis.patch.yml", path); err != nil {
		return rollback(err)
	}
	if err := c.hookOnlyConnector.Setup(ctx, opts); err != nil {
		return rollback(err)
	}
	if err := c.transformPatch(opts, false); err != nil {
		return rollback(err)
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.name, "cordis.patch.yml", path); err != nil {
		return rollback(err)
	}
	return nil
}

func (c *DeepSeekConnector) transformPatch(opts SetupOpts, remove bool) error {
	path := deepseekPatchPath(opts)
	return atomicTransformFileWithStateDir(path, filepath.Join(opts.DataDir, "connector_transactions"), 0600,
		func(current []byte, exists bool) (atomicTransformResult, error) {
			if remove && !exists {
				return atomicTransformResult{Remove: true}, nil
			}
			data, err := deepseekPatch(current, opts, remove)
			return atomicTransformResult{Data: data}, err
		})
}

// Keep unrelated patch nodes, including comments and other insertions. An ID
// collision is refused rather than taking ownership of an operator's plugin.
func deepseekPatch(current []byte, opts SetupOpts, remove bool) ([]byte, error) {
	var doc yaml.Node
	if len(strings.TrimSpace(string(current))) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.SequenceNode, Tag: "!!seq"}}}
	} else if err := yaml.Unmarshal(current, &doc); err != nil {
		return nil, fmt.Errorf("deepseek Cordis patch: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.SequenceNode {
		return nil, fmt.Errorf("deepseek Cordis patch must be a YAML sequence")
	}
	root := doc.Content[0]
	found := false
	for _, operation := range root.Content {
		if operation.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("deepseek Cordis patch operations must be mappings")
		}
		for i := 0; i+1 < len(operation.Content); i += 2 {
			if operation.Content[i].Value != "insert" {
				continue
			}
			rows := operation.Content[i+1]
			if rows.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("deepseek Cordis insert must be a sequence")
			}
			for j := 0; j < len(rows.Content); j++ {
				var row struct {
					ID     string `yaml:"id"`
					Name   string `yaml:"name"`
					Config struct {
						ConfigPath string `yaml:"configPath"`
					} `yaml:"config"`
				}
				if err := rows.Content[j].Decode(&row); err != nil {
					return nil, err
				}
				if row.ID != deepseekPatchID {
					continue
				}
				if row.Name != "@deepseek-ai/dsh-hooks-claude-code" || row.Config.ConfigPath != deepseekHooksPath(opts) {
					return nil, fmt.Errorf("deepseek: Cordis row %q is not owned by this installation", deepseekPatchID)
				}
				if found {
					return nil, fmt.Errorf("deepseek: duplicate Cordis bridge registration")
				}
				found = true
				if !remove {
					var fields map[string]interface{}
					if err := rows.Content[j].Decode(&fields); err != nil {
						return nil, err
					}
					config, ok := fields["config"].(map[string]interface{})
					if len(fields) != 3 || !ok || len(config) != 2 || config["defaultTimeoutMs"] != 15000 {
						return nil, fmt.Errorf("deepseek: modified Cordis bridge registration; restore its original settings before setup")
					}
					continue
				}
				rows.Content = append(rows.Content[:j], rows.Content[j+1:]...)
				j--
			}
		}
	}
	if !remove && found {
		return current, nil
	}
	if !remove {
		row := map[string]interface{}{"insert": []interface{}{map[string]interface{}{
			"id": deepseekPatchID, "name": "@deepseek-ai/dsh-hooks-claude-code",
			"config": map[string]interface{}{"configPath": deepseekHooksPath(opts), "defaultTimeoutMs": 15000},
		}}}
		var node yaml.Node
		if err := node.Encode(row); err != nil {
			return nil, err
		}
		root.Content = append(root.Content, &node)
	}
	return yaml.Marshal(&doc)
}

func (c *DeepSeekConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "cordis.patch.yml", deepseekPatchPath(opts))
	if err != nil {
		return err
	}
	if !restored {
		if err := c.transformPatch(opts, true); err != nil {
			return err
		}
	}
	if err := c.hookOnlyConnector.Teardown(ctx, opts); err != nil {
		return err
	}
	if err := c.VerifyClean(opts); err != nil {
		return err
	}
	discardManagedFileBackup(opts.DataDir, c.name, "cordis.patch.yml")
	return nil
}

func patchDeepSeekHooks(path, command string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if raw, exists := cfg["hooks"]; exists {
		if _, ok := raw.(map[string]interface{}); !ok {
			return fmt.Errorf("deepseek: hooks must be an object")
		}
	}
	hooks := ensureJSONObject(cfg, "hooks")
	for _, event := range deepseekEvents {
		entry := map[string]interface{}{"matcher": "", "hooks": []interface{}{map[string]interface{}{
			"type": "command", "command": command, "timeout": 15,
		}}}
		if raw, exists := hooks[event]; exists {
			if _, ok := raw.([]interface{}); !ok {
				return fmt.Errorf("deepseek: %s hooks must be an array", event)
			}
		}
		hooks[event] = append(pruneDeepSeekHookGroups(hooks[event], command), entry)
	}
	return writeJSONObject(path, cfg)
}

func deepseekProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := devinProfileDecode(payload)
	req.ConnectorName = "deepseek"
	// The bridge supplies exactly tool_input. No guessing from the envelope.
	req.ToolArgsAuthoritative = true
	if args, exists := payload["tool_input"]; exists {
		req.ToolArgs, _ = json.Marshal(args)
	}
	return req
}

// DeepSeekHookOutput renders only decisions supported by the vendor bridge.
func DeepSeekHookOutput(event, action, reason string) map[string]interface{} {
	if event == "PreToolUse" && (action == "block" || action == "confirm") {
		decision := "deny"
		if action == "confirm" {
			decision = "ask"
		}
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName": event, "permissionDecision": decision, "permissionDecisionReason": reason,
		}}
	}
	if event == "UserPromptSubmit" && action == "block" {
		return map[string]interface{}{"decision": "block", "reason": reason}
	}
	// Stop must never force an unbounded continuation loop. PostToolUse is
	// observation only: the bridge cannot replace the original tool output.
	return nil
}

func deepseekToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{},
		AuthoritativeFailureEvents:        []string{},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{},
		AuthoritativeTerminalEvents:       []string{},
		InvocationIDAuthority:             ToolInvocationIDPairedID,
		OutcomeAuthority:                  ToolOutcomeNone,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StateTransitionEvents:  []string{},
			StructuredActionEvents: []string{"PreToolUse"},
			ResultContentEvents:    []string{"PostToolUse"},
			AuditOnlyEvents:        []string{"SessionStart", "Stop", "SubagentStart", "SubagentStop"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{deepseekSource},
		Limitations: []string{
			"PostToolUse flattens output to text and omits isError; no authoritative success/failure or session terminal event is claimed.",
			"Hook infrastructure failures and missing configuration fail open upstream; native OTLP and managed enterprise are not supported.",
		},
	}
}

func (c *DeepSeekConnector) AgentPaths(opts SetupOpts) AgentPaths {
	paths := c.hookOnlyConnector.AgentPaths(opts)
	paths.PatchedFiles = append(paths.PatchedFiles, deepseekPatchPath(opts))
	paths.BackupFiles = append(paths.BackupFiles, managedFileBackupPath(opts.DataDir, c.name, "cordis.patch.yml"))
	return paths
}

func (c *DeepSeekConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	cfg, err := readJSONObject(deepseekHooksPath(opts))
	if err != nil {
		return false, err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	for _, event := range deepseekEvents {
		groups, ok := hooks[event].([]interface{})
		if !ok {
			return false, nil
		}
		found := false
		for _, raw := range groups {
			group, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if matcher, _ := group["matcher"].(string); matcher != "" {
				continue
			}
			handlers, _ := group["hooks"].([]interface{})
			for _, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]interface{})
				if ok && handler["command"] == c.hookCommand(opts) && handler["type"] == "command" && handler["timeout"] == json.Number("15") {
					found = true
				}
			}
		}
		if !found {
			return false, nil
		}
	}
	raw, err := readHookConfigFile(deepseekPatchPath(opts))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := deepseekPatch(raw, opts, false); err != nil {
		return false, err
	}
	without, err := deepseekPatch(raw, opts, true)
	if err != nil {
		return false, err
	}
	// Compare decoded trees: YAML formatting alone does not indicate ownership.
	var before, after interface{}
	if err := yaml.Unmarshal(raw, &before); err != nil {
		return false, err
	}
	if err := yaml.Unmarshal(without, &after); err != nil {
		return false, err
	}
	a, _ := yaml.Marshal(before)
	b, _ := yaml.Marshal(after)
	return !bytes.Equal(a, b), nil
}

func (c *DeepSeekConnector) VerifyClean(opts SetupOpts) error {
	if err := c.hookOnlyConnector.VerifyClean(opts); err != nil {
		return err
	}
	raw, err := readHookConfigFile(deepseekPatchPath(opts))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var before, after interface{}
	without, err := deepseekPatch(raw, opts, true)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(raw, &before); err != nil {
		return err
	}
	if err := yaml.Unmarshal(without, &after); err != nil {
		return err
	}
	a, _ := yaml.Marshal(before)
	b, _ := yaml.Marshal(after)
	if !bytes.Equal(a, b) {
		return fmt.Errorf("deepseek teardown incomplete: Cordis bridge still registered")
	}
	return nil
}

func pruneDeepSeekHookGroups(raw interface{}, command string) []interface{} {
	groups, _ := raw.([]interface{})
	kept := make([]interface{}, 0, len(groups))
	for _, rawGroup := range groups {
		group, ok := rawGroup.(map[string]interface{})
		if !ok {
			kept = append(kept, rawGroup)
			continue
		}
		handlers, ok := group["hooks"].([]interface{})
		if !ok {
			kept = append(kept, group)
			continue
		}
		remaining := make([]interface{}, 0, len(handlers))
		removed := false
		for _, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]interface{})
			if ok && handler["type"] == "command" && handler["command"] == command {
				removed = true
				continue
			}
			remaining = append(remaining, rawHandler)
		}
		if !removed {
			kept = append(kept, group)
			continue
		}
		if len(remaining) > 0 {
			group["hooks"] = remaining
			kept = append(kept, group)
		}
	}
	return kept
}

func removeDeepSeekHookReferences(path, command string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return nil
	}
	for event, raw := range hooks {
		if _, ok := raw.([]interface{}); !ok {
			continue
		}
		hooks[event] = pruneDeepSeekHookGroups(raw, command)
	}
	return writeJSONObject(path, cfg)
}

// Repeated setup must not adopt an operator's later edits into our post-hash
// while retaining an older pristine file: that would erase those edits on
// teardown. Rebase only drifted receipts, stripping our exact registration.
func rebaseDeepSeekBackup(opts SetupOpts, logical, path, command string) error {
	backup, err := loadManagedFileBackupForTransform(opts.DataDir, "deepseek", logical, path)
	if err != nil || backup == nil {
		return err
	}
	current, info, err := readManagedTarget(path)
	if err != nil {
		return err
	}
	if managedFileBackupMatchesSnapshot(backup, current, info != nil) {
		return nil
	}
	pristine := current
	if info != nil {
		if logical == "cordis.patch.yml" {
			pristine, err = deepseekPatch(current, opts, true)
		} else {
			var cfg map[string]interface{}
			decoder := json.NewDecoder(bytes.NewReader(current))
			decoder.UseNumber()
			if err = decoder.Decode(&cfg); err == nil {
				if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
					for event, raw := range hooks {
						if _, ok := raw.([]interface{}); ok {
							hooks[event] = pruneDeepSeekHookGroups(raw, command)
						}
					}
				}
				pristine, err = json.MarshalIndent(cfg, "", "  ")
			}
		}
		if err != nil {
			return err
		}
		backup.Mode = uint32(info.Mode().Perm())
	}
	backup.Existed = info != nil
	backup.PristineBytes = pristine
	backup.PristineSHA256 = managedFileSnapshotHash(pristine, info != nil)
	backup.PostSHA256 = managedFileSnapshotHash(current, info != nil)
	return writeManagedFileBackup(managedFileBackupPath(opts.DataDir, "deepseek", logical), *backup)
}
