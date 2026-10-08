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

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// Operator block/allow requests change config.yaml asset_policy, the only
// block/allow list since config_version 9 (the audit.db actions rows are the
// enforcement journal). A managed standalone device refuses: its admin
// config comes from the management plane. Secure Client hosts keep writing
// the actions table, byte for byte as before.

const (
	assetListOpBlock   = "block"
	assetListOpAllow   = "allow"
	assetListOpUnblock = "unblock"
)

// assetListTargetTypes are the asset_policy lists /enforce/* may change.
var assetListTargetTypes = map[string]bool{"skill": true, "mcp": true, "plugin": true, "tool": true}

// assetListEdit is one operator block/allow/unblock of a named asset.
type assetListEdit struct {
	Op         string
	TargetType string
	Name       string
	Connector  string
	Reason     string
	SourcePath string
}

// assetListChange returns the writer change for edit against the current
// lists: a block or allow first drops every rule for the same name and
// connector from both lists (one decision per asset, as the actions table
// kept), then appends the new rule; an unblock only drops the denied rule.
// Names compare as the readers match them: skill, MCP and plugin names
// case-insensitively (assetRuleMatches), tool names exactly
// (ToolListDecision). An unnamed rule matches the first key shown by
// /enforce/blocked and /enforce/allowed. An exact compare left a denied
// MySkill in place on an unblock or allow of myskill (GAP-0319).
func assetListChange(cfg *config.Config, edit assetListEdit) []configwrite.Change {
	base := "asset_policy." + edit.TargetType
	sameAsset := func(name, connector string) bool {
		name = strings.TrimSpace(name)
		sameName := strings.EqualFold(name, strings.TrimSpace(edit.Name))
		if edit.TargetType == "tool" {
			sameName = name == edit.Name
		}
		return sameName && config.SameConnector(connector, edit.Connector)
	}
	if edit.TargetType == "tool" {
		denied, allowed := cfg.AssetPolicy.Tool.Denied, cfg.AssetPolicy.Tool.Allowed
		keep := func(rules []config.AssetPolicyToolRule) []map[string]any {
			out := []map[string]any{}
			for _, rule := range rules {
				if !sameAsset(rule.Name, rule.Connector) {
					out = append(out, toolRuleMap(rule))
				}
			}
			return out
		}
		nextDenied, nextAllowed := keep(denied), keep(allowed)
		if edit.Op == assetListOpUnblock {
			nextAllowed = nil
		}
		rule := toolRuleMap(config.AssetPolicyToolRule{Name: edit.Name, Connector: edit.Connector, Reason: edit.Reason})
		switch edit.Op {
		case assetListOpBlock:
			nextDenied = append(nextDenied, rule)
		case assetListOpAllow:
			nextAllowed = append(nextAllowed, rule)
		}
		return listChanges(base, nextDenied, nextAllowed)
	}

	var p config.AssetTypePolicy
	switch edit.TargetType {
	case "skill":
		p = cfg.AssetPolicy.Skill
	case "mcp":
		p = cfg.AssetPolicy.MCP
	case "plugin":
		p = cfg.AssetPolicy.Plugin
	}
	keep := func(rules []config.AssetPolicyRule) []map[string]any {
		out := []map[string]any{}
		for _, rule := range rules {
			matches := sameAsset(rule.Name, rule.Connector)
			if strings.TrimSpace(rule.Name) == "" {
				key := listedAssetRuleName(rule)
				matches = key != "" && key == strings.TrimSpace(edit.Name) &&
					config.SameConnector(rule.Connector, edit.Connector)
			}
			if !matches {
				out = append(out, assetRuleMap(rule))
			}
		}
		return out
	}
	nextDenied, nextAllowed := keep(p.Denied), keep(p.Allowed)
	if edit.Op == assetListOpUnblock {
		nextAllowed = nil
	}
	rule := config.AssetPolicyRule{Name: edit.Name, Connector: edit.Connector, Reason: edit.Reason}
	if edit.SourcePath != "" {
		rule.SourcePathContains = []string{edit.SourcePath}
	}
	switch edit.Op {
	case assetListOpBlock:
		nextDenied = append(nextDenied, assetRuleMap(rule))
	case assetListOpAllow:
		nextAllowed = append(nextAllowed, assetRuleMap(rule))
	}
	return listChanges(base, nextDenied, nextAllowed)
}

func listChanges(base string, denied, allowed []map[string]any) []configwrite.Change {
	changes := []configwrite.Change{{Path: base + ".denied", Value: denied}}
	if allowed != nil {
		changes = append(changes, configwrite.Change{Path: base + ".allowed", Value: allowed})
	}
	return changes
}

// assetRuleMap is the YAML mapping of an asset_policy rule with only the
// fields that are set.
func assetRuleMap(rule config.AssetPolicyRule) map[string]any {
	out := map[string]any{}
	for key, value := range map[string]string{
		"name": rule.Name, "connector": rule.Connector, "reason": rule.Reason,
		"url": rule.URL, "command": rule.Command, "transport": rule.Transport,
	} {
		if strings.TrimSpace(value) != "" {
			out[key] = value
		}
	}
	if len(rule.ArgsPrefix) > 0 {
		out["args_prefix"] = append([]string(nil), rule.ArgsPrefix...)
	}
	if len(rule.SourcePathContains) > 0 {
		out["source_path_contains"] = append([]string(nil), rule.SourcePathContains...)
	}
	return out
}

func toolRuleMap(rule config.AssetPolicyToolRule) map[string]any {
	out := map[string]any{"name": rule.Name}
	if strings.TrimSpace(rule.Connector) != "" {
		out["connector"] = rule.Connector
	}
	if strings.TrimSpace(rule.Reason) != "" {
		out["reason"] = rule.Reason
	}
	return out
}

// assetListResult is the writer result and the error of the reload that
// followed it. The edit is saved either way.
type assetListResult struct {
	configwrite.Result
	reloadErr error
}

// enforceWriteResponse is the /enforce write reply: the status, the
// config_generation the writer recorded and, once the gateway has applied
// it, the live generation's effective_policy_digest. When the gateway refused
// the reload (a restart-required key it can not keep at its running value),
// the reply says so instead of passing the old generation's digest off as the
// new one's.
func (a *APIServer) enforceWriteResponse(status string, result assetListResult) map[string]any {
	out := map[string]any{"status": status, "generation": result.Generation}
	if result.reloadErr != nil {
		out["applied"] = false
		out["reload_error"] = result.reloadErr.Error()
		return out
	}
	if g := a.generation(); g != nil && g.Digest != "" {
		out["effective_policy_digest"] = g.Digest
	}
	return out
}

// applyAssetListEdit writes edit to config.yaml through the single writer,
// reading the lists from the file it changes (compare-and-swap on its
// sha256, retried when another writer got there first), then applies the
// new config to this gateway.
func (a *APIServer) applyAssetListEdit(ctx context.Context, edit assetListEdit, actor string) (assetListResult, error) {
	// Written as the canonical connector name the runtime passes.
	edit.Connector = config.NormalizeConnectorName(edit.Connector)
	path := configFilePathForSnapshot(a.liveConfig())
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		raw, err := os.ReadFile(path)
		if err != nil {
			return assetListResult{}, fmt.Errorf("read %s: %w", path, err)
		}
		sum := sha256.Sum256(raw)
		var current struct {
			AssetPolicy config.AssetPolicyConfig `yaml:"asset_policy"`
		}
		if err := yaml.Unmarshal(raw, &current); err != nil {
			return assetListResult{}, fmt.Errorf("parse %s: %w", path, err)
		}
		changes := assetListChange(&config.Config{AssetPolicy: current.AssetPolicy}, edit)
		apply := a.configApply
		if apply == nil {
			apply = configwrite.Apply
		}
		result, err := apply(ctx, path, changes, configwrite.Options{
			Actor:        actor,
			Reason:       fmt.Sprintf("%s %s %s", edit.Op, edit.TargetType, edit.Name),
			ExpectSHA256: hex.EncodeToString(sum[:]),
		})
		if errors.Is(err, configwrite.ErrConflict) {
			lastErr = err
			continue
		}
		if err != nil {
			return assetListResult{}, err
		}
		out := assetListResult{Result: result}
		if a.configReloader != nil {
			if out.reloadErr = a.configReloader(ctx, "enforce_api"); out.reloadErr != nil {
				fmt.Fprintf(os.Stderr, "[api] config reload after %s %s %q: %v\n", edit.Op, edit.TargetType, edit.Name, out.reloadErr)
			}
		}
		return out, nil
	}
	return assetListResult{}, lastErr
}

// liveConfig is the config a read-only decision uses: the sidecar's
// published snapshot, else the startup config. Callers must not mutate it.
func (a *APIServer) liveConfig() *config.Config {
	if a == nil {
		return nil
	}
	if a.configSnapshot != nil {
		if cfg := a.configSnapshot(); cfg != nil {
			return cfg
		}
	}
	return a.scannerCfg
}

// apiConfigActor is the writer actor for a REST change: api:<principal>.
func apiConfigActor(ctx context.Context) string {
	principal := auditCallerIdentity(ctx).principalRef()
	if principal == "" {
		principal = "token"
	}
	return configwrite.ActorPrefixAPI + principal
}

// writeAssetListError maps a writer error to an HTTP status.
func (a *APIServer) writeAssetListError(w http.ResponseWriter, r *http.Request, action audit.Action, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, configwrite.ErrManaged):
		a.writeManagedDeviceRefusal(w, r, action)
		return
	case errors.Is(err, configwrite.ErrLockBusy):
		status = http.StatusServiceUnavailable
	case errors.Is(err, configwrite.ErrConflict):
		status = http.StatusConflict
	case errors.Is(err, configwrite.ErrNotImplemented):
		status = http.StatusNotImplemented
	}
	a.writeJSON(w, status, map[string]string{"error": err.Error()})
}

// refuseManagedPolicyWrite answers 403 on a managed standalone device, where
// policy changes are made in the management plane, and reports whether it
// did.
func (a *APIServer) refuseManagedPolicyWrite(w http.ResponseWriter, r *http.Request, action audit.Action) bool {
	cfg := a.liveConfig()
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return false
	}
	a.writeManagedDeviceRefusal(w, r, action)
	return true
}

// writeManagedDeviceRefusal audits the refused attempt (who asked for which
// change), then answers 403 managed_device.
func (a *APIServer) writeManagedDeviceRefusal(w http.ResponseWriter, r *http.Request, action audit.Action) {
	if a.logger != nil && r != nil {
		details := fmt.Sprintf("outcome=refused reason=managed_device method=%s actor=%s", r.Method, apiConfigActor(r.Context()))
		_ = a.logger.LogActionCtx(r.Context(), string(action), r.URL.Path, details)
	}
	a.writeJSON(w, http.StatusForbidden, map[string]string{
		"error":  "managed_device",
		"detail": "policy changes are made in the management plane",
	})
}

// configListEntries lists asset_policy denied or allowed rules as the
// /enforce/blocked and /enforce/allowed entries. Rules without a name
// (matched on URL, command or path) are listed under their first match key.
func configListEntries(cfg *config.Config, denied bool) []enforcementEntry {
	out := []enforcementEntry{}
	if cfg == nil {
		return out
	}
	updated := time.Time{}
	if info, err := os.Stat(configFilePathForSnapshot(cfg)); err == nil {
		updated = info.ModTime().UTC()
	}
	add := func(targetType, name, connector, reason string) {
		id := "asset_policy:" + targetType + ":" + name
		if connector != "" {
			id += "@" + connector
		}
		out = append(out, enforcementEntry{
			ID: id, TargetType: targetType, TargetName: name, Reason: reason,
			Connector: connector, UpdatedAt: updated,
		})
	}
	for _, typed := range []struct {
		targetType string
		policy     config.AssetTypePolicy
	}{{"skill", cfg.AssetPolicy.Skill}, {"mcp", cfg.AssetPolicy.MCP}, {"plugin", cfg.AssetPolicy.Plugin}} {
		rules := typed.policy.Allowed
		if denied {
			rules = typed.policy.Denied
		}
		for _, rule := range rules {
			name := listedAssetRuleName(rule)
			add(typed.targetType, name, rule.Connector, rule.Reason)
		}
	}
	tools := cfg.AssetPolicy.Tool.Allowed
	if denied {
		tools = cfg.AssetPolicy.Tool.Denied
	}
	for _, rule := range tools {
		add("tool", rule.Name, rule.Connector, rule.Reason)
	}
	return out
}

func listedAssetRuleName(rule config.AssetPolicyRule) string {
	return firstNonEmptyString(rule.Name, rule.URL, rule.Command, strings.Join(rule.SourcePathContains, ","))
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
