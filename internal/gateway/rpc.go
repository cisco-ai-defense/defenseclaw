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
	"encoding/json"
	"fmt"
)

// DisableSkill tells the gateway to disable a skill by key.
func (c *Client) DisableSkill(ctx context.Context, skillKey string) error {
	params := SkillsUpdateParams{
		SkillKey: skillKey,
		Enabled:  false,
	}
	_, err := c.Request(ctx, "skills.update", params)
	if err != nil {
		return fmt.Errorf("gateway: disable skill %q: %w", skillKey, err)
	}
	return nil
}

// EnableSkill tells the gateway to enable a skill by key.
func (c *Client) EnableSkill(ctx context.Context, skillKey string) error {
	params := SkillsUpdateParams{
		SkillKey: skillKey,
		Enabled:  true,
	}
	_, err := c.Request(ctx, "skills.update", params)
	if err != nil {
		return fmt.Errorf("gateway: enable skill %q: %w", skillKey, err)
	}
	return nil
}

// BlockMCPServer tells the gateway to block an MCP server by name.
// Uses config.patch since the gateway has no native MCP management RPC.
func (c *Client) BlockMCPServer(ctx context.Context, serverName string) error {
	params := ConfigPatchParams{
		Path:  "mcp.blocked." + serverName,
		Value: true,
	}
	_, err := c.Request(ctx, "config.patch", params)
	if err != nil {
		return fmt.Errorf("gateway: block MCP server %q: %w", serverName, err)
	}
	return nil
}

// pluginConfigRaw builds the nested config object for plugin enable/disable.
// OpenClaw requires plugins to be in both plugins.allow and
// plugins.entries.<name>.enabled to be fully active.
func pluginConfigRaw(pluginName string, enabled bool, allowList []string) map[string]interface{} {
	cfg := map[string]interface{}{
		"plugins": map[string]interface{}{
			"allow": allowList,
			"entries": map[string]interface{}{
				pluginName: map[string]interface{}{
					"enabled": enabled,
				},
			},
		},
	}
	return cfg
}

// updateAllowList returns a new allow list with pluginName added (if enable)
// or removed (if disable), preserving existing entries.
func updateAllowList(current []string, pluginName string, add bool) []string {
	out := make([]string, 0, len(current)+1)
	for _, s := range current {
		if s != pluginName {
			out = append(out, s)
		}
	}
	if add {
		out = append(out, pluginName)
	}
	return out
}

// setPluginEnabled patches the OpenClaw config to enable or disable a plugin.
// Uses config.patch (merge) instead of config.set (replace) to avoid
// overwriting unrelated config. Requires a baseHash from config.get for
// optimistic concurrency control.
//
// OpenClaw requires plugins to appear in both plugins.allow and
// plugins.entries.<name>.enabled, so this function reads the current
// allow list and adds/removes the plugin name accordingly.
func (c *Client) setPluginEnabled(ctx context.Context, pluginName string, enabled bool) error {
	cfgResp, err := c.GetConfig(ctx)
	if err != nil {
		return fmt.Errorf("gateway: config.get for plugin %q: %w", pluginName, err)
	}

	var snapshot configGetResponse
	if err := json.Unmarshal(cfgResp, &snapshot); err != nil {
		return fmt.Errorf("gateway: parse config.get for plugin %q: %w", pluginName, err)
	}

	var currentAllow []string
	if snapshot.Config != nil && snapshot.Config.Plugins != nil {
		currentAllow = snapshot.Config.Plugins.Allow
	}
	newAllow := updateAllowList(currentAllow, pluginName, enabled)

	raw, err := json.Marshal(pluginConfigRaw(pluginName, enabled, newAllow))
	if err != nil {
		return fmt.Errorf("gateway: marshal config for plugin %q: %w", pluginName, err)
	}

	params := ConfigPatchRawParams{
		Raw:      string(raw),
		BaseHash: snapshot.Hash,
	}
	_, err = c.Request(ctx, "config.patch", params)
	if err != nil {
		return fmt.Errorf("gateway: config.patch plugin %q: %w", pluginName, err)
	}
	return nil
}

// DisablePlugin tells the gateway to disable a plugin by name.
// Uses config.get + config.patch since the gateway has no native plugin RPC.
func (c *Client) DisablePlugin(ctx context.Context, pluginName string) error {
	return c.setPluginEnabled(ctx, pluginName, false)
}

// EnablePlugin tells the gateway to enable a plugin by name.
// Uses config.get + config.patch since the gateway has no native plugin RPC.
func (c *Client) EnablePlugin(ctx context.Context, pluginName string) error {
	return c.setPluginEnabled(ctx, pluginName, true)
}

// GetConfig fetches the current gateway configuration.
func (c *Client) GetConfig(ctx context.Context) (json.RawMessage, error) {
	return c.Request(ctx, "config.get", nil)
}

// PatchConfig applies a partial configuration update.
func (c *Client) PatchConfig(ctx context.Context, path string, value interface{}) error {
	params := ConfigPatchParams{
		Path:  path,
		Value: value,
	}
	_, err := c.Request(ctx, "config.patch", params)
	if err != nil {
		return fmt.Errorf("gateway: config.patch %q: %w", path, err)
	}
	return nil
}

// GetStatus fetches gateway status.
func (c *Client) GetStatus(ctx context.Context) (json.RawMessage, error) {
	return c.Request(ctx, "status", nil)
}

// GetToolsCatalog fetches the runtime tool catalog with provenance metadata.
func (c *Client) GetToolsCatalog(ctx context.Context) (json.RawMessage, error) {
	return c.Request(ctx, "tools.catalog", nil)
}

// GetSkillsStatus fetches the installed skills and their current status.
func (c *Client) GetSkillsStatus(ctx context.Context) (json.RawMessage, error) {
	return c.Request(ctx, "skills.status", nil)
}

// GetSkillsBins fetches the available skill binaries/entries.
func (c *Client) GetSkillsBins(ctx context.Context) (json.RawMessage, error) {
	return c.Request(ctx, "skills.bins", nil)
}

// SessionsList fetches active sessions from the gateway.
func (c *Client) SessionsList(ctx context.Context) (json.RawMessage, error) {
	return c.Request(ctx, "sessions.list", nil)
}

// SessionsSubscribe subscribes to session events (including session.tool).
func (c *Client) SessionsSubscribe(ctx context.Context, sessionID string) error {
	params := map[string]string{"sessionId": sessionID}
	_, err := c.Request(ctx, "sessions.subscribe", params)
	if err != nil {
		return fmt.Errorf("gateway: sessions.subscribe %q: %w", sessionID, err)
	}
	return nil
}

// SessionsMessagesSubscribe subscribes to message-level events for a session.
func (c *Client) SessionsMessagesSubscribe(ctx context.Context, sessionID string) error {
	params := map[string]string{"sessionId": sessionID}
	_, err := c.Request(ctx, "sessions.messages.subscribe", params)
	if err != nil {
		return fmt.Errorf("gateway: sessions.messages.subscribe %q: %w", sessionID, err)
	}
	return nil
}

// SessionsSend sends a message to a specific session via the gateway.
// The gateway expects "key" (session key) and "message" (text content).
func (c *Client) SessionsSend(ctx context.Context, sessionKey string, text string) error {
	params := map[string]interface{}{
		"key":     sessionKey,
		"message": text,
	}
	_, err := c.Request(ctx, "sessions.send", params)
	if err != nil {
		return fmt.Errorf("gateway: sessions.send to %q: %w", sessionKey, err)
	}
	return nil
}

// ResolveApproval approves or rejects an exec approval request.
func (c *Client) ResolveApproval(ctx context.Context, id string, approved bool, reason string) error {
	decision := "deny"
	if approved {
		decision = "allow-once"
	}
	params := ApprovalResolveParams{
		ID:       id,
		Decision: decision,
	}
	_, err := c.Request(ctx, "exec.approval.resolve", params)
	if err != nil {
		return fmt.Errorf("gateway: resolve approval %q: %w", id, err)
	}
	return nil
}
