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

// ResolveApproval approves or rejects an exec approval request.
func (c *Client) ResolveApproval(ctx context.Context, id string, approved bool, reason string) error {
	params := ApprovalResolveParams{
		ID:       id,
		Approved: approved,
		Reason:   reason,
	}
	_, err := c.Request(ctx, "exec.approval.resolve", params)
	if err != nil {
		return fmt.Errorf("gateway: resolve approval %q: %w", id, err)
	}
	return nil
}
