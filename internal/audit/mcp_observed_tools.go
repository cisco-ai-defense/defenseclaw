// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	maxMCPObservedToolName      = 256
	maxMCPObservedServerName    = 256
	maxMCPObservedConnectorName = 128
	maxMCPObservedParentID      = 256
	maxMCPObservedUserID        = 256
	maxMCPObservedUserIDKind    = 64
	maxMCPObservedUserName      = 256
	maxMCPToolsPerGroup         = 256
	maxMCPObservedGroups        = 256
)

// MCPObservedTool is the content-free durable projection of an authenticated
// MCP tool call. Arguments, results, descriptions, schemas, URLs and secrets
// are deliberately not part of this state.
type MCPObservedTool struct {
	// ObservationGroupID is a local storage key for one connector, user, and
	// runtime server tuple. It is not an MCP server component ID and is never
	// exported as a parent relationship.
	ObservationGroupID string
	Connector          string
	ServerName         string
	ToolName           string
	UserID             string
	UserIDKind         string
	UserName           string
	FirstObservedAt    time.Time
	LastObservedAt     time.Time
	Overflowed         bool
}

func migrateMCPObservedTools(ex dbExecer) error {
	_, err := ex.Exec(`
		CREATE TABLE IF NOT EXISTS mcp_observed_tools (
			parent_component_id TEXT NOT NULL,
			connector TEXT NOT NULL,
			server_name TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			first_observed_at DATETIME NOT NULL,
			last_observed_at DATETIME NOT NULL,
			PRIMARY KEY (parent_component_id, tool_name)
		);
		CREATE INDEX IF NOT EXISTS idx_mcp_observed_tools_last_seen
			ON mcp_observed_tools(parent_component_id, last_observed_at DESC, tool_name);
		CREATE TABLE IF NOT EXISTS mcp_observed_tool_parents (
			parent_component_id TEXT PRIMARY KEY,
			overflowed INTEGER NOT NULL DEFAULT 0 CHECK (overflowed IN (0, 1))
		);
	`)
	if err != nil {
		return fmt.Errorf("audit: migrate observed MCP tools: %w", err)
	}
	return nil
}

// migrateMCPObservedToolCorrelationFields adds the user half of the backend
// correlation tuple. Existing rows used a configured-server component ID as
// their key and cannot be attributed safely after the contract change, so the
// bounded cache is cleared and rebuilt from authenticated calls.
func migrateMCPObservedToolCorrelationFields(ex dbExecer) error {
	present, err := tableExists(ex, "mcp_observed_tools")
	if err != nil || !present {
		return err
	}
	added := false
	for _, field := range []struct {
		column    string
		statement string
	}{
		{"user_id", `ALTER TABLE mcp_observed_tools ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`},
		{"user_id_kind", `ALTER TABLE mcp_observed_tools ADD COLUMN user_id_kind TEXT NOT NULL DEFAULT ''`},
		{"user_name", `ALTER TABLE mcp_observed_tools ADD COLUMN user_name TEXT NOT NULL DEFAULT ''`},
	} {
		exists, err := hasColumnDB(ex, "mcp_observed_tools", field.column)
		if err != nil {
			return fmt.Errorf("audit: inspect observed MCP correlation fields: %w", err)
		}
		if exists {
			continue
		}
		if _, err := ex.Exec(field.statement); err != nil {
			return fmt.Errorf("audit: migrate observed MCP correlation fields: %w", err)
		}
		added = true
	}
	if !added {
		return nil
	}
	if _, err := ex.Exec(`DELETE FROM mcp_observed_tools; DELETE FROM mcp_observed_tool_parents`); err != nil {
		return fmt.Errorf("audit: reset legacy observed MCP correlation state: %w", err)
	}
	return nil
}

func validateMCPObservedTool(tool MCPObservedTool) (MCPObservedTool, error) {
	groupID := strings.TrimSpace(tool.ObservationGroupID)
	connector := strings.ToLower(strings.TrimSpace(tool.Connector))
	server := strings.TrimSpace(tool.ServerName)
	name := strings.TrimSpace(tool.ToolName)
	userID := strings.TrimSpace(tool.UserID)
	userIDKind := strings.TrimSpace(tool.UserIDKind)
	userName := strings.TrimSpace(tool.UserName)
	if groupID != tool.ObservationGroupID || connector == "" || server != tool.ServerName || name != tool.ToolName ||
		userID != tool.UserID || userIDKind != tool.UserIDKind || userName != tool.UserName ||
		!validMCPObservedText(groupID, maxMCPObservedParentID, false) ||
		!validMCPObservedText(connector, maxMCPObservedConnectorName, false) ||
		!validMCPObservedText(server, maxMCPObservedServerName, true) ||
		!validMCPObservedText(name, maxMCPObservedToolName, true) ||
		!validOptionalMCPObservedText(userID, maxMCPObservedUserID) ||
		!validOptionalMCPObservedText(userIDKind, maxMCPObservedUserIDKind) ||
		!validOptionalMCPObservedText(userName, maxMCPObservedUserName) ||
		tool.LastObservedAt.IsZero() {
		return MCPObservedTool{}, fmt.Errorf("audit: invalid observed MCP tool projection")
	}
	tool.ObservationGroupID, tool.Connector, tool.ServerName, tool.ToolName = groupID, connector, server, name
	tool.UserID, tool.UserIDKind, tool.UserName = userID, userIDKind, userName
	tool.LastObservedAt = tool.LastObservedAt.UTC()
	if tool.FirstObservedAt.IsZero() {
		tool.FirstObservedAt = tool.LastObservedAt
	} else {
		tool.FirstObservedAt = tool.FirstObservedAt.UTC()
	}
	return tool, nil
}

func validOptionalMCPObservedText(value string, maxBytes int) bool {
	if value == "" {
		return true
	}
	return validMCPObservedText(value, maxBytes, false)
}

func validMCPObservedText(value string, maxBytes int, rejectSlash bool) bool {
	if value == "" || len(value) > maxBytes || rejectSlash && strings.ContainsAny(value, `/\`) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func upsertMCPObservedToolTx(ctx context.Context, tx *sql.Tx, tool MCPObservedTool) error {
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO mcp_observed_tool_parents (parent_component_id, overflowed)
		SELECT ?, 0
		WHERE EXISTS (
			SELECT 1 FROM mcp_observed_tool_parents WHERE parent_component_id = ?
		) OR (SELECT COUNT(*) FROM mcp_observed_tool_parents) < ?
		ON CONFLICT(parent_component_id) DO NOTHING`,
		tool.ObservationGroupID, tool.ObservationGroupID, maxMCPObservedGroups); err != nil {
		return fmt.Errorf("audit: prepare observed MCP tool parent: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO mcp_observed_tools (
			parent_component_id, connector, server_name, tool_name,
			user_id, user_id_kind, user_name, first_observed_at, last_observed_at
		)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE EXISTS (
			SELECT 1 FROM mcp_observed_tool_parents WHERE parent_component_id = ?
		) AND (EXISTS (
			SELECT 1 FROM mcp_observed_tools
			WHERE parent_component_id = ? AND tool_name = ?
		) OR (
			SELECT COUNT(*) FROM mcp_observed_tools WHERE parent_component_id = ?
		) < ?)
		ON CONFLICT(parent_component_id, tool_name) DO UPDATE SET
			connector = excluded.connector,
			server_name = excluded.server_name,
			user_id = excluded.user_id,
			user_id_kind = excluded.user_id_kind,
			user_name = excluded.user_name,
			first_observed_at = CASE
				WHEN excluded.first_observed_at < mcp_observed_tools.first_observed_at
				THEN excluded.first_observed_at
				ELSE mcp_observed_tools.first_observed_at
			END,
			last_observed_at = CASE
				WHEN excluded.last_observed_at > mcp_observed_tools.last_observed_at
				THEN excluded.last_observed_at
				ELSE mcp_observed_tools.last_observed_at
			END`,
		tool.ObservationGroupID, tool.Connector, tool.ServerName, tool.ToolName,
		tool.UserID, tool.UserIDKind, tool.UserName,
		tool.FirstObservedAt, tool.LastObservedAt,
		tool.ObservationGroupID, tool.ObservationGroupID, tool.ToolName,
		tool.ObservationGroupID, maxMCPToolsPerGroup,
	)
	if err != nil {
		return fmt.Errorf("audit: upsert observed MCP tool: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("audit: inspect observed MCP tool upsert: %w", err)
	}
	if changed == 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE mcp_observed_tool_parents SET overflowed = 1
			WHERE parent_component_id = ?`, tool.ObservationGroupID); err != nil {
			return fmt.Errorf("audit: mark observed MCP tool overflow: %w", err)
		}
	}
	return nil
}

// UpsertMCPObservedTool records one authenticated tool without replacing any
// sibling. Inside a hook CallWriteBatch it joins that call's existing SQLite
// transaction; otherwise it uses the ordinary grouped durable write path.
func (s *Store) UpsertMCPObservedTool(ctx context.Context, input MCPObservedTool) error {
	return s.UpsertMCPObservedToolIf(ctx, input, nil)
}

// UpsertMCPObservedToolIf records one authenticated tool only if stillCurrent
// remains true when the durable transaction actually executes. The predicate
// closes the gap between hook-time attribution and a concurrent authoritative
// parent refresh, including when a CallWriteBatch defers this write.
func (s *Store) UpsertMCPObservedToolIf(ctx context.Context, input MCPObservedTool, stillCurrent func() bool) error {
	if s == nil || s.db == nil || ctx == nil {
		return fmt.Errorf("audit: observed MCP tool store is not initialized")
	}
	tool, err := validateMCPObservedTool(input)
	if err != nil {
		return err
	}
	run := func(runCtx context.Context, tx *sql.Tx) error {
		if stillCurrent != nil && !stillCurrent() {
			return nil
		}
		return upsertMCPObservedToolTx(runCtx, tx, tool)
	}
	if batch := deferringBatch(ctx, s); batch != nil {
		report, _ := ctx.Value(callWriteReportKey{}).(*CallWriteReport)
		if !report.claim() {
			report = nil
		}
		if batch.add(&deferredCallWrite{
			ctx: ctx, report: report,
			run: run,
			alone: func(aloneCtx context.Context) error {
				return s.callGroupWrite(aloneCtx, run)
			},
		}) {
			return nil
		}
		report.unclaim()
	}
	return s.callGroupWrite(ctx, run)
}

// ListMCPObservedTools restores the bounded projection after a gateway restart.
func (s *Store) ListMCPObservedTools(ctx context.Context) ([]MCPObservedTool, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, fmt.Errorf("audit: observed MCP tool store is not initialized")
	}
	rows, err := s.queryDB(ctx, "mcp_observed_tools_list", `
		SELECT tools.parent_component_id, tools.connector, tools.server_name, tools.tool_name,
			tools.user_id, tools.user_id_kind, tools.user_name,
			tools.first_observed_at, tools.last_observed_at, parents.overflowed
		FROM mcp_observed_tools AS tools
		JOIN mcp_observed_tool_parents AS parents
			ON parents.parent_component_id = tools.parent_component_id
		ORDER BY tools.parent_component_id, tools.tool_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tools []MCPObservedTool
	for rows.Next() {
		var tool MCPObservedTool
		if err := rows.Scan(&tool.ObservationGroupID, &tool.Connector, &tool.ServerName, &tool.ToolName,
			&tool.UserID, &tool.UserIDKind, &tool.UserName,
			&tool.FirstObservedAt, &tool.LastObservedAt, &tool.Overflowed); err != nil {
			return nil, fmt.Errorf("audit: scan observed MCP tool: %w", err)
		}
		tools = append(tools, tool)
	}
	return tools, rows.Err()
}

// DeleteMCPAdvertisedToolsForParents retires tools/list evidence only after an
// authoritative parent refresh proves that the configured server changed or
// left. Observed calls are independent of configuration inventory.
func (s *Store) DeleteMCPAdvertisedToolsForParents(ctx context.Context, parentIDs []string) error {
	if s == nil || s.db == nil || ctx == nil || len(parentIDs) == 0 {
		return nil
	}
	clean := make([]string, 0, len(parentIDs))
	seen := make(map[string]struct{}, len(parentIDs))
	for _, raw := range parentIDs {
		id := strings.TrimSpace(raw)
		if id == "" || len(id) > maxMCPObservedParentID {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		clean = append(clean, id)
	}
	if len(clean) == 0 {
		return nil
	}
	return s.callGroupWrite(ctx, func(runCtx context.Context, tx *sql.Tx) error {
		for _, id := range clean {
			if _, err := tx.ExecContext(runCtx, `DELETE FROM mcp_advertised_tools WHERE parent_component_id = ?`, id); err != nil {
				return fmt.Errorf("audit: delete advertised MCP tools for parent: %w", err)
			}
			if _, err := tx.ExecContext(runCtx, `DELETE FROM mcp_advertised_tool_parents WHERE parent_component_id = ?`, id); err != nil {
				return fmt.Errorf("audit: delete advertised MCP tool parent: %w", err)
			}
		}
		return nil
	})
}
