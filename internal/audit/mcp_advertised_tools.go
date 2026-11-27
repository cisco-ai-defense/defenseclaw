// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// MCPAdvertisedToolSnapshot is the bounded, content-free result of one
// authoritative tools/list operation.
type MCPAdvertisedToolSnapshot struct {
	ParentComponentID string
	Connector         string
	ServerName        string
	ToolNames         []string
	ListedAt          time.Time
	Partial           bool
}

func migrateMCPAdvertisedTools(ex dbExecer) error {
	_, err := ex.Exec(`
		CREATE TABLE IF NOT EXISTS mcp_advertised_tool_parents (
			parent_component_id TEXT PRIMARY KEY,
			connector TEXT NOT NULL,
			server_name TEXT NOT NULL,
			listed_at DATETIME NOT NULL,
			partial INTEGER NOT NULL DEFAULT 0 CHECK (partial IN (0, 1))
		);
		CREATE TABLE IF NOT EXISTS mcp_advertised_tools (
			parent_component_id TEXT NOT NULL,
			tool_name TEXT NOT NULL,
			PRIMARY KEY (parent_component_id, tool_name),
			FOREIGN KEY (parent_component_id) REFERENCES mcp_advertised_tool_parents(parent_component_id) ON DELETE CASCADE
		);
	`)
	if err != nil {
		return fmt.Errorf("audit: migrate advertised MCP tools: %w", err)
	}
	return nil
}

func validateMCPAdvertisedToolSnapshot(input MCPAdvertisedToolSnapshot) (MCPAdvertisedToolSnapshot, error) {
	base, err := validateMCPObservedTool(MCPObservedTool{
		ObservationGroupID: input.ParentComponentID, Connector: input.Connector,
		ServerName: input.ServerName, ToolName: "placeholder", LastObservedAt: input.ListedAt,
	})
	if err != nil {
		return MCPAdvertisedToolSnapshot{}, err
	}
	input.ParentComponentID, input.Connector, input.ServerName = base.ObservationGroupID, base.Connector, base.ServerName
	input.ListedAt = base.LastObservedAt
	if len(input.ToolNames) > maxMCPToolsPerGroup {
		return MCPAdvertisedToolSnapshot{}, fmt.Errorf("audit: too many advertised MCP tools")
	}
	seen := make(map[string]struct{}, len(input.ToolNames))
	for _, name := range input.ToolNames {
		if !validMCPObservedText(name, maxMCPObservedToolName, true) {
			return MCPAdvertisedToolSnapshot{}, fmt.Errorf("audit: invalid advertised MCP tool name")
		}
		if _, exists := seen[name]; exists {
			return MCPAdvertisedToolSnapshot{}, fmt.Errorf("audit: duplicate advertised MCP tool name")
		}
		seen[name] = struct{}{}
	}
	return input, nil
}

func (s *Store) ReplaceMCPAdvertisedToolsIf(ctx context.Context, input MCPAdvertisedToolSnapshot, stillCurrent func() bool) error {
	if s == nil || s.db == nil || ctx == nil {
		return fmt.Errorf("audit: advertised MCP tool store is not initialized")
	}
	snapshot, err := validateMCPAdvertisedToolSnapshot(input)
	if err != nil {
		return err
	}
	return s.callGroupWrite(ctx, func(runCtx context.Context, tx *sql.Tx) error {
		if stillCurrent != nil && !stillCurrent() {
			return nil
		}
		if _, err := tx.ExecContext(runCtx, `DELETE FROM mcp_advertised_tools WHERE parent_component_id = ?`, snapshot.ParentComponentID); err != nil {
			return fmt.Errorf("audit: clear advertised MCP tools: %w", err)
		}
		if _, err := tx.ExecContext(runCtx, `
			INSERT INTO mcp_advertised_tool_parents (parent_component_id, connector, server_name, listed_at, partial)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(parent_component_id) DO UPDATE SET connector=excluded.connector,
				server_name=excluded.server_name, listed_at=excluded.listed_at, partial=excluded.partial`,
			snapshot.ParentComponentID, snapshot.Connector, snapshot.ServerName, snapshot.ListedAt, snapshot.Partial); err != nil {
			return fmt.Errorf("audit: replace advertised MCP tool parent: %w", err)
		}
		for _, name := range snapshot.ToolNames {
			if _, err := tx.ExecContext(runCtx, `INSERT INTO mcp_advertised_tools (parent_component_id, tool_name) VALUES (?, ?)`, snapshot.ParentComponentID, name); err != nil {
				return fmt.Errorf("audit: insert advertised MCP tool: %w", err)
			}
		}
		return nil
	})
}

func (s *Store) ListMCPAdvertisedToolSnapshots(ctx context.Context) ([]MCPAdvertisedToolSnapshot, error) {
	rows, err := s.queryDB(ctx, "mcp_advertised_tools_list", `
		SELECT parents.parent_component_id, parents.connector, parents.server_name,
			parents.listed_at, parents.partial, tools.tool_name
		FROM mcp_advertised_tool_parents AS parents
		LEFT JOIN mcp_advertised_tools AS tools ON tools.parent_component_id = parents.parent_component_id
		ORDER BY parents.parent_component_id, tools.tool_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []MCPAdvertisedToolSnapshot
	for rows.Next() {
		var parent, connector, server string
		var listed time.Time
		var partial bool
		var name sql.NullString
		if err := rows.Scan(&parent, &connector, &server, &listed, &partial, &name); err != nil {
			return nil, err
		}
		if len(result) == 0 || result[len(result)-1].ParentComponentID != parent {
			result = append(result, MCPAdvertisedToolSnapshot{ParentComponentID: parent, Connector: connector, ServerName: server, ListedAt: listed, Partial: partial})
		}
		if name.Valid {
			result[len(result)-1].ToolNames = append(result[len(result)-1].ToolNames, name.String)
		}
	}
	return result, rows.Err()
}
