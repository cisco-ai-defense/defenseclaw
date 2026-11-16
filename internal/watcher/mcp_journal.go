// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// AccountMCPJournalType is the target type under which the actions journal
// keeps the install block and runtime disable of an enrolled account's MCP
// server. The row is identified by (type, name, connector), and a server
// name is free text: an account-less server may be named exactly like an
// account server's versioned key, and under one type the two would share a
// row, so the scan or release of one would overwrite or erase the other's
// decision. Under their own type the two cannot meet, whatever a server is
// named.
const AccountMCPJournalType = audit.AccountMCPActionType

// MCPJournalName is the name under which the actions journal keeps the
// install block and runtime disable of an MCP server, and MCPJournalType the
// target type of that row. A server a managed gateway read from an enrolled
// user's home is journaled under AccountMCPJournalType and its event path
// (name, connector, account home and project), so the verdict of one
// account's server never refuses, and the rescan of one never releases,
// another account's server of the same name (GAP-0216), nor an account-less
// server of any name. Every other server keeps its name under the "mcp" type,
// as before.
func MCPJournalName(server config.MCPServerEntry) string {
	if server.Home != "" {
		return MCPEventPath(server)
	}
	return server.Name
}

// MCPJournalType is the target type of the journal row MCPJournalName names.
func MCPJournalType(server config.MCPServerEntry) string {
	if server.Home != "" {
		return AccountMCPJournalType
	}
	return string(InstallMCP)
}

// journalTarget is the journal row (target type and name) of the target of
// evt: an enrolled account's MCP server under AccountMCPJournalType and its
// event path, everything else under targetType and the event name.
func journalTarget(evt InstallEvent, targetType string) (string, string) {
	if evt.Type == InstallMCP && IsAccountMCPJournalName(evt.Name, evt.Path) {
		return AccountMCPJournalType, evt.Path
	}
	return targetType, evt.Name
}

// IsAccountMCPJournalName reports whether key is the versioned event path of
// the MCP server name of an enrolled account.
func IsAccountMCPJournalName(name, key string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	identity, ok := decodeMCPEventPath(key)
	return ok && identity.Name == name && identity.Connector != "" && identity.Home != ""
}

// MCPAccountJournalServes reports whether the account journal row key (an
// MCPJournalName of an enrolled account's server) is the server a tool call
// reaches: the call's connector, a server name the call spells, the caller's
// home and, for a project server, a project the agent works in. A caller
// whose home is not known matches every account, and a call without a
// working folder matches every project of the account: both refuse rather
// than miss a block (fail closed). Old unstructured keys match nothing.
func MCPAccountJournalServes(key string, q MCPAdmissionQuery) bool {
	identity, ok := decodeMCPEventPath(key)
	return ok && identity.Connector != "" && identity.Home != "" && mcpServerServesQuery(identity.server(), q)
}

// MCPAccountRuntimeDisabled reports an account journal row (of
// AccountMCPJournalType) whose runtime disable is its own server's admission
// decision: the disable was written with the row's key as its deciding path,
// in one statement (audit.SetRuntimeDisableForConnector). No release before
// 1.0.9 wrote that path, and every other runtime write drops it, so a row
// moved here from a bare-name row (MigrateAccountMCPJournal) stays inert
// until normal admission records a new outcome, while a fresh decision needs
// no other table to be in force.
func MCPAccountRuntimeDisabled(row audit.ActionEntry) bool {
	return row.Actions.Runtime == "disable" && row.RuntimeSource != "" && row.RuntimeSource == row.TargetName
}

// MigrateAccountMCPJournal moves the MCP journal rows that earlier versions
// kept under the bare server name for an enrolled account's server to that
// server's account key (MCPJournalName), on a gateway that admits the
// servers of several accounts. The row's source path is the server's event
// path, so it names the account the verdict was for. The account row is
// written before the bare row is removed, so the block holds at every
// moment; fields an account row already has are kept, and missing ones are
// added from the bare row. An old row without a versioned source path stays
// stored but is ignored by runtime policy until normal admission records a
// new outcome. Explicit operator decisions come from asset_policy.
func MigrateAccountMCPJournal(store *audit.Store) (moved, kept int, err error) {
	if store == nil {
		return 0, 0, nil
	}
	rows, err := store.ListActionsByType(string(InstallMCP))
	if err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		if row.Connector == "" {
			continue // a global row
		}
		if !IsAccountMCPJournalName(row.TargetName, row.SourcePath) {
			_, versioned := decodeMCPEventPath(row.SourcePath)
			if (row.SourcePath == "" || versioned) &&
				(row.Actions.Runtime == "disable" || row.Actions.Install == "block") {
				kept++
			}
			continue
		}
		key := row.SourcePath
		current, err := store.GetActionForConnector(AccountMCPJournalType, key, row.Connector)
		if err != nil {
			return moved, kept, err
		}
		if current == nil {
			if err := store.SetActionForConnector(AccountMCPJournalType, key, row.Connector, row.SourcePath, row.Actions, row.Reason); err != nil {
				return moved, kept, fmt.Errorf("move mcp journal row %s: %w", row.TargetName, err)
			}
		} else {
			for field, value := range map[string]string{"install": row.Actions.Install, "runtime": row.Actions.Runtime, "file": row.Actions.File} {
				if value == "" || accountFieldSet(current.Actions, field) {
					continue
				}
				if err := store.SetActionFieldForConnector(AccountMCPJournalType, key, row.Connector, field, value, row.Reason); err != nil {
					return moved, kept, fmt.Errorf("move mcp journal row %s: %w", row.TargetName, err)
				}
			}
		}
		if err := store.RemoveActionForConnector(row.TargetType, row.TargetName, row.Connector); err != nil {
			return moved, kept, fmt.Errorf("remove moved mcp journal row %s: %w", row.TargetName, err)
		}
		moved++
	}
	return moved, kept, nil
}

func accountFieldSet(state audit.ActionState, field string) bool {
	switch field {
	case "install":
		return state.Install != ""
	case "runtime":
		return state.Runtime != ""
	default:
		return state.File != ""
	}
}

// ClearAccountMCPJournal clears field of the account journal rows of the MCP
// server name in the connector scope, as an operator allow of that name
// clears the bare row.
func ClearAccountMCPJournal(store *audit.Store, name, connector, field string) error {
	if store == nil || strings.TrimSpace(name) == "" {
		return nil
	}
	rows, err := store.ListActionsByTypeForConnector(AccountMCPJournalType, connector)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if IsAccountMCPJournalName(name, row.TargetName) {
			if err := store.ClearActionFieldForConnector(row.TargetType, row.TargetName, row.Connector, field); err != nil {
				return err
			}
		}
	}
	return nil
}
