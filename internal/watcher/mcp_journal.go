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

// MCPJournalName is the name under which the actions journal keeps the
// install block and runtime disable of an MCP server. A server a managed
// gateway read from an enrolled user's home is journaled under its event
// path (name, connector, account home and project), so the verdict of one
// account's server never refuses, and the rescan of one never releases,
// another account's server of the same name (GAP-0216). Every other server
// keeps its name, as before.
func MCPJournalName(server config.MCPServerEntry) string {
	if server.Home != "" {
		return MCPEventPath(server)
	}
	return server.Name
}

// journalName is the journal name of the target of evt: MCPJournalName for
// an enrolled account's MCP server, the event name for everything else.
func journalName(evt InstallEvent) string {
	if evt.Type == InstallMCP && IsAccountMCPJournalName(evt.Name, evt.Path) {
		return evt.Path
	}
	return evt.Name
}

// IsAccountMCPJournalName reports whether key is the event path of the MCP
// server name of an enrolled account. Versioned keys carry a full tuple;
// older journal rows keep their original spelling.
func IsAccountMCPJournalName(name, key string) bool {
	if strings.TrimSpace(name) == "" {
		return false
	}
	if identity, ok := decodeMCPEventPath(key); ok {
		return identity.Name == name && identity.Connector != "" && identity.Home != ""
	}
	rest, ok := strings.CutPrefix(key, name+"@")
	if !ok {
		return false
	}
	connector, home, ok := strings.Cut(rest, ":")
	return ok && connector != "" && !strings.ContainsAny(connector, "@#") && home != ""
}

// MCPAccountJournalServes reports whether the account journal row key (an
// MCPJournalName of an enrolled account's server) is the server a tool call
// reaches: the call's connector, a server name the call spells, the caller's
// home and, for a project server, a project the agent works in. A caller
// whose home is not known matches every account, and a call without a
// working folder matches every project of the account: both refuse rather
// than miss a block (fail closed).
func MCPAccountJournalServes(key string, q MCPAdmissionQuery) bool {
	if identity, ok := decodeMCPEventPath(key); ok {
		return identity.Connector != "" && identity.Home != "" && mcpServerServesQuery(identity.server(), q)
	}
	connector := strings.ToLower(strings.TrimSpace(q.Connector))
	if connector == "" {
		return false
	}
	marker := "@" + connector + ":"
	i := strings.Index(key, marker)
	if i <= 0 {
		return false
	}
	name, rest := key[:i], key[i+len(marker):]
	if !config.SameMCPToolServer(connector, name, q.Server) {
		return false
	}
	home, project := rest, ""
	if j := strings.Index(rest, "@"+connector+"#"); j >= 0 {
		home, project = rest[:j], rest[j+len("@"+connector+"#"):]
	}
	if home == "" {
		return false
	}
	if q.Home != "" && !sameMCPFolder(home, q.Home) {
		return false
	}
	if project != "" && q.CWD != "" && !mcpFolderWithin(q.CWD, project) {
		return false
	}
	return true
}

// migrateLegacyMCPJournal moves an account action before a versioned
// admission writes its verdict. The old snapshot must identify the same
// scope; otherwise the action stays on its old key. A current action is
// also left intact rather than merging two independent decisions.
func (w *InstallWatcher) migrateLegacyMCPJournal(evt InstallEvent) error {
	if w == nil || w.store == nil || evt.Type != InstallMCP || w.secureClientActive() {
		return nil
	}
	identity, ok := decodeMCPEventPath(evt.Path)
	if !ok || identity.Name != evt.Name || identity.Connector == "" || identity.Home == "" ||
		!strings.EqualFold(identity.Connector, evt.Connector) {
		return nil
	}
	server := identity.server()
	oldPath := legacyMCPEventPath(server)
	oldSnapshot, err := w.store.GetTargetSnapshot(string(InstallMCP), oldPath)
	if err != nil || !mcpLegacySnapshotMatchesServer(oldPath, oldSnapshot, server) {
		return nil
	}
	scope := w.journalScope(w.eventConnector(evt))
	old, err := w.store.GetActionForConnector(string(InstallMCP), oldPath, scope)
	if err != nil {
		return err
	}
	if old == nil || old.SourcePath != oldPath || old.Actions.IsEmpty() {
		return nil
	}
	current, err := w.store.GetActionForConnector(string(InstallMCP), evt.Path, scope)
	if err != nil {
		return err
	}
	if current != nil {
		if current.SourcePath == evt.Path && current.Actions == old.Actions && current.Reason == old.Reason {
			return w.store.RemoveActionForConnector(string(InstallMCP), oldPath, scope)
		}
		return nil
	}
	if err := w.store.SetActionForConnector(string(InstallMCP), evt.Path, scope, evt.Path, old.Actions, old.Reason); err != nil {
		return err
	}
	return w.store.RemoveActionForConnector(string(InstallMCP), oldPath, scope)
}

// MigrateAccountMCPJournal moves the MCP journal rows that earlier versions
// kept under the bare server name for an enrolled account's server to that
// server's account key (MCPJournalName), on a gateway that admits the
// servers of several accounts. The row's source path is the server's event
// path, so it names the account the verdict was for. The account row is
// written before the bare row is removed, so the block holds at every
// moment; fields an account row already has are kept, and missing ones are
// added from the bare row. A bare row without an account source path (an
// operator row, or one whose server cannot be told) stays as it is and
// keeps refusing every account's server of that name (fail closed).
func MigrateAccountMCPJournal(store *audit.Store) (moved, kept int, err error) {
	if store == nil {
		return 0, 0, nil
	}
	rows, err := store.ListActionsByType(string(InstallMCP))
	if err != nil {
		return 0, 0, err
	}
	for _, row := range rows {
		if row.Connector == "" || row.TargetName == row.SourcePath {
			continue // a global row, or an account row already
		}
		if !IsAccountMCPJournalName(row.TargetName, row.SourcePath) {
			if row.Actions.Runtime == "disable" || row.Actions.Install == "block" {
				kept++
			}
			continue
		}
		key := row.SourcePath
		current, err := store.GetActionForConnector(row.TargetType, key, row.Connector)
		if err != nil {
			return moved, kept, err
		}
		if current == nil {
			if err := store.SetActionForConnector(row.TargetType, key, row.Connector, row.SourcePath, row.Actions, row.Reason); err != nil {
				return moved, kept, fmt.Errorf("move mcp journal row %s: %w", row.TargetName, err)
			}
		} else {
			for field, value := range map[string]string{"install": row.Actions.Install, "runtime": row.Actions.Runtime, "file": row.Actions.File} {
				if value == "" || accountFieldSet(current.Actions, field) {
					continue
				}
				if err := store.SetActionFieldForConnector(row.TargetType, key, row.Connector, field, value, row.Reason); err != nil {
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
	rows, err := store.ListActionsByTypeForConnector(string(InstallMCP), connector)
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
