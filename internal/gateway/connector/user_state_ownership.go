// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

// ManagedUserStateDir reports directories that a managed installation may
// create below its per-user data folder. A directory is only traversed; its
// contents are checked separately and it is removed only when empty.
func ManagedUserStateDir(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	switch rel {
	case "hooks", "logs", "shims", "policies", "native-codeguard", "foreign-hook-sessions", "connector_backups", "foreign-hooks-backup":
		return true
	}
	if kind, ok := strings.CutPrefix(rel, "connector_backups/"); ok && !strings.Contains(kind, "/") {
		return IsKnownBuiltinConnector(kind) || IsRemovedConnector(kind)
	}
	return false
}

// ManagedUserStateFile reports files with names owned by the managed runtime.
// Unknown files, even below a managed directory, are account data. The names
// come from the same hook assets and connector registry used by setup.
func ManagedUserStateFile(rel string) bool {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == "." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return false
	}
	parts := strings.Split(rel, "/")
	if len(parts) == 1 {
		switch rel {
		case "session-facts.json", "hook_contract_lock.json", "hook_contract_lock.json.lock",
			"watcher-created-dirs.json", "agent_selection.json", "agent_selection.json.lock",
			"agent_discovery.json", "ai_discovery_state.json", "managed_peer_homes.json",
			"gateway-api.json", "hook_guardian_state.json",
			"inventory.db", "inventory.db-journal", "inventory.db-shm", "inventory.db-wal",
			"foreign-hook-env.json", "hermes-home-setup.json", ".hermes-lifecycle.lock",
			"removed-connectors-logged.json", "kiro-created-dirs.json", ".hook-api-token-publish.lock",
			"gateway.pid", "gateway.stopped", "notify-bridge.sh":
			return true
		}
		if kind, ok := strings.CutPrefix(rel, ".hook-"); ok {
			if kind, ok = strings.CutSuffix(kind, ".token"); ok && (IsKnownBuiltinConnector(kind) || IsRemovedConnector(kind)) {
				return true
			}
		}
		if kind, ok := strings.CutPrefix(rel, ".hookcfg-"); ok {
			if kind, ok = strings.CutSuffix(kind, ".json"); ok && (IsKnownBuiltinConnector(kind) || IsRemovedConnector(kind)) {
				return true
			}
		}
		return false
	}
	if len(parts) != 2 {
		return false
	}
	name := parts[1]
	switch parts[0] {
	case "hooks":
		if slices.Contains([]string{".hookcfg", ".hookcfg.lock", ".hookcfg.legacy", ".token", ".hook-api-token-publish.lock", ".gateway-helper", ".config-record", "hermes-direct-native-state.json"}, name) {
			return true
		}
		for _, scope := range OTLPPathTokenScopes() {
			if name == otlpPathTokenFileName(scope) {
				return true
			}
		}
		if kind, ok := strings.CutPrefix(name, ".hookcfg."); ok && (IsKnownBuiltinConnector(kind) || IsRemovedConnector(kind)) {
			return true
		}
		if kind, ok := strings.CutPrefix(name, ".hook-"); ok {
			if kind, ok = strings.CutSuffix(kind, ".token"); ok && (IsKnownBuiltinConnector(kind) || IsRemovedConnector(kind)) {
				return true
			}
		}
		_, err := fs.Stat(hookFS, "hooks/"+name)
		return err == nil
	case "logs":
		return name == "hook-failures.jsonl" || name == "hook.log" || name == "hooks.log"
	case "shims":
		return name == ".token" || name == "ncat" || slices.Contains(shimBinaries, name)
	case "policies":
		return name == "defenseclaw-policy.yaml"
	case "native-codeguard":
		return name == nativeCodeGuardCodexReceiptName
	case "foreign-hook-sessions":
		return managedSessionRecordName(name)
	}
	return false
}

// The session store uses a kind and a 40-character lowercase SHA-256 prefix.
func managedSessionRecordName(name string) bool {
	if len(name) != 47 || (name[:2] != "p-" && name[:2] != "s-") || name[42:] != ".json" {
		return false
	}
	for _, ch := range name[2:42] {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
