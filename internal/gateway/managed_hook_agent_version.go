// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// callerAgentLedgers are the guardian authorization readers of
// callerAgentContract, by path. Each caches like the hook socket's reader:
// for two seconds and while the file's stat is unchanged.
var callerAgentLedgers sync.Map // string -> *managedHookLedgerLoader

// loadCallerAgentLedger reads the guardian authorization at path. A seam
// for tests.
var loadCallerAgentLedger = func(path string) (managedHookLedger, error) {
	loader, ok := callerAgentLedgers.Load(path)
	if !ok {
		loader, _ = callerAgentLedgers.LoadOrStore(path, newManagedHookLedgerLoader(path))
	}
	return loader.(*managedHookLedgerLoader).Load()
}

// callerAgentContract is the agent version and hook contract the guardian
// recorded when it protected the verified caller's target of connector name.
// The caller is the kernel-verified hook-socket peer (uid) or the account a
// per-user credential is bound to (uid, or SID on Windows). ok is false for
// any other request, when the record cannot be read, when no protected
// target of the caller records a version, and when its targets record
// different ones: the profile then resolves as before (the connector's
// default contract, "unversioned").
func (a *APIServer) callerAgentContract(ctx context.Context, name string) (string, string, bool) {
	identity := ""
	if peer, found := managedHookPeerFromContext(ctx); found {
		identity = strconv.Itoa(peer.UID)
	} else if bound, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); bound != "" {
		identity = bound
	}
	dataDir := a.configDataDir()
	if identity == "" || dataDir == "" {
		return "", "", false
	}
	if ledger, err := loadCallerAgentLedger(managed.HookGuardianAuthorizationPath(dataDir)); err == nil {
		if version, contractID, ok := ledger.agentContract(identity, name); ok {
			return version, contractID, true
		}
	}
	// A Linux or macOS machine-policy connector has no guardian row: the
	// enumerator publishes the caller's verified version beside the ledger
	// (managed.HookGuardianAgentVersionsFile). The machine policy is one
	// render for every account, made without a version, so the contract
	// stays the one that render speaks (the connector's unversioned
	// contract); the version decides the compatibility status the audit and
	// status report against it (rel-1-0-10:GAP-0114).
	versions, err := loadCallerAgentLedger(filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), managed.HookGuardianAgentVersionsFile))
	if err != nil {
		return "", "", false
	}
	version, _, ok := versions.agentContract(identity, name)
	if !ok {
		return "", "", false
	}
	rendered := a.hookProfileForConnector(name).ContractID
	if rendered == "" {
		return "", "", false
	}
	return version, rendered, true
}

// agentContract is the agent version and hook contract the protected
// targets of identity for connector name record, when they record one and
// agree on it.
func (l managedHookLedger) agentContract(identity, name string) (string, string, bool) {
	identity, ok := connector.CanonicalUserScopedIdentity(identity)
	if !ok {
		return "", "", false
	}
	version, contractID, found := "", "", false
	for _, target := range l.Targets {
		if !target.OK || target.Result == nil || !strings.EqualFold(strings.TrimSpace(target.Connector), name) ||
			!ledgerTargetIdentityIs(target, identity) {
			continue
		}
		recordedVersion := strings.TrimSpace(target.Result.AgentVersion)
		recordedContract := strings.TrimSpace(target.Result.HookContractID)
		if recordedVersion == "" {
			continue
		}
		if found && (recordedVersion != version || recordedContract != contractID) {
			return "", "", false
		}
		version, contractID, found = recordedVersion, recordedContract, true
	}
	return version, contractID, found
}

// ledgerTargetIdentityIs reports whether target is the account canonical
// names, by the SID or uid the guardian recorded. A row with neither (the
// Unix guardian omits uid 0) is never matched by name here.
func ledgerTargetIdentityIs(target managedHookLedgerTarget, canonical string) bool {
	recorded := strings.TrimSpace(target.SID)
	if recorded == "" && target.UID != nil {
		recorded = strconv.Itoa(*target.UID)
	}
	if recorded == "" {
		return false
	}
	recorded, ok := connector.CanonicalUserScopedIdentity(recorded)
	return ok && recorded == canonical
}
