// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TamperedDropIns lists the machine-policy drop-ins DefenseClaw owns whole
// and published (an ownership record names them) whose bytes are no longer
// the ones it wrote, or that are gone: the Claude Code managed-settings
// drop-in and the GitHub Copilot CLI policy.d drop-in. The standalone Unix
// hook guardian checks them between lifecycle runs, because an edited or
// deleted drop-in left the hooks off for every user until an administrator
// ran repair (GAP-1178, GAP-1348). DefenseClaw's part of the shared Codex
// requirements file is checked by TamperedCodexRequirements; other shared
// vendor files, which administrators edit too, are left to verify.
func TamperedDropIns(opts Options) []string {
	var tampered []string
	for _, owned := range []struct {
		connector string
		path      func(Options) (string, error)
	}{{claudeConnector, claudeDropInPath}, {copilotConnector, copilotDropInPath}} {
		expected, err := owned.path(opts)
		if err != nil {
			continue
		}
		record, err := loadRecord(opts, owned.connector)
		if err != nil || record == nil || record.Path != expected || record.PostimageSHA256 == "" {
			continue
		}
		current, exists, err := readPolicyFile(opts, record.Path)
		if err != nil || !exists || sha256Hex(current) != record.PostimageSHA256 {
			tampered = append(tampered, record.Path)
		}
	}
	return tampered
}

// TamperedCodexRequirements reports the Codex requirements.toml DefenseClaw
// published (ownership merge) when DefenseClaw's own content in it is no
// longer what DefenseClaw writes: the file is gone or does not parse, a
// managed block or marked line was changed, removed or moved, a line was
// added before DefenseClaw's managed settings block or after its managed
// hooks block (TOML puts a key there in DefenseClaw's last table), or an
// administrator value now disables the managed hooks, the file as a whole no
// longer parses or carries the managed hooks (an administrator table that
// collides with DefenseClaw's hook arrays, GAP-1966), or its byte order mark
// was added or removed. opts must carry the deployed config, which renders
// the managed content. The standalone Unix hook guardian checks it between
// lifecycle runs and starts the restore, as for the drop-ins, because such
// an edit left the file unhealed until an administrator ran a lifecycle
// action (GAP-1928). An edit of the administrator's own text alone (a
// comment or setting between DefenseClaw's blocks) is not listed: verify
// reports it, ensure and repair put back the published file, and reconcile
// accepts it.
func TamperedCodexRequirements(opts Options) (string, bool) {
	if !CodexRequirementsDrifted(opts) {
		return "", false
	}
	policy := opts.PolicyFor(codexConnector)
	if policy.Ownership != config.MachinePolicyOwnershipMerge {
		return "", false
	}
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return "", false
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil || !exists {
		return path, true
	}
	rendered, conflicts, err := renderCodex(opts, stripCodexOwned(current), policy)
	if err != nil || rendered == nil || len(conflicts) != 0 || !bytes.Equal(rendered, current) {
		return path, true
	}
	// The same probe reconcile runs on the document it would write: a file
	// that re-renders to itself can still not parse as a whole (a
	// [hooks.<Event>] table between the blocks redefines DefenseClaw's hook
	// array) or lack a managed hook, and Codex then runs without them.
	var probe State
	if inspectCodex(opts, current, policy, &probe) != nil || len(codexMissingHookConflicts(probe)) > 0 {
		return path, true
	}
	// A byte order mark is the administrator's text's, and the render keeps
	// it as it finds it, so adding or removing one alone re-renders to the
	// file; it is still not what DefenseClaw published, and verify fails.
	if record, err := loadRecord(opts, codexConnector); err == nil && record != nil &&
		bytes.HasPrefix(current, utf8BOM) != bytes.HasPrefix(record.Preimage, utf8BOM) {
		return path, true
	}
	return "", false
}

// CodexRequirementsDrifted reports whether DefenseClaw published the Codex
// requirements file and its bytes are no longer the ones it wrote, or it is
// gone. It reads only the ownership record and the file, so the guardian
// renders the managed content (TamperedCodexRequirements) only after it.
func CodexRequirementsDrifted(opts Options) bool {
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return false
	}
	record, err := loadRecord(opts, codexConnector)
	if err != nil || !publishedByRecord(record, path) {
		return false
	}
	current, exists, err := readPolicyFile(opts, path)
	return err != nil || !exists || sha256Hex(current) != record.PostimageSHA256
}

// ClaudeDropInRestoredAt is when DefenseClaw last put back its Claude Code
// drop-in after another writer changed or removed it, or the zero time.
// Claude Code keeps the hooks a session loaded, so a session open through
// that change can still run the broken hook command after the drop-in is
// back (GAP-1077).
func ClaudeDropInRestoredAt(opts Options) time.Time {
	record, err := loadRecord(opts, claudeConnector)
	if err != nil || record == nil || record.RestoredAt == "" {
		return time.Time{}
	}
	restored, err := time.Parse(time.RFC3339, record.RestoredAt)
	if err != nil {
		return time.Time{}
	}
	return restored
}
