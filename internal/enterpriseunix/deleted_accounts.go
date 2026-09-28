// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Warning codes of repair's deleted-account check.
const (
	codeDeletedAccountsRevoked = "deleted_account_targets_removed"
	codeDeletedAccountsKept    = "deleted_account_targets_kept"
	codeDeletedAccountsCheck   = "deleted_account_check_failed"
)

// deletedAccountsCheckTimeout bounds the check: it runs while the gateway
// is stopped, and each lookup can wait for an unreachable directory.
const deletedAccountsCheckTimeout = 30 * time.Second

// revokeDeletedAccounts removes the guardian targets of accounts that no
// longer exist. The enumerator removes them after 3 definitive misses on
// its five-minute cycle, and until then the guardian reports each as a
// failed target, so verify and reconcile fail for the whole host; an
// administrator's repair removes them at once. It runs between quiesce and
// activation, so neither the enumerator nor the guardian reads or rewrites
// the manifest meanwhile, and it is bounded by deletedAccountsCheckTimeout.
// An account a directory outage could explain keeps its targets. A failed
// check is a warning: the enumerator still removes the targets later.
func (l *lifecycle) revokeDeletedAccounts(ctx context.Context) {
	env, r := l.env, l.result
	ctx, cancel := context.WithTimeout(ctx, deletedAccountsCheckTimeout)
	defer cancel()
	result, err := env.runGatewayCLI(ctx, "enterprise", "hooks", "revoke-gone", "--manifest", env.Layout.ManifestPath, "--json")
	if err != nil {
		r.AddWarning(codeDeletedAccountsCheck, "could not check the guardian targets for deleted accounts; the enumerator removes them after 3 cycles: "+err.Error())
		return
	}
	// The JSON report is the last line that holds an object.
	line := []byte{}
	for _, candidate := range bytes.Split(result.Stdout, []byte("\n")) {
		if candidate = bytes.TrimSpace(candidate); bytes.HasPrefix(candidate, []byte("{")) {
			line = candidate
		}
	}
	if len(line) == 0 {
		return
	}
	var report struct {
		Revoked []string `json:"revoked"`
		Kept    []string `json:"kept"`
	}
	if err := json.Unmarshal(line, &report); err != nil {
		r.AddWarning(codeDeletedAccountsCheck, "could not read the deleted-account check's result: "+err.Error())
		return
	}
	if len(report.Revoked) > 0 {
		r.AddWarning(codeDeletedAccountsRevoked, "removed the guardian targets of accounts that no longer exist: "+strings.Join(report.Revoked, ", "))
	}
	for _, kept := range report.Kept {
		r.AddWarning(codeDeletedAccountsKept, kept)
	}
}
