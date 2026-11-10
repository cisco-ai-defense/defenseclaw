// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
)

// enterpriseConnectorEnrolledBefore reports whether the guardian enrolled the
// account's connector before: the per-connector hook configuration it writes
// in the account's own DefenseClaw folder, in the account's session, at
// enrollment (<data dir>\hooks\.hookcfg.<connector>). It is the one marker the
// hook refusal, the administrator's status and verify, and the account's own
// status share to tell an enrolled account that is pending now (disconnected or
// signed out, its runtime revoked) from one that was never enrolled
// (GAP-1026, GAP-1034). The account can write it, but only the wording of its
// own refusal and status follows; nothing is decided by it.
func enterpriseConnectorEnrolledBefore(dataDir, connector string) bool {
	dataDir, connector = strings.TrimSpace(dataDir), strings.ToLower(strings.TrimSpace(connector))
	if dataDir == "" || connector == "" {
		return false
	}
	info, err := os.Lstat(filepath.Join(dataDir, "hooks", ".hookcfg."+connector))
	return err == nil && info.Mode().IsRegular()
}

// enterpriseHomeConnectorEnrolledBefore is enterpriseConnectorEnrolledBefore
// for an account's profile folder.
func enterpriseHomeConnectorEnrolledBefore(userHome, connector string) bool {
	userHome = strings.TrimSpace(userHome)
	if userHome == "" {
		return false
	}
	return enterpriseConnectorEnrolledBefore(filepath.Join(userHome, ".defenseclaw"), connector)
}
