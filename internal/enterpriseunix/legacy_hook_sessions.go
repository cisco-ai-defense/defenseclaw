// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"fmt"
	"os"
)

// The 1.0.2 Linux gateway stored foreign-hook session records in the hook
// socket runtime directory. The current gateway stores them in its private
// data directory and cannot consume the old records. Retire the old tree only
// after the new deployment is committed, so a rolled-back upgrade leaves the
// previous gateway's live session state intact.
func (l *lifecycle) invalidateLegacyHookSessions(ctx context.Context) {
	if l.env.GOOS != "linux" {
		return
	}
	root := l.env.P("/run/defenseclaw-hook/sessions")
	if _, err := os.Lstat(root); os.IsNotExist(err) {
		return
	} else if err != nil {
		l.result.AddWarning("legacy_hook_sessions_cleanup_failed", fmt.Sprintf("inspect old foreign-hook session records: %v", err))
		return
	}
	account, ok, err := l.env.Accounts.Lookup(ctx, l.env.Layout.ServiceUser)
	if err != nil || !ok {
		l.result.AddWarning("legacy_hook_sessions_cleanup_failed", "could not resolve the gateway service account to retire old foreign-hook session records")
		return
	}
	if err := os.RemoveAll(root); err != nil {
		l.result.AddWarning("legacy_hook_sessions_cleanup_failed", fmt.Sprintf("remove old foreign-hook session records: %v", err))
		return
	}
	if err := l.env.ensureDir(root, 0o711, fileOwner{UID: account.UID, GID: account.GID}); err != nil {
		l.result.AddWarning("legacy_hook_sessions_cleanup_failed", fmt.Sprintf("restore the retired session root at mode 0711: %v", err))
		return
	}
	l.result.AddWarning("legacy_hook_sessions_invalidated", "old foreign-hook session records were invalidated during the upgrade; the retired session root is 0711")
}
