//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-2380: the per-user cleanup takes the inventory grant off the dotdirs on
// the revoked connector's hook path before the removal, and a failed removal
// names a failed revoke too.
func TestAttemptWindowsStandaloneUserCleanupRevokesTheHookPathDotdirGrantFirst(t *testing.T) {
	home := t.TempDir()
	entry := enterpriseHookUserCleanup{Connector: "OpenCode", SID: userCleanupSIDA, UserHome: home, DataDir: filepath.Join(home, ".defenseclaw")}
	var order []string
	revokeErr := error(nil)
	originalRevoke := enterpriseHookWindowsRevokeHookPathDotdirGrant
	t.Cleanup(func() { enterpriseHookWindowsRevokeHookPathDotdirGrant = originalRevoke })
	enterpriseHookWindowsRevokeHookPathDotdirGrant = func(gotHome, connectorName string) error {
		if gotHome != filepath.Clean(home) || connectorName != "OpenCode" {
			t.Fatalf("revoke for %s %s", gotHome, connectorName)
		}
		order = append(order, "revoke")
		return revokeErr
	}
	removeErr := error(nil)
	stubWindowsUserCleanupSeams(t,
		func(string, string) error { return nil },
		func(_ context.Context, opts enterprisehooks.InstallOptions) error {
			order = append(order, "remove "+opts.ConnectorName)
			return removeErr
		},
	)
	if outcome, err := attemptWindowsStandaloneUserCleanup(context.Background(), entry); outcome != enterpriseHookUserCleanupDone || err != nil ||
		strings.Join(order, ",") != "revoke,remove opencode" {
		t.Fatalf("outcome=%d err=%v order=%v", outcome, err, order)
	}
	revokeErr, removeErr = errors.New("set DACL: access denied"), errors.New("removal file trust check failed")
	_, err := attemptWindowsStandaloneUserCleanup(context.Background(), entry)
	if err == nil || !strings.Contains(err.Error(), "removal file trust check failed") || !strings.Contains(err.Error(), "set DACL: access denied") {
		t.Fatalf("failed removal error = %v", err)
	}
}
