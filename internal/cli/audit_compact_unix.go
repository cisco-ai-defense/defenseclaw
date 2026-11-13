// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
)

// auditCompactAsStoreOwner keeps root from writing SQLite files in a folder
// another account owns. SQLite opens audit.db-wal and the VACUUM copy by name
// there, so the account that owns the folder could point them elsewhere.
//
// On a standalone managed computer root runs the same command again as the
// gateway service account that owns the store (the descriptor names it),
// with no supplementary groups, and returns its exit code; the store's own
// owner checks then apply as they do for the gateway. On a per-user install
// root is refused for a store it does not own. handled is false when the
// caller runs the compaction itself.
func auditCompactAsStoreOwner(cmd *cobra.Command, db string) (bool, error) {
	if auditCompactCallerUID() != 0 {
		return false, nil
	}
	info, err := os.Stat(db)
	if err != nil {
		return false, nil // CompactStore reports it.
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return false, nil
	}
	if !auditCompactManaged() {
		return true, fmt.Errorf("audit compact: %s belongs to another account; run it as that account, without sudo. Nothing was changed", db)
	}
	_, descriptor, err := managedStandaloneAdminDeployment()
	if err != nil || descriptor.ServiceUID <= 0 || uint32(descriptor.ServiceUID) != stat.Uid || descriptor.ServiceGID < 0 {
		return true, fmt.Errorf("audit compact: %s does not belong to the gateway service account the managed deployment names. Nothing was changed", db)
	}
	return true, auditCompactRunAs(cmd, db, uint32(descriptor.ServiceUID), uint32(descriptor.ServiceGID))
}

// auditCompactCallerUID is the effective uid; tests replace it.
var auditCompactCallerUID = os.Geteuid

// auditCompactRunAs runs this command again as uid:gid; tests replace it.
var auditCompactRunAs = func(cmd *cobra.Command, db string, uid, gid uint32) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("audit compact: find this program: %w", err)
	}
	child := exec.CommandContext(cmd.Context(), self, os.Args[1:]...)
	child.Dir = filepath.Dir(db)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr()
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	err = child.Run()
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		// The child printed its own answer.
		cmd.SilenceErrors = true
		return withExitCode(err, exited.ExitCode())
	}
	if err != nil {
		return fmt.Errorf("audit compact: run as the gateway service account: %w", err)
	}
	return nil
}
