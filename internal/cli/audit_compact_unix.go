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
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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
	if !ok {
		return false, nil
	}
	if stat.Uid == 0 {
		// Root compacts a root-owned store itself, but only in a folder
		// that only root can change: the WAL and the VACUUM copy are
		// created there by name.
		folder, err := os.Stat(filepath.Dir(db))
		if err != nil {
			return false, nil // CompactStore reports it.
		}
		if folderStat, ok := folder.Sys().(*syscall.Stat_t); !ok || !auditCompactRootOnlyFolder(folderStat.Uid, folder.Mode()) {
			return true, fmt.Errorf("audit compact: %s belongs to root, but its folder %s can be changed by another account; "+
				"give the store to the account that owns the folder (on a managed computer, run the enterprise repair) "+
				"and run compact again. Nothing was changed", db, filepath.Dir(db))
		}
		return false, nil
	}
	if !auditCompactManaged() {
		return true, fmt.Errorf("audit compact: %s belongs to another account; run it as that account, without sudo. Nothing was changed", db)
	}
	_, descriptor, err := managedStandaloneAdminDeployment()
	if err != nil || descriptor.ServiceUID <= 0 || uint32(descriptor.ServiceUID) != stat.Uid || descriptor.ServiceGID <= 0 {
		return true, fmt.Errorf("audit compact: %s does not belong to the gateway service account the managed deployment names. Nothing was changed", db)
	}
	return true, auditCompactRunAs(cmd, db, uint32(descriptor.ServiceUID), uint32(descriptor.ServiceGID))
}

// auditCompactChildEnv is the whole environment of the service-account
// child: the managed deployment pins applyManagedStandaloneAdminEnv set, the
// locale, a system PATH and HOME set to the managed data directory. Nothing
// else of root's (sudo) environment reaches it.
func auditCompactChildEnv(getenv func(string) string) []string {
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if home := getenv("DEFENSECLAW_HOME"); home != "" {
		// The service's own folder, never root's home.
		env = append(env, "HOME="+home)
	}
	for _, key := range []string{
		managed.ConfigPathEnv, "DEFENSECLAW_HOME", managed.DeploymentModeEnv,
		managed.EnterpriseProfileEnv, managed.HookGuardianAuthorizationDirEnv, "LANG",
	} {
		if value := getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

// auditCompactServiceLive: the unix managed gateway records its PID in the
// data directory (auditCompactGatewayRunning), and the store's claim refuses
// a gateway that holds it.
var auditCompactServiceLive = func() (bool, error) { return false, nil }

// auditCompactCallerUID is the effective uid; tests replace it.
var auditCompactCallerUID = os.Geteuid

// auditCompactRunAs runs this command again as uid:gid; tests replace it.
var auditCompactRunAs = func(cmd *cobra.Command, db string, uid, gid uint32) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("audit compact: find this program: %w", err)
	}
	// Not CommandContext: a cancelled context would SIGKILL the child.
	// Ctrl-C and SIGTERM go to the child (in its own session) instead, and
	// this process waits for it, so the prompt returns only once the child
	// has let go of the store.
	child := exec.Command(self, os.Args[1:]...)
	child.Dir = filepath.Dir(db)
	child.Env = auditCompactChildEnv(os.Getenv)
	// No stdin, and a session of its own: the child cannot read the root
	// terminal or take signals meant for the caller's job.
	child.Stdin, child.Stdout, child.Stderr = nil, cmd.OutOrStdout(), cmd.ErrOrStderr()
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := child.Start(); err != nil {
		return fmt.Errorf("audit compact: run as the gateway service account: %w", err)
	}
	err = waitForwardingSignals(child, signals)
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

// waitForwardingSignals waits for a started child and passes it every signal
// that arrives on signals meanwhile.
func waitForwardingSignals(child *exec.Cmd, signals <-chan os.Signal) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case received := <-signals:
				_ = child.Process.Signal(received)
			case <-done:
				return
			}
		}
	}()
	return child.Wait()
}

// auditCompactRootOnlyFolder reports a folder that only root can change:
// owned by root, and no group or other write.
func auditCompactRootOnlyFolder(uid uint32, mode os.FileMode) bool {
	return uid == 0 && mode.Perm()&0o022 == 0
}
