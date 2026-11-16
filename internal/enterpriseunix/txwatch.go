// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A lifecycle run that is killed (SIGKILL, an OOM kill, a crash) after it
// wrote its transaction intent left the services it quiesced stopped: the
// hook guardian, the enumerator and the apply trigger, and in a full change
// the gateway. Nothing started them again until an administrator ran verify,
// repair or the change again, so hook tamper repair lapsed while the
// transaction stayed pending (rel-1-0-3 GAP-0276). Before it stops anything,
// a run of an installed deployment now starts a watcher outside its own
// process: a transient systemd unit on Linux (outside the run's cgroup), a
// detached session on macOS. When the run is gone and its intent is still
// there, the watcher starts the apply trigger, which recovers the
// transaction (rolls it back and starts the stopped services again), the
// route verify takes (GAP-0428). A run that finishes clears its intent, and
// the watcher then exits.

// TransactionWatchAction is the hidden `enterprise linux|macos` action that
// runs the watcher.
const TransactionWatchAction = "watch-transaction"

const unitTransactionWatchPrefix = "defenseclaw-enterprise-txwatch-"

var (
	transactionWatchPoll = time.Second
	transactionWatchMax  = 24 * time.Hour
)

// armTransactionWatch starts the watcher of the transaction pending names.
// A watcher that cannot start leaves the earlier behavior: verify, repair
// or the next change recovers the transaction.
func (l *lifecycle) armTransactionWatch(ctx context.Context, pending *Pending) {
	env := l.env
	if env.StartTransactionWatch == nil || env.Geteuid() != 0 || pending == nil || pending.SnapshotDir == "" {
		return
	}
	_ = env.StartTransactionWatch(ctx, os.Getpid(), pending.SnapshotDir)
}

// startTransactionWatch is the production StartTransactionWatch: this
// executable, run as `enterprise <os> watch-transaction`.
func (e *Env) startTransactionWatch(ctx context.Context, pid int, snapshotDir string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	group := "linux"
	if e.GOOS == "darwin" {
		group = "macos"
	}
	args := []string{"enterprise", group, TransactionWatchAction, "--pid", strconv.Itoa(pid), "--snapshot", snapshotDir}
	if e.GOOS == "linux" {
		// Its own unit: a stop of the unit the run executes in (the apply
		// trigger) ends the run's whole cgroup.
		_, err := e.Runner.Run(ctx, "systemd-run", append([]string{"--quiet", "--collect",
			"--unit=" + unitTransactionWatchPrefix + strconv.Itoa(pid), "--description=DefenseClaw lifecycle transaction watcher",
			executable}, args...)...)
		return err
	}
	command := exec.Command(executable, args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
}

// WatchTransaction waits while the lifecycle run pid has the transaction
// whose snapshot is snapshotDir pending. It returns when the intent is gone
// or names another transaction (the run finished, or another run recovered
// it), and when the run is gone with the intent still in place, after it
// started the apply trigger.
func WatchTransaction(ctx context.Context, env *Env, pid int, snapshotDir string) error {
	if pid <= 0 || strings.TrimSpace(snapshotDir) == "" {
		return errors.New("watch-transaction needs --pid and --snapshot")
	}
	if env.Geteuid() != 0 {
		return errors.New("watch-transaction runs as root")
	}
	deadline := env.Now().Add(transactionWatchMax)
	for {
		pending, err := env.loadPending()
		if err != nil || pending == nil || pending.SnapshotDir != snapshotDir {
			return nil
		}
		if !processRunning(pid) {
			return env.startApplyTrigger(ctx)
		}
		if env.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(transactionWatchPoll):
		}
	}
}

// processRunning reports whether pid is a live process; a zombie (killed,
// not yet reaped) is not.
func processRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	if stat, readErr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); readErr == nil {
		if end := strings.LastIndexByte(string(stat), ')'); end >= 0 && end+2 < len(stat) && stat[end+2] == 'Z' {
			return false
		}
	}
	return true
}

// startApplyTrigger starts the config-apply trigger, which runs ensure; an
// ensure recovers a pending transaction first.
func (e *Env) startApplyTrigger(ctx context.Context) error {
	var err error
	if e.GOOS == "darwin" {
		_, err = e.Runner.Run(ctx, "launchctl", "kickstart", "system/"+labelApply)
	} else {
		_, err = e.Runner.Run(ctx, "systemctl", "start", "--no-block", unitApplyService)
	}
	return err
}
