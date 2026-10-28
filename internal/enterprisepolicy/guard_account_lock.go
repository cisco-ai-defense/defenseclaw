// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The per-account removal lock (1.0.4 guard consolidation).
//
// A hook removal of one account and the gateway's online answers for that
// account exclude each other through one writer-preferred readers-writer
// lock across processes. It is two lock files next to the account's private
// session store, in the gateway's data directory, which only root, SYSTEM
// and the gateway service can reach:
//
//	<data dir>/foreign-hook-sessions/<store digest>.gate
//	<data dir>/foreign-hook-sessions/<store digest>.lock
//
//   - An exchange (the gateway's online answer) takes the gate exclusively,
//     the lock shared, and lets go of the gate: it waits at most
//     ForeignHookExchangeWait, and gets ErrForeignHookRemovalPending (a
//     denial) when a removal holds either. It keeps the lock shared until
//     its answer is written, and answers allow only within
//     ForeignHookExchangeHold of taking it.
//   - A removal (the hook guardian) takes the gate exclusively and keeps it,
//     so no new exchange of the account gets in, then the lock exclusively.
//     It waits for exchanges inside at most ForeignHookRemovalDrainWait,
//     longer than any of them may answer, and then goes on even if one is
//     still inside: such an exchange read the record key before the removal
//     rotated it, so what it publishes proves nothing, and its answer is
//     already cut.
//
// Other accounts never wait on this account's removal. The guardian does
// only the removal commit under the lock (rotate the account's record key,
// record the removal, change the file, record it again); a scan never holds
// it.

const (
	// ForeignHookExchangeWait bounds how long an exchange waits for the
	// account's lock before it denies.
	ForeignHookExchangeWait = 750 * time.Millisecond
	// ForeignHookExchangeHold bounds an allow: an exchange answers allow
	// only within this time after it took the lock, and its answer is cut
	// after it.
	ForeignHookExchangeHold = time.Second
	// ForeignHookRemovalDrainWait is the longest a removal waits for the
	// exchanges inside the lock.
	ForeignHookRemovalDrainWait = ForeignHookExchangeHold + 500*time.Millisecond
	// ForeignHookRemovalGateWait bounds how long a removal waits for the
	// gate, which exchanges hold only for a moment and another removal of
	// the account for one commit.
	ForeignHookRemovalGateWait = 30 * time.Second
)

const (
	foreignHookLockExchangePoll = 5 * time.Millisecond
	foreignHookLockRemovalPoll  = time.Millisecond
	foreignHookLockGateSuffix   = ".gate"
	foreignHookLockMainSuffix   = ".lock"
)

// ForeignHookAccountLockPaths are the two lock files of identity's account
// under the gateway data directory dataDir.
func ForeignHookAccountLockPaths(dataDir, identity string) (gate, lock string, ok bool) {
	dataDir = strings.TrimSpace(dataDir)
	if _, valid := connector.CanonicalUserScopedIdentity(identity); !valid || dataDir == "" || !filepath.IsAbs(dataDir) {
		return "", "", false
	}
	store := ForeignHookSessionStoreDir(filepath.Clean(dataDir), identity)
	return store + foreignHookLockGateSuffix, store + foreignHookLockMainSuffix, true
}

// LockForeignHookAccountExchange holds identity's removal lock shared for one
// online exchange, waiting within ctx. A removal of the account that holds
// the gate or the lock past ctx is ErrForeignHookRemovalPending; a lock file
// that cannot be opened or locked is another error. Both deny the call.
func LockForeignHookAccountExchange(ctx context.Context, dataDir, identity string) (func(), error) {
	gatePath, mainPath, ok := ForeignHookAccountLockPaths(dataDir, identity)
	if !ok {
		return nil, errors.New("the account has no foreign-hook removal lock")
	}
	if err := createForeignHookSessionStoreParent(filepath.Clean(strings.TrimSpace(dataDir)), filepath.Dir(gatePath)); err != nil {
		return nil, fmt.Errorf("create the foreign-hook session store folder: %w", err)
	}
	gate, err := openForeignHookAccountLock(gatePath, dataDir)
	if err != nil {
		return nil, err
	}
	defer gate.close()
	if err := gate.lock(ctx, true, foreignHookLockExchangePoll); err != nil {
		return nil, foreignHookLockWaitError(err)
	}
	main, err := openForeignHookAccountLock(mainPath, dataDir)
	if err != nil {
		gate.unlock()
		return nil, err
	}
	err = main.lock(ctx, false, foreignHookLockExchangePoll)
	gate.unlock()
	if err != nil {
		main.close()
		return nil, foreignHookLockWaitError(err)
	}
	return sync.OnceFunc(main.release), nil
}

// LockForeignHookAccountRemoval holds identity's removal lock exclusively for
// one removal commit: the gate within ctx (an error when it expires), then
// the lock for at most ForeignHookRemovalDrainWait, a wait ctx does not
// shorten. drained reports that no exchange was inside when it went on.
func LockForeignHookAccountRemoval(ctx context.Context, dataDir, identity string) (release func(), drained bool, err error) {
	gatePath, mainPath, ok := ForeignHookAccountLockPaths(dataDir, identity)
	if !ok {
		return nil, false, errors.New("the account has no foreign-hook removal lock")
	}
	if err := createForeignHookSessionStoreParent(filepath.Clean(strings.TrimSpace(dataDir)), filepath.Dir(gatePath)); err != nil {
		return nil, false, fmt.Errorf("create the foreign-hook session store folder: %w", err)
	}
	gate, err := openForeignHookAccountLock(gatePath, dataDir)
	if err != nil {
		return nil, false, err
	}
	gateCtx, cancel := context.WithTimeout(ctx, ForeignHookRemovalGateWait)
	err = gate.lock(gateCtx, true, foreignHookLockRemovalPoll)
	cancel()
	if err != nil {
		gate.close()
		return nil, false, fmt.Errorf("take the foreign-hook removal gate of the account: %w", err)
	}
	main, err := openForeignHookAccountLock(mainPath, dataDir)
	if err != nil {
		gate.release()
		return nil, false, err
	}
	// The drain always gets its whole wait, whatever is left of ctx: the
	// removal goes on past an exchange still inside only once that
	// exchange's answer deadline has passed (it set it before it asked for
	// the gate, which this removal now holds). A caller whose own deadline
	// ended the wait early would go on while that exchange may still
	// publish an allow under the key the removal is about to rotate.
	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), foreignHookRemovalDrainWait())
	err = main.lock(drainCtx, true, foreignHookLockRemovalPoll)
	cancel()
	held := err == nil
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		main.close()
		gate.release()
		return nil, false, fmt.Errorf("take the foreign-hook removal lock of the account: %w", err)
	}
	return sync.OnceFunc(func() {
		if held {
			main.unlock()
		}
		main.close()
		gate.release()
	}), held, nil
}

// foreignHookRemovalDrainOverride replaces ForeignHookRemovalDrainWait
// when set (nanoseconds): tests in other packages shorten the drain to
// probe whether an exchange is inside the lock
// (OverrideForeignHookRemovalDrainWaitForTest).
var foreignHookRemovalDrainOverride atomic.Int64

func foreignHookRemovalDrainWait() time.Duration {
	if d := foreignHookRemovalDrainOverride.Load(); d > 0 {
		return time.Duration(d)
	}
	return ForeignHookRemovalDrainWait
}

// OverrideForeignHookRemovalDrainWaitForTest sets how long a removal waits
// for the exchanges inside the lock, for tests that probe whether one is
// inside without waiting the whole drain.
func OverrideForeignHookRemovalDrainWaitForTest(wait time.Duration) (restore func()) {
	previous := foreignHookRemovalDrainOverride.Swap(int64(wait))
	return func() { foreignHookRemovalDrainOverride.Store(previous) }
}

func foreignHookLockWaitError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%w: %v", ErrForeignHookRemovalPending, err)
	}
	return err
}

type foreignHookAccountLock struct {
	path string
	info fs.FileInfo
	file *os.File
}

// openForeignHookAccountLock opens (creating it when missing) one lock file:
// a regular file, not a link, that the path still names once open. A file
// root creates gets the owner of the folder it is in, so the gateway can
// open it too.
func openForeignHookAccountLock(path, dataDir string) (*foreignHookAccountLock, error) {
	file, err := openForeignHookLockFile(path)
	if err != nil {
		return nil, fmt.Errorf("open the foreign-hook removal lock %s: %w", path, err)
	}
	opened, err := file.Stat()
	if err == nil && !opened.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err == nil {
		var current fs.FileInfo
		if current, err = os.Lstat(path); err == nil && !os.SameFile(opened, current) {
			err = errors.New("replaced while it was opened")
		}
	}
	if err == nil {
		err = foreignHookLockFileOwner(file, filepath.Dir(path))
	}
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("foreign-hook removal lock %s: %w", path, err)
	}
	return &foreignHookAccountLock{path: path, info: opened, file: file}, nil
}

// lock takes the file lock within ctx and checks that the path still names
// the locked file: holders on different files would not exclude each other.
func (l *foreignHookAccountLock) lock(ctx context.Context, exclusive bool, poll time.Duration) error {
	if err := lockForeignHookRemovalFile(ctx, l.file, exclusive, poll); err != nil {
		return err
	}
	current, err := os.Lstat(l.path)
	if err == nil && !os.SameFile(l.info, current) {
		err = errors.New("replaced")
	}
	if err != nil {
		l.unlock()
		return fmt.Errorf("foreign-hook removal lock %s changed while locking: %v", l.path, err)
	}
	return nil
}

func (l *foreignHookAccountLock) unlock() { unlockForeignHookRemovalFile(l.file) }

func (l *foreignHookAccountLock) close() { _ = l.file.Close() }

func (l *foreignHookAccountLock) release() {
	l.unlock()
	l.close()
}

// ForeignHookRemovalsLedgerLockFile is the hook guardian's lock of the
// removal ledger, next to it in the guardian's authorization folder. Every
// guardian process takes it exclusively around its read, merge and atomic
// replacement of the ledger, so a removal one process recorded is never
// lost to another process's write that read the ledger before it. The
// gateway reads the ledger without it (the ledger is replaced in one
// rename), so it never delays an online answer.
const ForeignHookRemovalsLedgerLockFile = "foreign-hook-removals-ledger.lock"

// LockForeignHookRemovalLedger holds the ledger lock in dir within ctx.
func LockForeignHookRemovalLedger(ctx context.Context, dir string) (func(), error) {
	lock, err := openForeignHookAccountLock(filepath.Join(dir, ForeignHookRemovalsLedgerLockFile), dir)
	if err != nil {
		return nil, err
	}
	if err := lock.lock(ctx, true, foreignHookLockRemovalPoll); err != nil {
		lock.close()
		return nil, fmt.Errorf("take the foreign-hook removal ledger lock: %w", err)
	}
	return sync.OnceFunc(lock.release), nil
}
