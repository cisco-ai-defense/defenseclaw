// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// enterpriseForeignHookRemovalsMu serializes ledger updates of this process:
// the Unix per-user workers report their removals concurrently. Commits of
// different guardian processes for one account are serialized by the
// account's removal lock.
var enterpriseForeignHookRemovalsMu sync.Mutex

// enterpriseForeignHookAccountID names an account the way the gateway names
// a verified caller: the SID when there is one, else the uid.
func enterpriseForeignHookAccountID(sid string, uid int) string {
	if sid != "" {
		return sid
	}
	if uid >= 0 {
		return strconv.Itoa(uid)
	}
	return ""
}

// enterpriseForeignHookRemovalMarkAhead is how far ahead the first record of
// a removal (made before the file changes) denies agent processes: past
// the longest a cleanup worker can still change files after its guardian
// ended (enterpriseHookWorkerTimeout plus its kill), so a guardian that
// ends between the change and the second record leaves every process that
// may have loaded the file denied until it restarts.
const enterpriseForeignHookRemovalMarkAhead = 5 * time.Minute

// enterpriseForeignHookRemovalTx is one removal commit of one account: the
// account's removal lock held exclusively and the removal recorded once
// before the change.
type enterpriseForeignHookRemovalTx struct {
	stderr    io.Writer
	identity  string
	home      string
	connector string
	paths     []string
	release   func()
	// first is the first record (with ForeignHookRemovalInProgressSuffix),
	// which the commit drops.
	first []enterprisepolicy.ForeignHookRemoval
}

// beginEnterpriseForeignHookRemoval opens the commit of one removal of
// account's (home's) hook files paths for connector, before any of them
// changes (GAP-0348, GAP-0381, GAP-0414, GAP-0457, and the 1.0.4 guard
// consolidation). In this order, and stopping at the first failure:
//
//  1. It takes the account's removal lock exclusively
//     (enterprisepolicy.LockForeignHookAccountRemoval): no new online
//     answer of the account starts, and those inside finish within their
//     bound or are cut. Other accounts never wait.
//  2. It records the removal in the ledger with a mark
//     enterpriseForeignHookRemovalMarkAhead ahead.
//
// On an error nothing may change: the hook stays in place, so the scan
// keeps blocking, and the next pass tries again. The caller changes the
// files and then commits (enterpriseForeignHookRemovalTx.commit).
func beginEnterpriseForeignHookRemoval(ctx context.Context, stderr io.Writer, account, home, connectorName string, paths []string) (*enterpriseForeignHookRemovalTx, error) {
	return beginEnterpriseForeignHookRemovalMarked(ctx, stderr, account, home, connectorName, paths, "")
}

// beginEnterpriseForeignHookRemovalMarked is beginEnterpriseForeignHookRemoval
// whose first record has firstMark ("" for the mark ahead): a record of a
// change already made (recordEnterpriseForeignHookRemovalsAt) takes the
// mark of when that change was known to be done.
func beginEnterpriseForeignHookRemovalMarked(ctx context.Context, stderr io.Writer, account, home, connectorName string, paths []string, firstMark string) (*enterpriseForeignHookRemovalTx, error) {
	identity, ok := connector.CanonicalUserScopedIdentity(account)
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil, errors.New("foreign-hook removal outside a standalone enterprise host")
	}
	if !ok || connectorName == "" || len(paths) == 0 {
		return nil, errors.New("cannot bind the hook removal to an account, a connector and its files")
	}
	if !filepath.IsAbs(cfg.DataDir) {
		return nil, errors.New("the data directory is not an absolute path")
	}
	release, drained, err := enterpriseForeignHookLockAccount(ctx, cfg.DataDir, identity)
	if err != nil {
		return nil, fmt.Errorf("take the account's foreign-hook removal lock: %w", err)
	}
	if !drained {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: an online answer for %s did not finish within %s; going on, it is cut\n",
			foreignGuardLogField(account, 256), enterprisepolicy.ForeignHookRemovalDrainWait)
	}
	tx := &enterpriseForeignHookRemovalTx{stderr: stderr, identity: identity, home: home, connector: connectorName, paths: limitEnterpriseForeignHookPaths(paths), release: release}
	mark := firstMark
	if mark == "" {
		mark = agentprocess.NowAfter(enterpriseForeignHookRemovalMarkAhead)
	}
	first, err := tx.record(mark, enterprisepolicy.ForeignHookRemovalInProgressSuffix, nil)
	if err != nil {
		release()
		return nil, fmt.Errorf("record the removal before it is made: %w", err)
	}
	tx.first = first
	return tx, nil
}

// limitEnterpriseForeignHookPaths keeps at most 32 paths of a removal, each
// at most 512 bytes, as the worker reports them.
func limitEnterpriseForeignHookPaths(paths []string) []string {
	out := make([]string, 0, min(len(paths), 32))
	for _, path := range paths {
		if len(out) == 32 {
			break
		}
		out = append(out, foreignGuardLogField(path, 512))
	}
	return out
}

// record writes the transaction's files to the ledger with mark. The time
// of each entry has nanoseconds: the ledger keeps, per account, connector
// and file, the entry recorded last, and records of one account are made
// in commit order under its removal lock, so the second record of a commit
// always replaces its first, and a later commit an earlier one.
func (tx *enterpriseForeignHookRemovalTx) record(mark, suffix string, dropped []enterprisepolicy.ForeignHookRemoval) ([]enterprisepolicy.ForeignHookRemoval, error) {
	if mark == "" {
		return nil, errors.New("the process clock is unavailable")
	}
	now := time.Now().UTC()
	connectors := enterprisepolicy.StandaloneConnectors(cfg)
	var added []enterprisepolicy.ForeignHookRemoval
	for _, path := range tx.paths {
		for _, name := range enterprisepolicy.ForeignHookRemovalConnectors(tx.home, path, tx.connector, connectors) {
			added = append(added, enterprisepolicy.ForeignHookRemoval{
				Identity: tx.identity, Connector: name, Path: foreignGuardLogField(path, 512) + suffix,
				At: now.Format(time.RFC3339Nano), Mark: mark,
			})
		}
	}
	enterpriseForeignHookRemovalsMu.Lock()
	defer enterpriseForeignHookRemovalsMu.Unlock()
	return added, writeEnterpriseForeignHookRemovalLedger(added, dropped, now)
}

// commit records the transaction's files again with the mark of now, which
// replaces the mark ahead (the change is done, so only processes that
// started before now may have loaded a file it removed), and lets go of the
// account's lock. It runs whether or not the change worked. A record that
// fails leaves the first one, which denies longer.
func (tx *enterpriseForeignHookRemovalTx) commit(removed []string) error {
	return tx.commitAt(agentprocess.Now(), removed)
}

// commitAt is commit with the mark of when the change was known to be done:
// taken before any wait, so a lock this process waits for never makes an
// agent process that started after the change count as one that started
// before it.
func (tx *enterpriseForeignHookRemovalTx) commitAt(mark string, removed []string) error {
	defer tx.release()
	_, err := tx.record(mark, "", tx.first)
	if err != nil {
		fmt.Fprintf(tx.stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s after it was made (the record made before it still denies): %v\n",
			tx.connector, foreignGuardLogField(tx.identity, 256), err)
	}
	_ = removed
	return err
}

// recordEnterpriseForeignHookRemovals records removals a cleanup made that
// no commit recorded (a worker that changed a file and ended before its
// commit): a full commit (beginEnterpriseForeignHookRemoval) with nothing
// left to change.
// Failures are logged; the per-call check still applies.
func recordEnterpriseForeignHookRemovals(stderr io.Writer, account, home, connectorName string, paths []string) {
	recordEnterpriseForeignHookRemovalsAt(stderr, agentprocess.Now(), account, home, connectorName, paths)
}

// recordEnterpriseForeignHookRemovalsAt is recordEnterpriseForeignHookRemovals
// with the mark of when the cleanup that made the removals ended (taken
// before any lock wait): every agent process that may have loaded a removed
// file started before it.
func recordEnterpriseForeignHookRemovalsAt(stderr io.Writer, mark, account, home, connectorName string, paths []string) {
	if len(paths) == 0 || cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	if mark == "" {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: the process clock is unavailable\n",
			connectorName, foreignGuardLogField(account, 256))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), enterpriseForeignHookInProcessQueueWait)
	defer cancel()
	tx, err := beginEnterpriseForeignHookRemovalMarked(ctx, stderr, account, home, connectorName, paths, mark)
	if err == nil {
		err = tx.commitAt(mark, paths)
	}
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw: enterprise foreign-hook guard: record the %s hook removal for %s: %v\n",
			connectorName, foreignGuardLogField(account, 256), err)
	}
}

// writeEnterpriseForeignHookRemovalLedger adds added to the removal ledger
// in the guardian's authorization directory. A ledger that cannot be read
// is never replaced: the gateway denies every call while it cannot read it,
// and a new ledger would drop the removals it holds. A ledger too full to
// keep the denial of every account and connector
// (enterprisepolicy.ErrForeignHookRemovalLedgerFull) is not written either.
// The new file has its final mode and owner before it is renamed into
// place (writeEnterpriseHookGatewayRecord). The caller holds
// enterpriseForeignHookRemovalsMu.
func writeEnterpriseForeignHookRemovalLedger(added, dropped []enterprisepolicy.ForeignHookRemoval, now time.Time) error {
	dataDir := cfg.DataDir
	if !filepath.IsAbs(managed.HookGuardianAuthorizationDir(dataDir)) {
		return errors.New("the data directory is not an absolute path")
	}
	dir := managed.HookGuardianAuthorizationDir(dataDir)
	path := filepath.Join(dir, enterprisepolicy.ForeignHookRemovalsFile)
	if _, err := prepareEnterpriseHookAuthorizationDir(dataDir); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), enterpriseForeignHookLedgerLockWait)
	release, err := enterpriseForeignHookLockLedger(ctx, dir)
	cancel()
	if err != nil {
		return err
	}
	defer release()
	existing, err := loadEnterpriseForeignHookRemovals(path)
	if err != nil {
		return fmt.Errorf("the removal ledger cannot be read and is kept until it can be read again or an administrator removes %s: %w", path, err)
	}
	data, err := enterprisepolicy.EncodeForeignHookRemovalsDropping(existing, added, dropped, now)
	if err != nil {
		return err
	}
	return writeEnterpriseHookGatewayRecord(path, data)
}

// enterpriseForeignHookLedgerLockWait bounds the wait for the ledger lock,
// which another guardian process holds only for one ledger write; past it
// the removal is refused (the hook stays and the scan keeps blocking).
const enterpriseForeignHookLedgerLockWait = 30 * time.Second

var (
	enterpriseForeignHookLockAccount = enterprisepolicy.LockForeignHookAccountRemoval
	enterpriseForeignHookLockLedger  = enterprisepolicy.LockForeignHookRemovalLedger
)

func loadEnterpriseForeignHookRemovals(path string) ([]enterprisepolicy.ForeignHookRemoval, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := enterpriseHookAuthorizationFileTrustCheck(path); err != nil {
		return nil, err
	}
	data, err := readEnterpriseHookBoundedFile(path, info, enterprisepolicy.ForeignHookRemovalsMaxBytes, "foreign-hook removal ledger")
	if err != nil {
		return nil, err
	}
	return enterprisepolicy.ParseForeignHookRemovals(data)
}
