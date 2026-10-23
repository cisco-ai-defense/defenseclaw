// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// An owed revocation (any doubt blocks).
//
// The gateway revokes an account's protected session record key before it
// records or publishes any block (killForeignHookSessionKey). When the
// operating system refuses every way of doing it (the key's removal, its
// revocation mark and the block record), an allow the account got before
// may still verify, and the gateway could change nothing the hook reads.
// The revocation is then owed:
//
//   - it is saved in the gateway's data directory
//     (foreignHookRevocationOwedPath), so a restarted gateway owes it too,
//     and kept in memory as well, in case that save fails;
//   - every exchange of the account tries it again first and, while it is
//     still owed, publishes no allow with a key, so no allow made after the
//     block passes an outage either;
//   - the API server tries every owed revocation again every
//     foreignHookRevocationRetryEvery and once more when it stops, so a
//     folder that takes a change again ends the earlier allow at once, not
//     at the account's next call.
//
// While it is owed the account stays closed when its closed mark could be
// added (enterprisepolicy.MarkPublishedSessionAccountClosed; each retry adds
// it again when it could not), no proof of the account is renewed, and,
// whatever the folders look like, its earlier allows end by themselves
// within enterprisepolicy.PublishedSessionProofLifetime of their last
// renewal (foreign_hook_session_proof.go). A revocation that took clears the
// account's closed mark: no earlier allow verifies any more.

// The saved owed revocations are in the gateway's data directory
// (enterprisepolicy.ForeignHookRevocationsOwedDir), where the hook guardian
// reads them too: it ends the key of every account named there at every
// pass, as root or SYSTEM, whom the operating system does not refuse what
// it refused the gateway.
const foreignHookRevocationsOwedDirName = enterprisepolicy.ForeignHookRevocationsOwedDirName

// foreignHookRevocationRetryEvery is how often the API server tries the
// owed revocations again, and foreignHookRevocationStopTimeout bounds its
// last try when it stops.
const (
	foreignHookRevocationRetryEvery  = time.Second
	foreignHookRevocationStopTimeout = 2 * time.Second
)

// foreignHookRevocationsOwed are the owed revocations this gateway process
// knows of: the saved file of each, and its account identity.
type foreignHookRevocationsOwed struct {
	mu   sync.Mutex
	owed map[string]string
}

// foreignHookRevocationOwedPath is the saved owed revocation of identity's
// account: one file per account in the data directory dataDir, named like
// its private session store, holding the identity.
func foreignHookRevocationOwedPath(dataDir, identity string) string {
	return enterprisepolicy.ForeignHookRevocationOwedPath(dataDir, identity)
}

// oweForeignHookRevocation records that a revocation of identity's account
// did not take.
func (a *APIServer) oweForeignHookRevocation(places foreignHookSessionPlaces, identity string) {
	path := foreignHookRevocationOwedPath(places.dataDir, identity)
	a.foreignHookOwed.mu.Lock()
	if a.foreignHookOwed.owed == nil {
		a.foreignHookOwed.owed = map[string]string{}
	}
	a.foreignHookOwed.owed[path] = identity
	a.foreignHookOwed.mu.Unlock()
	if err := saveForeignHookRevocationOwed(path, identity); err != nil {
		// A restarted gateway does not know of it, but it renews no proof
		// it did not answer itself, so the earlier allows still end.
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: an owed revocation of an account's protected session records was not saved; it is owed in memory: %v\n", err)
	}
}

func saveForeignHookRevocationOwed(path, identity string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(identity+"\n"), 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// settleForeignHookRevocation records that a revocation of identity's
// account took: none is owed any more, and the account's closed mark, which
// stood for allows that no longer verify, is cleared.
func (a *APIServer) settleForeignHookRevocation(places foreignHookSessionPlaces, identity string) {
	if err := foreignHookSessionOpen(places.recordRoot, identity); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the account's closed mark could not be cleared, so its guarded calls block during an outage until the hook guardian clears it: %v\n", err)
	}
	path := foreignHookRevocationOwedPath(places.dataDir, identity)
	a.foreignHookOwed.mu.Lock()
	delete(a.foreignHookOwed.owed, path)
	a.foreignHookOwed.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Still owed on disk: this gateway, and a restarted one, try it
		// again, which only ends the account's allows once more.
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: a settled revocation of an account's protected session records could not be cleared: %v\n", err)
	}
}

// foreignHookRevocationOwed reports a revocation of identity's account that
// is owed: known to this process, or saved. A saved one that cannot be
// checked is owed.
func (a *APIServer) foreignHookRevocationOwed(places foreignHookSessionPlaces, identity string) bool {
	path := foreignHookRevocationOwedPath(places.dataDir, identity)
	a.foreignHookOwed.mu.Lock()
	_, owed := a.foreignHookOwed.owed[path]
	a.foreignHookOwed.mu.Unlock()
	if owed {
		return true
	}
	_, err := os.Lstat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// payForeignHookRevocation tries an owed revocation of identity's account
// again (the caller holds the account's exchange lock of this process), and
// closes the account again when the revocation still does not take. It
// reports whether none is owed any more.
func (a *APIServer) payForeignHookRevocation(places foreignHookSessionPlaces, identity, connectorName string) bool {
	if places.recordRoot == "" || !a.foreignHookRevocationOwed(places, identity) {
		return true
	}
	if a.killForeignHookSessionKey(places, identity, connectorName) == nil {
		return true
	}
	if err := foreignHookSessionClose(places.recordRoot, identity); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: revocation FAILED again: the account could not be closed either; its earlier allows end within %s of their last renewal, and this is tried again: %v\n",
			enterprisepolicy.PublishedSessionProofLifetime, err)
	}
	return false
}

// owedForeignHookRevocations names the accounts with an owed revocation
// under the data directory dataDir: those this process knows of and those
// saved there.
func (a *APIServer) owedForeignHookRevocations(dataDir string) []string {
	dir := filepath.Join(dataDir, foreignHookRevocationsOwedDirName)
	seen := map[string]bool{}
	a.foreignHookOwed.mu.Lock()
	for path, identity := range a.foreignHookOwed.owed {
		if identity != "" && filepath.Dir(path) == dir {
			seen[identity] = true
		}
	}
	a.foreignHookOwed.mu.Unlock()
	saved, _, _ := enterprisepolicy.ForeignHookRevocationsOwed(dataDir)
	for _, identity := range saved {
		seen[identity] = true
	}
	identities := make([]string, 0, len(seen))
	for identity := range seen {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return identities
}

// payOwedForeignHookRevocations tries every owed revocation of this
// gateway's data directory again, each under its account's exchange lock of
// this process, so that it never settles a revocation an exchange owed
// after this one tried.
func (a *APIServer) payOwedForeignHookRevocations() {
	dataDir := strings.TrimSpace(a.configDataDir())
	if !filepath.IsAbs(dataDir) {
		return
	}
	places := a.foreignHookSessionPlaces(dataDir)
	if places.recordRoot == "" {
		return
	}
	for _, identity := range a.owedForeignHookRevocations(dataDir) {
		unlock := a.foreignHookSessionLocks.lock(enterprisepolicy.ForeignHookSessionStoreDir(dataDir, identity))
		a.payForeignHookRevocation(places, identity, "")
		unlock()
	}
}

// retryOwedForeignHookRevocations tries the owed revocations again every
// interval until ctx ends, and once more then.
func (a *APIServer) retryOwedForeignHookRevocations(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.payOwedForeignHookRevocations()
			return
		case <-ticker.C:
			a.payOwedForeignHookRevocations()
		}
	}
}
