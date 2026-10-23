// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
// While the folders take no change, the hook refuses every allow of the
// account during an outage by itself: it allows only while the folder of
// the account's revocation marks lets the gateway add a file
// (enterprisepolicy.CheckPublishedForeignHookSession).

// foreignHookRevocationsOwedDirName is the folder of the owed revocations
// in the gateway's data directory, and foreignHookRevocationOwedLimit
// bounds one saved revocation (an account identity).
const (
	foreignHookRevocationsOwedDirName = "foreign-hook-revocations-owed"
	foreignHookRevocationOwedLimit    = 512
)

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
	return filepath.Join(dataDir, foreignHookRevocationsOwedDirName, filepath.Base(enterprisepolicy.ForeignHookSessionStoreDir(dataDir, identity)))
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
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: an owed revocation of an account's protected session records was not saved, so a restarted gateway would not try it again: %v\n", err)
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
// account took: none is owed any more.
func (a *APIServer) settleForeignHookRevocation(places foreignHookSessionPlaces, identity string) {
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
// again (the caller holds the account's exchange lock of this process). It
// reports whether none is owed any more.
func (a *APIServer) payForeignHookRevocation(places foreignHookSessionPlaces, identity, connectorName string) bool {
	if places.recordRoot == "" || !a.foreignHookRevocationOwed(places, identity) {
		return true
	}
	return a.killForeignHookSessionKey(places, identity, connectorName)
}

// owedForeignHookRevocations names the accounts with an owed revocation
// under the data directory dataDir: those this process knows of and those
// saved there.
func (a *APIServer) owedForeignHookRevocations(dataDir string) []string {
	dir := filepath.Join(dataDir, foreignHookRevocationsOwedDirName)
	seen := map[string]bool{}
	a.foreignHookOwed.mu.Lock()
	for path, identity := range a.foreignHookOwed.owed {
		if filepath.Dir(path) == dir {
			seen[identity] = true
		}
	}
	a.foreignHookOwed.mu.Unlock()
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if identity, ok := readForeignHookRevocationOwed(path); ok && foreignHookRevocationOwedPath(dataDir, identity) == path {
			seen[identity] = true
		}
	}
	identities := make([]string, 0, len(seen))
	for identity := range seen {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return identities
}

// readForeignHookRevocationOwed is the account identity a saved owed
// revocation names.
func readForeignHookRevocationOwed(path string) (string, bool) {
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, foreignHookRevocationOwedLimit))
	if err != nil {
		return "", false
	}
	return connector.CanonicalUserScopedIdentity(strings.TrimSpace(string(data)))
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
