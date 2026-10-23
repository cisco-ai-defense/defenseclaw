// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Owed revocations (1.0.4 guard review loop round 3).
//
// When the operating system refuses the gateway every way of ending an
// account's protected session record key, the gateway owes the revocation
// and saves it in its data directory (internal/gateway
// foreign_hook_revocation_owed.go): one file per account, named like the
// account's private session store and holding its identity. The gateway
// settles a revocation once its own revocation took. The hook guardian,
// which runs as root or SYSTEM and so is not refused what the gateway was,
// ends the key of every account named there at every pass
// (ForeignHookRevocationsOwed), and of every account when it cannot tell
// whom a saved one names.

const (
	// ForeignHookRevocationsOwedDirName is the folder of the owed
	// revocations in the gateway's data directory.
	ForeignHookRevocationsOwedDirName = "foreign-hook-revocations-owed"
	// foreignHookRevocationOwedLimit bounds one saved revocation (an
	// account identity).
	foreignHookRevocationOwedLimit = 512
)

// ForeignHookRevocationsOwedDir is the folder of the owed revocations
// under the gateway data directory dataDir.
func ForeignHookRevocationsOwedDir(dataDir string) string {
	return filepath.Join(dataDir, ForeignHookRevocationsOwedDirName)
}

// ForeignHookRevocationOwedPath is the saved owed revocation of identity's
// account under dataDir.
func ForeignHookRevocationOwedPath(dataDir, identity string) string {
	return filepath.Join(ForeignHookRevocationsOwedDir(dataDir), filepath.Base(ForeignHookSessionStoreDir(dataDir, identity)))
}

// ReadForeignHookRevocationOwed is the account identity the saved owed
// revocation at path names, and false when it names none: a file that is
// not a regular file, cannot be read, or holds no identity.
func ReadForeignHookRevocationOwed(path string) (string, bool) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return "", false
	}
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

// ForeignHookRevocationsOwed lists the owed revocations saved under the
// gateway data directory dataDir: the accounts they name, and all when
// every account's key must be ended. Any doubt is all: a folder that cannot
// be read (the error says why), and an entry that names no account (a save
// cut short, a name that does not match its identity, a file that cannot
// be read).
func ForeignHookRevocationsOwed(dataDir string) (identities []string, all bool, err error) {
	dir := ForeignHookRevocationsOwedDir(dataDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, fmt.Errorf("read the owed revocations in %s: %w", dir, err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		identity, ok := ReadForeignHookRevocationOwed(path)
		if !ok || ForeignHookRevocationOwedPath(dataDir, identity) != path {
			all = true
			continue
		}
		seen[identity] = true
	}
	for identity := range seen {
		identities = append(identities, identity)
	}
	sort.Strings(identities)
	return identities, all, nil
}
