// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A closed account (1.0.4 guard: fail closed by class).
//
// When the gateway denies a session and a revocation write fails (the
// key's removal, its revocation mark or the block record), it closes the
// account: it adds an empty file, the account's closed mark, in a second
// folder only root, SYSTEM, Administrators and the gateway service can add
// to, apart from the folder of the revocation marks
// (publishedSessionClosedPath: the record folder on Linux and macOS, the
// account's own folder on Windows). While the mark is there, or when it
// cannot be read, no allow of the account passes an outage. The gateway
// removes it once a revocation of the account's key took; the hook
// guardian, as root or SYSTEM, rotates the key of a closed account and then
// removes it (ensurePublishedSessionAccountKey). Only the existence of the
// file counts, so no standard user can open an account by any change to
// it: one who could add it would only close their own outage allows.

// publishedSessionCreateClosedFile creates a closed mark and
// publishedSessionClosedStat reads one (replaceable in tests, which stand
// in for a folder that takes no new file and a mark that cannot be read).
var (
	publishedSessionCreateClosedFile = createPublishedSessionMarkFile
	publishedSessionClosedStat       = os.Lstat
)

// publishedSessionClosedSuffix ends the name of a closed mark.
const publishedSessionClosedSuffix = ".closed"

// publishedSessionClosedPlace checks root and the account folder name
// digest of a closed mark: the clean record folder, or false.
func publishedSessionClosedPlace(root, digest string) (string, bool) {
	if _, _, ok := publishedSessionKeyRoot(root); !ok || !publishedSessionDigest(digest) {
		return "", false
	}
	return filepath.Clean(strings.TrimSpace(root)), true
}

// isPublishedSessionClosedName reports the name of a closed mark.
func isPublishedSessionClosedName(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), publishedSessionClosedSuffix)
}

// MarkPublishedSessionAccountClosed closes identity's account under the
// record folder root: it adds the account's closed mark, flushes it and
// its folder, and reads it back. A mark that is there already is kept. A
// folder the mark goes in that does not exist holds no record of the
// account, so there is nothing to close.
func MarkPublishedSessionAccountClosed(root, identity string) error {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return fmt.Errorf("invalid caller identity")
	}
	path, ok := publishedSessionClosedPath(root, digest)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if err := publishedSessionCreateClosedFile(path); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("add the closed mark %s: %w", path, err)
	}
	if err := publishedSessionSyncDir(dir); err != nil {
		return fmt.Errorf("flush %s: %w", dir, err)
	}
	if _, err := publishedSessionClosedStat(path); err != nil {
		return fmt.Errorf("read the closed mark %s back: %w", path, err)
	}
	return nil
}

// ClearPublishedSessionAccountClosed removes identity's closed mark under
// root: the caller ended the account's key since it was added.
func ClearPublishedSessionAccountClosed(root, identity string) error {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return fmt.Errorf("invalid caller identity")
	}
	return clearPublishedSessionAccountClosed(root, digest)
}

func clearPublishedSessionAccountClosed(root, digest string) error {
	path, ok := publishedSessionClosedPath(root, digest)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// PublishedSessionAccountClosed reports identity's account closed under
// root, or its closed mark unreadable (an error); nil when it is open. The
// gateway renews none of a closed account's proofs.
func PublishedSessionAccountClosed(root, identity string) error {
	digest, ok := publishedSessionIdentityDigest(identity)
	if !ok {
		return fmt.Errorf("invalid caller identity")
	}
	return publishedSessionAccountClosed(root, digest)
}

// publishedSessionAccountClosed is the hook's check of the account whose
// folder name is digest: nil only when its closed mark is known not to be
// there.
func publishedSessionAccountClosed(root, digest string) error {
	path, ok := publishedSessionClosedPath(root, digest)
	if !ok {
		return fmt.Errorf("no protected session record folder %q", root)
	}
	_, err := publishedSessionClosedStat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return fmt.Errorf("the account's closed mark cannot be read: %v", err)
	}
	return errors.New("the gateway closed the account: a revocation of its records did not take")
}

// PublishedSessionAllowWindowEnd is when the last allow of identity's
// account under root stops proving its session during an outage: the
// latest renewal of an allow record with a MAC in the account's folder,
// plus PublishedSessionProofLifetime; the zero time when it has none. A
// folder or record that cannot be read is an error: the caller then knows
// only that every allow ends by PublishedSessionProofLifetime after now.
func PublishedSessionAllowWindowEnd(root, identity string) (time.Time, error) {
	dir, ok := PublishedSessionIdentityDir(root, identity)
	if !ok {
		return time.Time{}, fmt.Errorf("invalid caller identity")
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	var last time.Time
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		record, exists, err := readPublishedSessionRecord(filepath.Join(dir, name), func(string) error { return nil })
		if err != nil {
			return time.Time{}, err
		}
		if !exists || record.Blocked || record.MAC == "" {
			continue
		}
		at, err := time.Parse(time.RFC3339, record.At)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s: %w", name, err)
		}
		if at.After(last) {
			last = at
		}
	}
	if last.IsZero() {
		return last, nil
	}
	return last.Add(PublishedSessionProofLifetime), nil
}
