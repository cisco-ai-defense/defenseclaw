// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// An account that enterprise.enrollment.exclude_users (or exclude_groups)
// names is not enrolled on purpose: the administrator chose to leave it
// alone, so it holds no row in the protected target set and no runtime. The
// machine-wide hook runs as that account and cannot read the administrator
// only configuration, so it could not tell it from an account that is not
// enrolled yet, and it refused every call with the wait-five-minutes text
// of a pending enrollment, which never ends for an excluded account.
//
// The hook guardian therefore publishes one marker per excluded account in
// the machine hook runtime directory (administrator-owned, readable by every
// account, the directory of the off-roster markers): the file name carries
// the SID, the body repeats it. The hook allows the call only when the
// marker of its own SID is present and valid in a trusted directory. A
// marker is removed in the cycle that no longer excludes the account, and
// the whole set is rewritten each cycle, so a marker never outlives the
// exclusion by more than one cycle. A cycle that cannot judge the accounts
// (no configuration, no profile list, no manifest write) removes every
// marker, so a failed cycle never leaves an old one authorizing an account
// that is no longer excluded. A marker that cannot be removed is overwritten
// with a revoked body, which the hook reads as no marker. Any other state
// keeps the refusal.
//
// The bytes and the directory handling are here; Windows binds the trusted
// reads and writes (account_excluded_windows.go).

const accountExcludedMarkerPrefix = ".defenseclaw-account-excluded-"

var accountExcludedSIDPattern = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)

// accountExcludedSID is sid in its canonical upper-case spelling, and false
// when it is not a SID string. Only that shape reaches a file name.
func accountExcludedSID(sid string) (string, bool) {
	sid = strings.ToUpper(strings.TrimSpace(sid))
	return sid, accountExcludedSIDPattern.MatchString(sid)
}

func accountExcludedMarkerPath(dir, sid string) string {
	return filepath.Join(dir, accountExcludedMarkerPrefix+sid)
}

func accountExcludedMarkerBody(sid string) []byte {
	return []byte("account-excluded-v1 " + sid + "\n")
}

// accountExcludedRevokedBody replaces the body of a marker that could not be
// removed. It names no SID, so no account reads it as its own marker.
var accountExcludedRevokedBody = []byte("account-excluded-revoked\n")

// accountExcludedRemoveAttempts and accountExcludedRemoveWait bound the retry
// of a removal that a reader of the file holds up for a moment.
const accountExcludedRemoveAttempts = 3

var accountExcludedRemoveWait = 50 * time.Millisecond

// accountExcludedMarkerIO is the trusted file access of one platform.
type accountExcludedMarkerIO struct {
	// ensure makes dir ready for the guardian to publish in.
	ensure func(dir string) error
	// write replaces the file at path with body.
	write func(path string, body []byte) error
	// read returns the file at path, and whether it exists.
	read func(path string) ([]byte, bool, error)
	// checkDir proves dir is administrator-owned and not a link.
	checkDir func(dir string) error
}

// publishAccountExcludedMarkers makes the markers in dir exactly those of
// sids: it writes the missing or damaged ones and removes every other marker.
// An empty sids removes them all and creates nothing.
func publishAccountExcludedMarkers(dir string, sids []string, io accountExcludedMarkerIO) error {
	keep := map[string]string{}
	var errs []error
	for _, raw := range sids {
		sid, ok := accountExcludedSID(raw)
		if !ok {
			errs = append(errs, fmt.Errorf("enterprise hooks: %q is not a SID, so no excluded-account marker is published for it", raw))
			continue
		}
		keep[strings.ToLower(accountExcludedMarkerPrefix+sid)] = sid
	}
	// Revocation comes first and does not depend on the publication: a
	// directory that cannot be prepared for new markers still has its stale
	// ones removed.
	revokeErr := removeAccountExcludedMarkers(dir, keep, io)
	if len(keep) == 0 {
		return errors.Join(append(errs, revokeErr)...)
	}
	if err := io.ensure(dir); err != nil {
		return errors.Join(append(errs, revokeErr, err)...)
	}
	for _, sid := range keep {
		path := accountExcludedMarkerPath(dir, sid)
		if data, exists, err := io.read(path); err == nil && exists && string(data) == string(accountExcludedMarkerBody(sid)) {
			continue
		}
		if err := io.write(path, accountExcludedMarkerBody(sid)); err != nil {
			// A marker that is not written keeps that account on the
			// existing refusal, and the other accounts are still published.
			errs = append(errs, fmt.Errorf("enterprise hooks: publish the excluded-account marker of %s: %w", sid, err))
		}
	}
	return errors.Join(append(errs, revokeErr)...)
}

// removeAccountExcludedMarkers removes the markers in dir whose lower-cased
// file name is not a key of keep. A directory that does not exist has none.
// A marker that cannot be removed, after a short retry, is overwritten with
// the revoked body; only when both fail does it stay valid, and the error
// says so.
func removeAccountExcludedMarkers(dir string, keep map[string]string, io accountExcludedMarkerIO) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: list the excluded-account markers: %w", err)
	}
	var errs []error
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if !strings.HasPrefix(name, accountExcludedMarkerPrefix) {
			continue
		}
		if _, kept := keep[name]; kept {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		removeErr := removeAccountExcludedMarkerFile(path)
		if removeErr == nil {
			continue
		}
		if writeErr := io.write(path, accountExcludedRevokedBody); writeErr != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: the stale excluded-account marker %s could be neither removed (%v) nor revoked (%v); it stays valid until the next cycle removes it", entry.Name(), removeErr, writeErr))
		}
	}
	return errors.Join(errs...)
}

func removeAccountExcludedMarkerFile(path string) error {
	var err error
	for attempt := 0; attempt < accountExcludedRemoveAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(accountExcludedRemoveWait)
		}
		if err = os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}
	return err
}

// accountExcludedMarkerPresent is the hook read: whether dir holds a valid
// marker for sid. An untrusted directory, a link, a damaged or unreadable
// marker and an absent marker are all "no"; only the first four carry an error.
func accountExcludedMarkerPresent(dir, sid string, io accountExcludedMarkerIO) (bool, error) {
	sid, ok := accountExcludedSID(sid)
	if !ok {
		return false, fmt.Errorf("enterprise hooks: the calling account has no SID string")
	}
	if err := io.checkDir(dir); err != nil {
		return false, err
	}
	data, exists, err := io.read(accountExcludedMarkerPath(dir, sid))
	if err != nil || !exists {
		return false, err
	}
	if string(data) != string(accountExcludedMarkerBody(sid)) {
		return false, fmt.Errorf("enterprise hooks: the excluded-account marker of %s changed", sid)
	}
	return true, nil
}
