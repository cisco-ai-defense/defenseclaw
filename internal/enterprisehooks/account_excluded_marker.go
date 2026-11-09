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
// that is no longer excluded. A marker that cannot be removed (a
// reader of the file holds it open without delete sharing) is revoked by a
// second file, the revocation record, which is a new name nothing holds: the
// hook reads a marker as valid only while its account has no revocation
// record, and the guardian removes the record in the cycle that publishes the
// account again or finds the marker gone. Any other state keeps the refusal.
//
// The bytes and the directory handling are here; Windows binds the trusted
// reads and writes (account_excluded_windows.go).

const accountExcludedMarkerPrefix = ".defenseclaw-account-excluded-"

// accountExcludedRevokedPrefix names the revocation record of an account. It
// is not a prefix-extension of the marker name, so no marker scan sees it.
const accountExcludedRevokedPrefix = ".defenseclaw-account-revoked-"

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

func accountExcludedRevokedPath(dir, sid string) string {
	return filepath.Join(dir, accountExcludedRevokedPrefix+sid)
}

// The hook reads only that the record exists; the body names the account for
// a human reading the directory.
func accountExcludedRevokedBody(sid string) []byte {
	return []byte("account-excluded-revoked-v1 " + sid + "\n")
}

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
	// remove deletes the file at path.
	remove func(path string) error
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
		// An earlier revocation record is cleared before the marker is
		// published; one that cannot be cleared keeps the account refused.
		if err := clearAccountExcludedRevocation(dir, sid, io); err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: clear the excluded-account revocation of %s, so its marker is not published: %w", sid, err))
			continue
		}
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
// A marker that cannot be removed, after a short retry, is revoked by the
// revocation record of its account, a new file no reader of the marker can
// hold; only when that cannot be written either does the marker stay valid,
// and the error says so. A revocation record whose marker is gone is removed.
func removeAccountExcludedMarkers(dir string, keep map[string]string, io accountExcludedMarkerIO) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: list the excluded-account markers: %w", err)
	}
	keptSIDs := map[string]bool{}
	for _, sid := range keep {
		keptSIDs[sid] = true
	}
	var errs []error
	held := map[string]bool{} // accounts whose marker could not be removed
	for _, entry := range entries {
		name := strings.ToLower(entry.Name())
		if !strings.HasPrefix(name, accountExcludedMarkerPrefix) {
			continue
		}
		if _, kept := keep[name]; kept {
			continue
		}
		removeErr := removeAccountExcludedFile(filepath.Join(dir, entry.Name()), io)
		if removeErr == nil {
			continue
		}
		sid, ok := accountExcludedSID(entry.Name()[len(accountExcludedMarkerPrefix):])
		if !ok {
			errs = append(errs, fmt.Errorf("enterprise hooks: remove the stale excluded-account marker %s: %w", entry.Name(), removeErr))
			continue
		}
		held[sid] = true
		if revokeErr := revokeAccountExcludedMarker(dir, sid, io); revokeErr != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: the stale excluded-account marker %s could be neither removed (%v) nor revoked (%v); it stays valid until the next cycle removes it", entry.Name(), removeErr, revokeErr))
		}
	}
	for _, entry := range entries {
		if !strings.HasPrefix(strings.ToLower(entry.Name()), accountExcludedRevokedPrefix) {
			continue
		}
		sid, ok := accountExcludedSID(entry.Name()[len(accountExcludedRevokedPrefix):])
		if ok && (held[sid] || keptSIDs[sid]) {
			continue // in force, or cleared when the marker of the account is published
		}
		if removeErr := removeAccountExcludedFile(filepath.Join(dir, entry.Name()), io); removeErr != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: remove the spent excluded-account revocation %s: %w", entry.Name(), removeErr))
		}
	}
	return errors.Join(errs...)
}

// revokeAccountExcludedMarker writes the revocation record of sid, unless it
// is already there.
func revokeAccountExcludedMarker(dir, sid string, io accountExcludedMarkerIO) error {
	path := accountExcludedRevokedPath(dir, sid)
	if _, exists, err := io.read(path); err == nil && exists {
		return nil
	}
	return io.write(path, accountExcludedRevokedBody(sid))
}

// clearAccountExcludedRevocation removes the revocation record of sid, so a
// marker published after it counts again.
func clearAccountExcludedRevocation(dir, sid string, io accountExcludedMarkerIO) error {
	path := accountExcludedRevokedPath(dir, sid)
	if _, exists, err := io.read(path); err == nil && !exists {
		return nil
	}
	return removeAccountExcludedFile(path, io)
}

func removeAccountExcludedFile(path string, io accountExcludedMarkerIO) error {
	var err error
	for attempt := 0; attempt < accountExcludedRemoveAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(accountExcludedRemoveWait)
		}
		if err = io.remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
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
	// A marker the guardian could not remove is revoked by its record; an
	// unreadable record is a revocation too.
	if _, revoked, err := io.read(accountExcludedRevokedPath(dir, sid)); err != nil || revoked {
		return false, fmt.Errorf("enterprise hooks: the excluded-account marker of %s was revoked (record present=%t, read error=%v)", sid, revoked, err)
	}
	return true, nil
}
