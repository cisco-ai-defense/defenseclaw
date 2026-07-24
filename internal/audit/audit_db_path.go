// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// auditDBPathHooks provide deterministic fault/race injection without
// weakening the production path. There is intentionally no group-readable
// mode: v8 exposes no supported configuration knob for one, so audit.db and
// its SQLite sidecars remain owner-only.
type auditDBPathHooks struct {
	chmodFile          func(*os.File, os.FileMode) error
	chmodPath          func(string, os.FileMode) error
	securePlatformFile func(*os.File, bool) error
	beforeSQLiteOpen   func(string) error
}

func (hooks auditDBPathHooks) withDefaults() auditDBPathHooks {
	if hooks.chmodFile == nil {
		hooks.chmodFile = func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }
	}
	if hooks.chmodPath == nil {
		hooks.chmodPath = os.Chmod
	}
	if hooks.securePlatformFile == nil {
		hooks.securePlatformFile = secureAuditDBPlatformFile
	}
	return hooks
}

// preparedAuditDatabasePath pins the validated filesystem leaf across the
// SQLite name-based open. validateAfterOpen proves the pathname still names
// that leaf and re-checks parents and auxiliary files before the pin is closed.
type preparedAuditDatabasePath struct {
	path        string
	pinned      *os.File
	securedMode os.FileMode
	hooks       auditDBPathHooks
	inMemory    bool
}

func (prepared *preparedAuditDatabasePath) close() {
	if prepared != nil && prepared.pinned != nil {
		_ = prepared.pinned.Close()
		prepared.pinned = nil
	}
}

// openHardenedAuditSQLite is the intended NewStore integration seam. It
// preserves the existing pool/pragma behavior in openSQLite while adding a
// fail-closed filesystem trust boundary around the lazy database/sql open.
func openHardenedAuditSQLite(dbPath string, hooks auditDBPathHooks) (*sql.DB, error) {
	db, _, err := openHardenedAuditSQLiteWithIdentity(dbPath, hooks)
	return db, err
}

// openHardenedAuditSQLiteWithIdentity also returns the exact normalized path
// passed to SQLite. Store retains that immutable identity for post-migration
// revalidation and runtime-plan binding instead of reinterpreting a relative
// constructor path after the process working directory changes.
func openHardenedAuditSQLiteWithIdentity(
	dbPath string,
	hooks auditDBPathHooks,
) (*sql.DB, string, error) {
	prepared, err := prepareAuditDatabasePath(dbPath, hooks)
	if err != nil {
		return nil, "", err
	}
	defer prepared.close()

	if prepared.inMemory {
		db, err := openSQLite(prepared.path)
		return db, prepared.path, err
	}
	if hooks.beforeSQLiteOpen != nil {
		if err := hooks.beforeSQLiteOpen(prepared.path); err != nil {
			return nil, "", fmt.Errorf("audit: pre-open path check: %w", err)
		}
	}
	db, err := openSQLite(prepared.path)
	if err != nil {
		return nil, "", err
	}
	// sql.Open is lazy. Ping forces SQLite's DSN pragmas and filesystem open
	// while the validated leaf remains pinned, making permission/open errors a
	// constructor failure instead of a later write-path surprise.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, "", fmt.Errorf("audit: verify database open %s: %w", prepared.path, err)
	}
	if err := prepared.validateAfterOpen(); err != nil {
		_ = db.Close()
		return nil, "", err
	}
	return db, prepared.path, nil
}

// revalidateHardenedAuditSQLite repeats the filesystem trust checks after
// migrations and the readiness write have created or reused WAL/SHM files.
// The SQLite connection remains open while the main leaf is pinned and every
// auxiliary path is checked.
func revalidateHardenedAuditSQLite(dbPath string, hooks auditDBPathHooks) error {
	prepared, err := prepareAuditDatabasePath(dbPath, hooks)
	if err != nil {
		return err
	}
	defer prepared.close()
	return prepared.validateAfterOpen()
}

func prepareAuditDatabasePath(path string, hooks auditDBPathHooks) (*preparedAuditDatabasePath, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("audit: database path is required")
	}
	// Keep the package's existing in-memory test contract without treating an
	// arbitrary SQLite URI/DSN as a trusted filesystem path.
	if path == ":memory:" {
		return &preparedAuditDatabasePath{path: path, hooks: hooks, inMemory: true}, nil
	}
	// openSQLite appends its pragma query to the filename. Reject a filename
	// that already contains the delimiter so the validated path cannot differ
	// from the resource SQLite opens.
	if strings.ContainsRune(path, '?') {
		return nil, errors.New("audit: database path contains an unsupported DSN delimiter")
	}

	hooks = hooks.withDefaults()
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, errors.New("audit: normalize database path")
	}
	if err := ensureTrustedAuditDBParents(filepath.Dir(absolute), hooks, true); err != nil {
		return nil, err
	}

	pinned, created, err := openPinnedAuditDBLeaf(absolute)
	if err != nil {
		return nil, err
	}
	prepared := &preparedAuditDatabasePath{
		path: absolute, pinned: pinned, hooks: hooks,
	}
	fail := func(err error) (*preparedAuditDatabasePath, error) {
		prepared.close()
		return nil, err
	}
	if created {
		if err := hooks.securePlatformFile(pinned, false); err != nil {
			return fail(err)
		}
	}

	info, err := pinned.Stat()
	if err != nil {
		return fail(fmt.Errorf("audit: inspect database file: %w", err))
	}
	if err := validateAuditDBLeaf(absolute, info); err != nil {
		return fail(err)
	}

	currentMode := info.Mode().Perm()
	targetMode := tightenedAuditDBFileMode(currentMode)
	if created {
		targetMode = 0o600
	}
	// Existing permissions can only be intersected with 0600. Startup must
	// never grant a bit the operator/previous install had removed.
	if created || targetMode != currentMode {
		if err := hooks.chmodFile(pinned, targetMode); err != nil {
			return fail(fmt.Errorf("audit: secure database file permissions: %w", err))
		}
	}
	if err := validatePinnedAuditDBLeaf(absolute, pinned); err != nil {
		return fail(err)
	}
	tightenedInfo, err := pinned.Stat()
	if err != nil {
		return fail(fmt.Errorf("audit: inspect secured database file: %w", err))
	}
	if !auditDBModeMatches(tightenedInfo, targetMode) {
		return fail(errors.New("audit: database file permissions could not be secured"))
	}
	if err := secureAuditDBSQLiteSidecars(absolute, hooks); err != nil {
		return fail(err)
	}
	prepared.securedMode = targetMode
	return prepared, nil
}

var auditDBSQLiteSidecarSuffixes = [...]string{"-wal", "-shm", "-journal"}

// secureAuditDBSQLiteSidecars handles leftovers from crashes and older
// constructors before SQLite is allowed to recover/reuse their raw pages.
func secureAuditDBSQLiteSidecars(databasePath string, hooks auditDBPathHooks) error {
	hooks = hooks.withDefaults()
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		path := databasePath + suffix
		before, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("audit: inspect SQLite sidecar %s: %w", suffix, err)
		}
		if err := validateAuditDBLeaf(path, before); err != nil {
			return fmt.Errorf("audit: unsafe SQLite sidecar %s: %w", suffix, err)
		}
		pinned, err := openAuditDBFileNoFollow(path, false)
		if err != nil {
			return fmt.Errorf("audit: open SQLite sidecar %s safely: %w", suffix, err)
		}
		closePinned := func() { _ = pinned.Close() }
		pinnedBefore, err := pinned.Stat()
		if err != nil {
			closePinned()
			return fmt.Errorf("audit: inspect pinned SQLite sidecar %s: %w", suffix, err)
		}
		if !os.SameFile(before, pinnedBefore) {
			closePinned()
			return fmt.Errorf("audit: SQLite sidecar %s changed before secure open", suffix)
		}
		if err := validateAuditDBLeaf(path, pinnedBefore); err != nil {
			closePinned()
			return fmt.Errorf("audit: unsafe pinned SQLite sidecar %s: %w", suffix, err)
		}

		targetMode := tightenedAuditDBFileMode(pinnedBefore.Mode().Perm())
		if targetMode != pinnedBefore.Mode().Perm() {
			if err := hooks.chmodFile(pinned, targetMode); err != nil {
				closePinned()
				return fmt.Errorf("audit: secure SQLite sidecar %s permissions: %w", suffix, err)
			}
		}
		if err := hooks.securePlatformFile(pinned, false); err != nil {
			closePinned()
			return fmt.Errorf("audit: secure SQLite sidecar %s platform ACL: %w", suffix, err)
		}
		pinnedAfter, err := pinned.Stat()
		if err != nil {
			closePinned()
			return fmt.Errorf("audit: re-inspect pinned SQLite sidecar %s: %w", suffix, err)
		}
		after, err := os.Lstat(path)
		if err != nil {
			closePinned()
			return fmt.Errorf("audit: re-inspect SQLite sidecar %s: %w", suffix, err)
		}
		if !os.SameFile(pinnedAfter, after) {
			closePinned()
			return fmt.Errorf("audit: SQLite sidecar %s changed during secure open", suffix)
		}
		if err := validateAuditDBLeaf(path, after); err != nil {
			closePinned()
			return fmt.Errorf("audit: unsafe SQLite sidecar %s after securing: %w", suffix, err)
		}
		if !auditDBModeMatches(pinnedAfter, targetMode) {
			closePinned()
			return fmt.Errorf("audit: SQLite sidecar %s permissions could not be secured", suffix)
		}
		closePinned()
	}
	return nil
}

func openPinnedAuditDBLeaf(path string) (*os.File, bool, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if err := validateAuditDBLeaf(path, info); err != nil {
			return nil, false, err
		}
		file, openErr := openAuditDBFileNoFollow(path, false)
		if openErr != nil {
			return nil, false, fmt.Errorf("audit: open existing database file safely: %w", openErr)
		}
		return file, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("audit: inspect database file: %w", err)
	}

	file, err := openAuditDBFileNoFollow(path, true)
	if err == nil {
		return file, true, nil
	}
	if !os.IsExist(err) {
		return nil, false, fmt.Errorf("audit: create database file safely: %w", err)
	}
	// Another creator won the race. Validate and open the winner without
	// following a substituted link.
	info, statErr := os.Lstat(path)
	if statErr != nil {
		return nil, false, fmt.Errorf("audit: inspect raced database file: %w", statErr)
	}
	if err := validateAuditDBLeaf(path, info); err != nil {
		return nil, false, err
	}
	file, err = openAuditDBFileNoFollow(path, false)
	if err != nil {
		return nil, false, fmt.Errorf("audit: open raced database file safely: %w", err)
	}
	return file, false, nil
}

func ensureTrustedAuditDBParents(parent string, hooks auditDBPathHooks, allowCreate bool) error {
	parent = filepath.Clean(parent)
	chain := make([]string, 0, 8)
	for current := parent; ; current = filepath.Dir(current) {
		chain = append(chain, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
	}
	for left, right := 0, len(chain)-1; left < right; left, right = left+1, right-1 {
		chain[left], chain[right] = chain[right], chain[left]
	}

	for _, directory := range chain {
		info, err := os.Lstat(directory)
		created := false
		if os.IsNotExist(err) {
			if !allowCreate {
				return errors.New("audit: database directory changed during secure open")
			}
			mkdirErr := os.Mkdir(directory, 0o700)
			if mkdirErr != nil && !os.IsExist(mkdirErr) {
				return fmt.Errorf("audit: create database directory: %w", mkdirErr)
			}
			created = mkdirErr == nil
			info, err = os.Lstat(directory)
		}
		if err != nil {
			return fmt.Errorf("audit: inspect database directory: %w", err)
		}
		if created {
			if err := secureAuditDBPlatformPath(directory, true); err != nil {
				return err
			}
			info, err = os.Lstat(directory)
			if err != nil {
				return fmt.Errorf("audit: re-inspect database directory: %w", err)
			}
		}
		if err := validateAuditDBDirectory(directory, info, directory != parent); err != nil {
			return err
		}
		if created {
			if err := hooks.chmodPath(directory, 0o700); err != nil {
				return fmt.Errorf("audit: secure database directory permissions: %w", err)
			}
			info, err = os.Lstat(directory)
			if err != nil {
				return fmt.Errorf("audit: re-inspect database directory: %w", err)
			}
			if !auditDBModeMatches(info, 0o700) {
				return errors.New("audit: new database directory permissions are not 0700")
			}
		}
	}
	return nil
}

func validateAuditDBDirectory(path string, info os.FileInfo, allowStickyWritableAncestor bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		if trustedAuditDBSystemDirectoryAlias(path, info) {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("audit: resolve trusted system directory alias: %w", err)
			}
			target, err := os.Stat(resolved)
			if err != nil {
				return fmt.Errorf("audit: inspect trusted system directory alias: %w", err)
			}
			return validateAuditDBDirectory(resolved, target, allowStickyWritableAncestor)
		}
		return errors.New("audit: database path contains a symbolic link")
	}
	if !info.IsDir() {
		return errors.New("audit: database parent is not a directory")
	}
	if err := validateAuditDBPlatformTrust(path, info, true, !allowStickyWritableAncestor); err != nil {
		return err
	}
	if !allowStickyWritableAncestor && !auditDBImmediateDirectoryModeTrusted(info) {
		return errors.New("audit: immediate database directory is group- or other-writable")
	}
	return nil
}

func validateAuditDBLeaf(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("audit: database file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("audit: database file must be regular")
	}
	return validateAuditDBPlatformTrust(path, info, false, true)
}

func validatePinnedAuditDBLeaf(path string, pinned *os.File) error {
	pinnedInfo, err := pinned.Stat()
	if err != nil {
		return fmt.Errorf("audit: inspect pinned database file: %w", err)
	}
	if err := validateAuditDBLeaf(path, pinnedInfo); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("audit: re-inspect database file: %w", err)
	}
	if err := validateAuditDBLeaf(path, pathInfo); err != nil {
		return err
	}
	if !os.SameFile(pinnedInfo, pathInfo) {
		return errors.New("audit: database file changed during secure open")
	}
	return nil
}

func (prepared *preparedAuditDatabasePath) validateAfterOpen() error {
	if prepared == nil {
		return errors.New("audit: secure database path handle is unavailable")
	}
	if prepared.inMemory {
		return nil
	}
	if prepared.pinned == nil {
		return errors.New("audit: secure database path handle is unavailable")
	}
	if err := ensureTrustedAuditDBParents(
		filepath.Dir(prepared.path), auditDBPathHooks{}.withDefaults(), false,
	); err != nil {
		return err
	}
	if err := validatePinnedAuditDBLeaf(prepared.path, prepared.pinned); err != nil {
		return err
	}
	info, err := prepared.pinned.Stat()
	if err != nil {
		return fmt.Errorf("audit: inspect database file after open: %w", err)
	}
	if !auditDBModeMatches(info, prepared.securedMode) {
		return errors.New("audit: database file permissions changed during secure open")
	}
	return secureAuditDBSQLiteSidecars(prepared.path, prepared.hooks)
}

func tightenedAuditDBFileMode(mode os.FileMode) os.FileMode {
	return mode.Perm() & 0o600
}
