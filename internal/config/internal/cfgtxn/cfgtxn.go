// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package cfgtxn holds the file-level steps of the config.yaml writer
// protocol: the shared config.yaml.lock, the durable atomic replace and the
// config.generation.json counter. It imports nothing from internal/config so
// both the config package (migrations) and configwrite can use it; the
// public API is internal/config/configwrite.
package cfgtxn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

const (
	// LockSuffix is appended to the config path for the writer lock.
	LockSuffix = ".lock"
	// GenerationFileName is the writer's state file, next to config.yaml.
	GenerationFileName = "config.generation.json"
	// DefaultLockTimeout bounds the wait for another writer.
	DefaultLockTimeout = 10 * time.Second
)

// ErrLockBusy means another writer held the lock past the timeout.
var ErrLockBusy = errors.New("configwrite: another DefenseClaw process is changing config.yaml")

// ErrFileLockBusy means another writer held a file's sibling lock past the
// timeout (LockFile).
var ErrFileLockBusy = errors.New("configwrite: another DefenseClaw process is changing the file")

// ErrConflict means the file changed after the transaction read it.
var ErrConflict = errors.New("configwrite: config.yaml changed since it was read")

// afterPublicationError marks an error that occurred after config.yaml was
// replaced, even when Commit put the previous bytes back before returning.
// The caller must reconcile the running gateway, which may have loaded the
// candidate during that interval. An error before the rename must never
// trigger that reconciliation.
type afterPublicationError struct{ error }

func (e afterPublicationError) Unwrap() error { return e.error }

// AfterPublication preserves that config.yaml was published before err.
func AfterPublication(err error) error {
	if err == nil || PublicationOccurred(err) {
		return err
	}
	return afterPublicationError{err}
}

// PublicationOccurred reports whether err follows a config.yaml rename.
func PublicationOccurred(err error) bool {
	var published afterPublicationError
	return errors.As(err, &published)
}

// GenerationState is config.generation.json.
type GenerationState struct {
	// Generation is monotonic; a writer that finds the file missing or
	// corrupt starts from max(previous+1, 1) and sets GenerationReset.
	Generation   uint64 `json:"generation"`
	ConfigSHA256 string `json:"config_sha256"`
	Actor        string `json:"actor"`
	LocalActor   string `json:"local_actor,omitempty"`
	Reason       string `json:"reason,omitempty"`
	// WrittenAt is RFC 3339 UTC.
	WrittenAt       string `json:"written_at"`
	GenerationReset bool   `json:"generation_reset,omitempty"`
	// BundleID, BundleVersion and SignerKeyID name the signed policy bundle
	// whose config the enterprise lifecycle installed in this generation;
	// absent for every other writer.
	BundleID      string `json:"bundle_id,omitempty"`
	BundleVersion uint64 `json:"bundle_version,omitempty"`
	SignerKeyID   string `json:"signer_key_id,omitempty"`
	// BundleDir is the name of the store version directory that holds this
	// bundle (1.0.6). The bundle store is not listable by the gateway's
	// service account on Linux and macOS, so the signed-activation check
	// opens this directory by name. Absent on a record an earlier build
	// wrote.
	BundleDir string `json:"bundle_dir,omitempty"`
	// Transaction* identifies the attempted bundle on a rollback generation.
	// Bundle* above continues to identify the policy that is now enforcing.
	TransactionActor         string `json:"transaction_actor,omitempty"`
	TransactionBundleID      string `json:"transaction_bundle_id,omitempty"`
	TransactionBundleVersion uint64 `json:"transaction_bundle_version,omitempty"`
	TransactionSignerKeyID   string `json:"transaction_signer_key_id,omitempty"`
	TransactionSummary       string `json:"transaction_summary,omitempty"`
}

// Writer is who records a generation and why, and the policy bundle it
// installs (only the enterprise lifecycle sets the bundle fields).
type Writer struct {
	GenerationFloor          uint64
	Actor                    string
	LocalActor               string
	Reason                   string
	BundleID                 string
	BundleVersion            uint64
	SignerKeyID              string
	BundleDir                string
	TransactionActor         string
	TransactionBundleID      string
	TransactionBundleVersion uint64
	TransactionSignerKeyID   string
	TransactionSummary       string
}

// LockPath returns the writer lock path for a config path.
func LockPath(configPath string) string { return configPath + LockSuffix }

// GenerationPath returns the config.generation.json path for a config path.
func GenerationPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), GenerationFileName)
}

// ReadGenerationState reads config.generation.json next to configPath. A
// missing file returns os.ErrNotExist (wrapped).
func ReadGenerationState(configPath string) (GenerationState, error) {
	raw, err := os.ReadFile(GenerationPath(configPath))
	if err != nil {
		return GenerationState{}, err
	}
	var state GenerationState
	if err := json.Unmarshal(raw, &state); err != nil {
		// A truncated or hand-broken file may still carry its counter. Return
		// it with the error so the next writer never goes backwards.
		return GenerationState{Generation: salvageGeneration(raw)},
			fmt.Errorf("configwrite: decode %s: %w", GenerationFileName, err)
	}
	return state, nil
}

var generationCounter = lazyregexp.New(`"generation"\s*:\s*([0-9]{1,20})`)

// salvageGeneration reads the "generation" counter out of bytes that are
// not valid JSON. It returns 0 when there is none.
func salvageGeneration(raw []byte) uint64 {
	m := generationCounter.FindSubmatch(raw)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseUint(string(m[1]), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// SHA256Hex is the hex sha256 the writer records for config bytes.
func SHA256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Txn holds config.yaml.lock for one read/modify/write cycle.
type Txn struct {
	path string
	lock *os.File
	// generationWrite permits a transaction-local durability fault in tests.
	generationWrite func(string, []byte, os.FileMode) error
}

// Begin takes the writer lock for configPath, waiting up to timeout (zero
// means DefaultLockTimeout). The config directory must exist.
func Begin(ctx context.Context, configPath string, timeout time.Duration) (*Txn, error) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("configwrite: resolve %s: %w", configPath, err)
	}
	lock, busy, err := acquireLock(ctx, LockPath(abs), timeout)
	if err != nil {
		return nil, err
	}
	if busy {
		return nil, ErrLockBusy
	}
	return &Txn{path: abs, lock: lock}, nil
}

// LockFile takes path's sibling lock, path+".lock", the sentinel that
// Python's file_lock.locked_file_update takes for the same file (the .env
// writers of keys set and setup use it). It waits up to timeout (zero means
// DefaultLockTimeout); the directory must exist. A writer that also holds
// config.yaml.lock takes that one first. release drops the lock.
func LockFile(ctx context.Context, path string, timeout time.Duration) (release func(), err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("configwrite: resolve %s: %w", path, err)
	}
	lock, busy, err := acquireLock(ctx, abs+LockSuffix, timeout)
	if err != nil {
		return nil, err
	}
	if busy {
		return nil, fmt.Errorf("%w: %s", ErrFileLockBusy, abs)
	}
	return func() {
		unlock(lock)
		_ = lock.Close()
	}, nil
}

// acquireLock opens lockPath and takes it, waiting up to timeout (zero
// means DefaultLockTimeout). busy reports a lock still held at the deadline.
func acquireLock(ctx context.Context, lockPath string, timeout time.Duration) (lock *os.File, busy bool, err error) {
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	lock, err = openLockFile(lockPath)
	if err != nil {
		return nil, false, fmt.Errorf("configwrite: open %s: %w", lockPath, err)
	}
	deadline := time.Now().Add(timeout)
	for {
		held, lockErr := tryLock(lock)
		if lockErr != nil {
			_ = lock.Close()
			return nil, false, fmt.Errorf("configwrite: lock %s: %w", lockPath, lockErr)
		}
		if !held {
			return lock, false, nil
		}
		if time.Now().After(deadline) {
			_ = lock.Close()
			return nil, true, nil
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, false, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Path is the absolute config path the transaction locks.
func (t *Txn) Path() string { return t.path }

// Close releases the lock. It is safe to call more than once.
func (t *Txn) Close() error {
	if t == nil || t.lock == nil {
		return nil
	}
	unlock(t.lock)
	err := t.lock.Close()
	t.lock = nil
	return err
}

// Read returns the current config bytes and mode. A missing file returns
// nil bytes, mode 0600 and exists=false.
func (t *Txn) Read() (raw []byte, mode os.FileMode, exists bool, err error) {
	info, err := os.Lstat(t.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0o600, false, nil
		}
		return nil, 0, false, fmt.Errorf("configwrite: stat %s: %w", t.path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("configwrite: refusing to edit %s through a symbolic link", t.path)
	}
	if !info.Mode().IsRegular() {
		return nil, 0, false, fmt.Errorf("configwrite: %s is not a regular file", t.path)
	}
	raw, err = os.ReadFile(t.path)
	if err != nil {
		return nil, 0, false, fmt.Errorf("configwrite: read %s: %w", t.path, err)
	}
	return raw, info.Mode().Perm(), true, nil
}

// Commit replaces config.yaml with candidate (durably) and then advances
// config.generation.json. The lock must still be held. When either step
// fails after the new bytes reached config.yaml (a failed directory fsync, a
// full disk before the generation file), the previous bytes are put back and
// the error records that a gateway might have loaded the candidate. If that
// restore fails too, the error says config.yaml holds the new bytes.
func (t *Txn) Commit(expected, candidate []byte, expectedExists bool, mode os.FileMode, w Writer) (GenerationState, error) {
	if t == nil || t.lock == nil {
		return GenerationState{}, errors.New("configwrite: commit without the writer lock")
	}
	previous, readErr := os.ReadFile(t.path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return GenerationState{}, fmt.Errorf("configwrite: read previous config %s: %w", t.path, readErr)
	}
	existed := readErr == nil
	if existed != expectedExists || !bytes.Equal(previous, expected) {
		return GenerationState{}, ErrConflict
	}
	if err := WriteFileDurable(t.path, candidate, mode); err != nil {
		if !PublicationOccurred(err) {
			return GenerationState{}, err
		}
		return GenerationState{}, AfterPublication(t.undoCommit(err, candidate, previous, existed, mode))
	}
	state, err := t.RecordGeneration(SHA256Hex(candidate), w)
	if err != nil {
		return GenerationState{}, AfterPublication(t.undoCommit(err, candidate, previous, existed, mode))
	}
	return state, nil
}

// undoCommit restores the previous config.yaml after a failed Commit when the
// candidate bytes are on disk, and returns cause (annotated if the restore
// failed too).
func (t *Txn) undoCommit(cause error, candidate, previous []byte, existed bool, mode os.FileMode) error {
	onDisk, err := os.ReadFile(t.path)
	if err != nil || !bytes.Equal(onDisk, candidate) {
		return cause
	}
	var restoreErr error
	if existed {
		restoreErr = WriteFileDurable(t.path, previous, mode)
	} else {
		restoreErr = os.Remove(t.path)
	}
	if restoreErr != nil {
		return fmt.Errorf("%w; config.yaml now holds the new bytes and the previous ones could not be restored: %v", cause, restoreErr)
	}
	return cause
}

// RecordGeneration advances config.generation.json for bytes that are
// already on disk (a writer that installs the file itself, such as the
// enterprise lifecycle). The lock must still be held.
func (t *Txn) RecordGeneration(configSHA256 string, w Writer) (GenerationState, error) {
	if t == nil || t.lock == nil {
		return GenerationState{}, errors.New("configwrite: generation update without the writer lock")
	}
	next := GenerationState{
		ConfigSHA256:             configSHA256,
		Actor:                    w.Actor,
		LocalActor:               w.LocalActor,
		Reason:                   w.Reason,
		WrittenAt:                time.Now().UTC().Format(time.RFC3339),
		BundleID:                 w.BundleID,
		BundleVersion:            w.BundleVersion,
		SignerKeyID:              w.SignerKeyID,
		BundleDir:                w.BundleDir,
		TransactionActor:         w.TransactionActor,
		TransactionBundleID:      w.TransactionBundleID,
		TransactionBundleVersion: w.TransactionBundleVersion,
		TransactionSignerKeyID:   w.TransactionSignerKeyID,
		TransactionSummary:       w.TransactionSummary,
	}
	previous, err := ReadGenerationState(t.path)
	if err != nil {
		// Preserve a salvageable counter and any live counter the lifecycle
		// proved before stopping the gateway.
		next.GenerationReset = true
	}
	previousCounter := max(previous.Generation, w.GenerationFloor)
	if previousCounter == ^uint64(0) {
		return GenerationState{}, errors.New("configwrite: generation counter exhausted; restore the last verified generation record before retrying")
	}
	next.Generation = previousCounter + 1
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return GenerationState{}, fmt.Errorf("configwrite: encode %s: %w", GenerationFileName, err)
	}
	encoded = append(encoded, '\n')
	path := GenerationPath(t.path)
	before, readErr := os.ReadFile(path)
	existed := readErr == nil
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return GenerationState{}, fmt.Errorf("configwrite: read %s before update: %w", path, readErr)
	}
	// An existing record keeps its read access: the enterprise lifecycle
	// gives it to the service group (0640), and a literal 0600 took that
	// away on every update (p0 GAP-1153). Write and execute bits for group
	// and other are never kept.
	mode := os.FileMode(0o600)
	if existed {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return GenerationState{}, fmt.Errorf("configwrite: stat %s before update: %w", path, statErr)
		}
		mode = info.Mode().Perm() & 0o644
	}
	write := t.generationWrite
	if write == nil {
		write = WriteFileDurable
	}
	if err := write(path, encoded, mode); err != nil {
		// WriteFileDurable may have renamed the file before a directory fsync
		// failed. Put the old record back before Commit restores config.yaml.
		current, currentErr := os.ReadFile(path)
		changed := currentErr == nil && (!existed || !bytes.Equal(current, before))
		if errors.Is(currentErr, os.ErrNotExist) && existed {
			changed = true
		} else if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
			return GenerationState{}, fmt.Errorf("%w; cannot inspect generation rollback: %v", err, currentErr)
		}
		if changed {
			var restoreErr error
			if existed {
				restoreErr = WriteFileDurable(path, before, mode)
			} else {
				restoreErr = os.Remove(path)
				if restoreErr == nil {
					restoreErr = syncDir(filepath.Dir(path))
				}
			}
			if restoreErr != nil {
				return GenerationState{}, fmt.Errorf("%w; generation record could not be restored: %v", err, restoreErr)
			}
		}
		return GenerationState{}, err
	}
	return next, nil
}

// WriteFileDurable replaces path with data: an exclusive temp file in the
// same directory with the target mode (and, when running as root on POSIX,
// the previous owner), fsync, an atomic rename (MoveFileExW with
// write-through on Windows), then an fsync of the directory on POSIX. A
// failed directory fsync is an error.
func WriteFileDurable(path string, data []byte, mode os.FileMode) error {
	return WriteFileDurablePublished(path, data, mode, nil)
}

// SyncDir flushes dir so a new entry in it is durable (fsync on POSIX; a
// no-op on Windows, where NTFS journals the directory).
func SyncDir(dir string) error { return syncDir(dir) }

// SyncFile flushes path, its owner and access included.
func SyncFile(path string) error { return syncFile(path) }

// MkdirDurable makes dir, whose parent exists, a folder whose entry
// survives a power loss before it returns: on POSIX a mkdir and an fsync
// of the parent, which a folder already there gets too; on Windows, where
// a folder has no flush of its own (syncDir), a temp folder beside it moved
// into place with MOVEFILE_WRITE_THROUGH (mkdirDurable). Anything else at
// dir is an error.
func MkdirDurable(dir string) error {
	if err := mkdirDurable(dir); err != nil {
		if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
			return fmt.Errorf("configwrite: make folder %s: %w", dir, err)
		}
	}
	if err := syncDir(filepath.Dir(dir)); err != nil {
		return fmt.Errorf("configwrite: fsync directory %s: %w", filepath.Dir(dir), err)
	}
	return nil
}

// syncPublished flushes the temp file again after publish changed its
// owner and access, so the rename never makes durable a file whose access
// a power loss can take back. A test replaces it.
var syncPublished = syncFile

// WriteFileDurablePublished is WriteFileDurable with publish run on the
// written and closed temp file before the rename, to give it its final
// owner and access: path never exists with the temp file's. The temp file
// is flushed again after publish, before the rename. A publish error
// removes the temp file and leaves path as it was.
func WriteFileDurablePublished(path string, data []byte, mode os.FileMode, publish func(tmp string) error) error {
	if mode == 0 {
		mode = 0o600
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("configwrite: temp file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode.Perm()); err != nil {
		return fmt.Errorf("configwrite: chmod %s: %w", tmpName, err)
	}
	keepOwner(tmp, path)
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("configwrite: write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("configwrite: fsync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("configwrite: close %s: %w", tmpName, err)
	}
	if publish != nil {
		if err := publish(tmpName); err != nil {
			return err
		}
		if err := syncPublished(tmpName); err != nil {
			return fmt.Errorf("configwrite: fsync %s after publish: %w", tmpName, err)
		}
	}
	if err := replaceDurable(tmpName, path); err != nil {
		return fmt.Errorf("configwrite: replace %s: %w", path, err)
	}
	committed = true
	if err := syncDir(dir); err != nil {
		return AfterPublication(fmt.Errorf("configwrite: fsync directory %s: %w", dir, err))
	}
	return nil
}
