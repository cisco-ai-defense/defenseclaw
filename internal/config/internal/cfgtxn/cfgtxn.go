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
	"regexp"
	"strconv"
	"time"
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

// GenerationState is config.generation.json.
type GenerationState struct {
	// Generation is monotonic; a writer that finds the file missing or
	// corrupt starts from max(previous+1, 1) and sets GenerationReset.
	Generation   uint64 `json:"generation"`
	ConfigSHA256 string `json:"config_sha256"`
	Actor        string `json:"actor"`
	Reason       string `json:"reason,omitempty"`
	// WrittenAt is RFC 3339 UTC.
	WrittenAt       string `json:"written_at"`
	GenerationReset bool   `json:"generation_reset,omitempty"`
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

var generationCounter = regexp.MustCompile(`"generation"\s*:\s*([0-9]{1,20})`)

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
}

// Begin takes the writer lock for configPath, waiting up to timeout (zero
// means DefaultLockTimeout). The config directory must exist.
func Begin(ctx context.Context, configPath string, timeout time.Duration) (*Txn, error) {
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("configwrite: resolve %s: %w", configPath, err)
	}
	lock, err := openLockFile(LockPath(abs))
	if err != nil {
		return nil, fmt.Errorf("configwrite: open %s: %w", LockPath(abs), err)
	}
	deadline := time.Now().Add(timeout)
	for {
		busy, lockErr := tryLock(lock)
		if lockErr != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("configwrite: lock %s: %w", LockPath(abs), lockErr)
		}
		if !busy {
			return &Txn{path: abs, lock: lock}, nil
		}
		if time.Now().After(deadline) {
			_ = lock.Close()
			return nil, ErrLockBusy
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, ctx.Err()
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
// full disk before the generation file), the previous bytes are put back so
// the error means nothing changed; if that restore fails too, the error says
// config.yaml holds the new bytes.
func (t *Txn) Commit(candidate []byte, mode os.FileMode, actor, reason string) (GenerationState, error) {
	if t == nil || t.lock == nil {
		return GenerationState{}, errors.New("configwrite: commit without the writer lock")
	}
	previous, readErr := os.ReadFile(t.path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return GenerationState{}, fmt.Errorf("configwrite: read previous config %s: %w", t.path, readErr)
	}
	existed := readErr == nil
	if err := WriteFileDurable(t.path, candidate, mode); err != nil {
		return GenerationState{}, t.undoCommit(err, candidate, previous, existed, mode)
	}
	state, err := t.RecordGeneration(SHA256Hex(candidate), actor, reason)
	if err != nil {
		return GenerationState{}, t.undoCommit(err, candidate, previous, existed, mode)
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
func (t *Txn) RecordGeneration(configSHA256, actor, reason string) (GenerationState, error) {
	if t == nil || t.lock == nil {
		return GenerationState{}, errors.New("configwrite: generation update without the writer lock")
	}
	next := GenerationState{
		ConfigSHA256: configSHA256,
		Actor:        actor,
		Reason:       reason,
		WrittenAt:    time.Now().UTC().Format(time.RFC3339),
	}
	previous, err := ReadGenerationState(t.path)
	switch {
	case err == nil:
		next.Generation = previous.Generation + 1
	default:
		// Missing or corrupt: say so. A corrupt file may still carry a
		// readable counter (ReadGenerationState salvages it); never go
		// backwards from it.
		next.Generation = 1
		next.GenerationReset = true
		if previous.Generation > 0 {
			next.Generation = previous.Generation + 1
		}
	}
	encoded, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return GenerationState{}, fmt.Errorf("configwrite: encode %s: %w", GenerationFileName, err)
	}
	encoded = append(encoded, '\n')
	if err := WriteFileDurable(GenerationPath(t.path), encoded, 0o600); err != nil {
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
	if err := replaceDurable(tmpName, path); err != nil {
		return fmt.Errorf("configwrite: replace %s: %w", path, err)
	}
	committed = true
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("configwrite: fsync directory %s: %w", dir, err)
	}
	return nil
}
