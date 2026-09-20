// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

const (
	DefaultJSONLMaxSizeMB  = 50
	DefaultJSONLMaxBackups = 5
	DefaultJSONLMaxAgeDays = 30
	maintenanceEntryLimit  = 10_000
	backupNameAttempts     = 100
	maxRetentionDays       = 3_650_000 // 10,000 years; bounds date arithmetic.
)

// JSONLConfig is an already-compiled JSONL transport. Omitted source values are
// resolved by the config compiler to the exported defaults above. Zero
// MaxBackups or MaxAgeDays disables that pruning dimension; it does not disable
// the destination and does not silently restore a default.
type JSONLConfig struct {
	Path       string
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	Compress   bool
}

// DefaultJSONLConfig returns the documented v8 rotation defaults for path.
func DefaultJSONLConfig(path string) JSONLConfig {
	return JSONLConfig{
		Path: path, MaxSizeMB: DefaultJSONLMaxSizeMB,
		MaxBackups: DefaultJSONLMaxBackups, MaxAgeDays: DefaultJSONLMaxAgeDays,
		Compress: true,
	}
}

// JSONL is a synchronous, generation-owned delivery adapter. Rotation,
// compression, and retention cleanup run on the destination's dispatcher
// worker; no lumberjack/background goroutine survives generation Close.
type JSONL struct {
	config   JSONLConfig
	maxBytes int64
	gate     chan struct{}
	file     *os.File
	identity os.FileInfo
	size     int64
	closed   bool
	sequence atomic.Uint64
}

// NewJSONL performs path preparation, secure owner-only open, and bounded
// retention cleanup before a runtime graph can activate producer intake.
func NewJSONL(config JSONLConfig) (*JSONL, error) {
	if config.Path == "" || !filepath.IsAbs(config.Path) || config.MaxSizeMB <= 0 ||
		config.MaxBackups < 0 || config.MaxAgeDays < 0 || config.MaxAgeDays > maxRetentionDays ||
		int64(config.MaxSizeMB) > (int64(^uint64(0)>>1))/(1024*1024) {
		return nil, newError(ErrorInvalidConfig)
	}
	if err := prepareSecureParent(config.Path); err != nil {
		if isUnsafeFailure(err) {
			return nil, newError(ErrorUnsafePath)
		}
		return nil, newError(ErrorOpenFailed)
	}
	file, identity, size, err := secureOpenAppend(config.Path)
	if err != nil {
		if isUnsafeFailure(err) {
			return nil, newError(ErrorUnsafePath)
		}
		return nil, newError(ErrorOpenFailed)
	}
	adapter := &JSONL{
		config: config, maxBytes: int64(config.MaxSizeMB) * 1024 * 1024,
		gate: make(chan struct{}, 1), file: file, identity: identity, size: size,
	}
	adapter.gate <- struct{}{}
	if err := adapter.cleanupBackups(context.Background(), time.Now().UTC()); err != nil {
		_ = file.Close()
		if isUnsafeFailure(err) {
			return nil, newError(ErrorUnsafePath)
		}
		return nil, newError(ErrorOpenFailed)
	}
	return adapter, nil
}

// EncodedSize is exact: every projected byte is written unchanged and every
// record receives exactly one trailing newline.
func (*JSONL) EncodedSize(projectedSizes []int) (int, bool) {
	total := 0
	for _, size := range projectedSizes {
		if size < 0 || total > maxInt-size || total+size == maxInt {
			return 0, false
		}
		total += size + 1
	}
	return total, true
}

// Deliver appends exact projected bytes plus one newline in dispatcher FIFO
// order. It never parses, reclassifies, redacts, or reaches back to raw records.
func (adapter *JSONL) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil {
		return localResult(delivery.OutcomePermanentPayload)
	}
	estimate, ok := adapter.EncodedSize(batchSizes(batch))
	if !ok || estimate != batch.EncodedSize() {
		return localResult(delivery.OutcomePermanentPayload)
	}
	// Validate the complete batch before the first append. A malformed later
	// projection must not make an earlier record look ambiguously delivered,
	// and raw CR/LF must never inject an additional JSONL record.
	for _, item := range batch.Items() {
		projected := item.Bytes()
		if len(projected) == 0 || !utf8.Valid(projected) ||
			bytes.ContainsAny(projected, "\r\n") || !json.Valid(projected) {
			return localResult(delivery.OutcomePermanentPayload)
		}
	}
	if !adapter.lock(ctx) {
		return localResult(delivery.OutcomeTransient)
	}
	defer adapter.unlock()
	if adapter.closed {
		return localResult(delivery.OutcomePermanentPayload)
	}
	if err := adapter.ensureActive(); err != nil {
		return localFileFailure(err, false)
	}

	wroteAny := false
	for _, item := range batch.Items() {
		if err := ctx.Err(); err != nil {
			if wroteAny {
				return localResult(delivery.OutcomeAmbiguous)
			}
			return localResult(delivery.OutcomeTransient)
		}
		projected := item.Bytes()
		lineBytes := int64(len(projected) + 1)
		if adapter.size > 0 && (lineBytes > adapter.maxBytes || adapter.size > adapter.maxBytes-lineBytes) {
			if err := adapter.rotate(ctx); err != nil {
				return localFileFailure(err, wroteAny)
			}
		}
		line := make([]byte, len(projected)+1)
		copy(line, projected)
		line[len(projected)] = '\n'
		n, writeErr, rolledBack := appendJSONLLine(adapter.file, &adapter.size, line)
		if writeErr != nil || n != len(line) {
			// A failed rollback leaves an unterminated fragment at the leaf.
			// Fail this generation closed so the dispatcher's exact-byte retry
			// cannot concatenate a complete record onto that fragment.
			if n > 0 && !rolledBack {
				adapter.failClosedFile()
			}
			// Complete earlier records, a fully written current record whose
			// acknowledgement failed, or a fragment that could not be removed
			// all make final delivery ambiguous. A successfully removed first
			// fragment is a clean pre-delivery transient failure.
			if wroteAny || n == len(line) || n > 0 && !rolledBack {
				return localResult(delivery.OutcomeAmbiguous)
			}
			return localResult(delivery.OutcomeTransient)
		}
		wroteAny = true
	}
	return localResult(delivery.OutcomeDelivered)
}

type jsonlAppendFile interface {
	Write([]byte) (int, error)
	Truncate(int64) error
}

// appendJSONLLine performs one append and removes an incomplete write before
// the immutable batch can be retried. The caller serializes access to file and
// size. rolledBack is true only when bytes from this attempt were removed.
func appendJSONLLine(file jsonlAppendFile, size *int64, line []byte) (n int, err error, rolledBack bool) {
	if file == nil || size == nil {
		return 0, io.ErrClosedPipe, false
	}
	before := *size
	n, err = file.Write(line)
	if n < 0 || n > len(line) {
		return n, io.ErrShortWrite, false
	}
	if n > 0 {
		*size += int64(n)
	}
	if err == nil && n == len(line) {
		return n, nil, false
	}
	if n == 0 {
		if err == nil {
			err = io.ErrShortWrite
		}
		return n, err, false
	}
	if truncateErr := file.Truncate(before); truncateErr != nil {
		if err == nil {
			err = io.ErrShortWrite
		}
		return n, err, false
	}
	*size = before
	if err == nil {
		err = io.ErrShortWrite
	}
	return n, err, true
}

func (adapter *JSONL) failClosedFile() {
	if adapter == nil {
		return
	}
	if adapter.file != nil {
		_ = adapter.file.Close()
	}
	adapter.file = nil
	adapter.identity = nil
	adapter.closed = true
}

// Reopen synchronously closes and securely reopens the configured path. It is
// intended for explicit service reopen signals. Symlink, hard-link/alias,
// reparse-point, non-regular, permission, or ownership replacements are refused.
func (adapter *JSONL) Reopen(ctx context.Context) error {
	if adapter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorInvalidConfig)
	}
	if !adapter.lock(ctx) {
		return ctx.Err()
	}
	defer adapter.unlock()
	if adapter.closed {
		return newError(ErrorClosed)
	}
	if err := prepareSecureParent(adapter.config.Path); err != nil {
		if isUnsafeFailure(err) {
			return newError(ErrorUnsafePath)
		}
		return newError(ErrorOpenFailed)
	}
	if adapter.file != nil {
		_ = adapter.file.Sync()
		_ = adapter.file.Close()
		adapter.file = nil
		adapter.identity = nil
	}
	file, identity, size, err := secureOpenAppend(adapter.config.Path)
	if err != nil {
		if isUnsafeFailure(err) {
			return newError(ErrorUnsafePath)
		}
		return newError(ErrorOpenFailed)
	}
	adapter.file, adapter.identity, adapter.size = file, identity, size
	return nil
}

// Close releases the file owned by this runtime generation. It is idempotent
// and retryable when the context expires while an in-flight delivery owns it.
func (adapter *JSONL) Close(ctx context.Context) error {
	if adapter == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorInvalidConfig)
	}
	if !adapter.lock(ctx) {
		return ctx.Err()
	}
	defer adapter.unlock()
	if adapter.closed {
		return nil
	}
	adapter.closed = true
	if adapter.file == nil {
		return nil
	}
	syncErr := adapter.file.Sync()
	if err := adapter.file.Close(); err != nil {
		adapter.closed = false
		return newError(ErrorOpenFailed)
	}
	adapter.file = nil
	adapter.identity = nil
	if syncErr != nil {
		return newError(ErrorOpenFailed)
	}
	return nil
}

func (adapter *JSONL) lock(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-adapter.gate:
		return true
	}
}

func (adapter *JSONL) unlock() { adapter.gate <- struct{}{} }

func (adapter *JSONL) ensureActive() error {
	if adapter.file != nil {
		same, err := securePathMatches(adapter.config.Path, adapter.file, adapter.identity)
		if err == nil && same {
			return nil
		}
		_ = adapter.file.Sync()
		_ = adapter.file.Close()
		adapter.file, adapter.identity = nil, nil
		if err != nil && isUnsafeFailure(err) {
			return err
		}
	}
	file, identity, size, err := secureOpenAppend(adapter.config.Path)
	if err != nil {
		return err
	}
	adapter.file, adapter.identity, adapter.size = file, identity, size
	return nil
}

func (adapter *JSONL) rotate(ctx context.Context) error {
	if adapter.file == nil {
		return ioFailure()
	}
	same, err := securePathMatches(adapter.config.Path, adapter.file, adapter.identity)
	if err != nil || !same {
		if err != nil {
			return err
		}
		return unsafeFailure()
	}
	if err := adapter.file.Sync(); err != nil {
		return ioFailure()
	}
	if err := adapter.file.Close(); err != nil {
		return ioFailure()
	}
	adapter.file, adapter.identity = nil, nil

	backup, err := adapter.reserveBackupName(time.Now().UTC())
	if err != nil {
		return err
	}
	if err := secureMoveNoReplace(adapter.config.Path, backup); err != nil {
		return ioFailure()
	}
	file, identity, size, openErr := secureOpenAppend(adapter.config.Path)
	if openErr == nil {
		adapter.file, adapter.identity, adapter.size = file, identity, size
	}
	if adapter.config.Compress {
		if err := compressSecureFile(ctx, backup); err != nil {
			if openErr != nil {
				return openErr
			}
			return err
		}
	}
	if err := adapter.cleanupBackups(ctx, time.Now().UTC()); err != nil {
		if openErr != nil {
			return openErr
		}
		return err
	}
	return openErr
}

func (adapter *JSONL) reserveBackupName(now time.Time) (string, error) {
	stamp := strconv.FormatInt(now.UnixNano(), 10)
	for attempt := 0; attempt < backupNameAttempts; attempt++ {
		sequence := adapter.sequence.Add(1)
		candidate := adapter.config.Path + "." + stamp + "." + strconv.FormatUint(sequence, 10)
		_, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			if !adapter.config.Compress {
				return candidate, nil
			}
			if _, gzipErr := os.Lstat(candidate + ".gz"); os.IsNotExist(gzipErr) {
				return candidate, nil
			} else if gzipErr != nil {
				return "", ioFailure()
			}
			continue
		}
		if err != nil {
			return "", ioFailure()
		}
	}
	return "", ioFailure()
}

type backupFile struct {
	path    string
	modTime time.Time
}

func (adapter *JSONL) cleanupBackups(ctx context.Context, now time.Time) error {
	if adapter.config.MaxBackups == 0 && adapter.config.MaxAgeDays == 0 {
		return nil
	}
	directory := filepath.Dir(adapter.config.Path)
	entries, err := readBoundedDirectory(directory)
	if err != nil {
		return ioFailure()
	}
	prefix := filepath.Base(adapter.config.Path) + "."
	backups := make([]backupFile, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return ioFailure()
		}
		if !strings.HasPrefix(entry.Name(), prefix) || !isJSONLBackupName(prefix, entry.Name()) {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return ioFailure()
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return unsafeFailure()
		}
		if err := validateSecureFileInfo(info); err != nil {
			return err
		}
		backups = append(backups, backupFile{path: path, modTime: info.ModTime()})
	}
	sort.Slice(backups, func(left, right int) bool {
		if backups[left].modTime.Equal(backups[right].modTime) {
			return backups[left].path < backups[right].path
		}
		return backups[left].modTime.Before(backups[right].modTime)
	})
	remove := make(map[string]struct{})
	if adapter.config.MaxAgeDays > 0 {
		cutoff := now.AddDate(0, 0, -adapter.config.MaxAgeDays)
		for _, backup := range backups {
			if backup.modTime.Before(cutoff) {
				remove[backup.path] = struct{}{}
			}
		}
	}
	if adapter.config.MaxBackups > 0 {
		retained := 0
		for index := len(backups) - 1; index >= 0; index-- {
			if _, aged := remove[backups[index].path]; aged {
				continue
			}
			retained++
			if retained > adapter.config.MaxBackups {
				remove[backups[index].path] = struct{}{}
			}
		}
	}
	for _, backup := range backups {
		if _, shouldRemove := remove[backup.path]; !shouldRemove {
			continue
		}
		if err := os.Remove(backup.path); err != nil && !os.IsNotExist(err) {
			return ioFailure()
		}
	}
	return nil
}

func readBoundedDirectory(path string) ([]os.DirEntry, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	entries := make([]os.DirEntry, 0, 256)
	for {
		batch, readErr := directory.ReadDir(256)
		if len(entries) > maintenanceEntryLimit-len(batch) {
			return nil, ioFailure()
		}
		entries = append(entries, batch...)
		if errors.Is(readErr, io.EOF) {
			return entries, nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func isJSONLBackupName(prefix, name string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if strings.HasSuffix(suffix, ".gz") {
		suffix = strings.TrimSuffix(suffix, ".gz")
	}
	parts := strings.Split(suffix, ".")
	if len(parts) != 2 {
		return false
	}
	stamp, stampErr := strconv.ParseInt(parts[0], 10, 64)
	sequence, sequenceErr := strconv.ParseUint(parts[1], 10, 64)
	return stampErr == nil && stamp > 0 && sequenceErr == nil && sequence > 0
}

func compressSecureFile(ctx context.Context, sourcePath string) error {
	source, _, err := secureOpenRead(sourcePath)
	if err != nil {
		return err
	}
	defer source.Close()
	destinationPath := sourcePath + ".gz"
	destination, err := secureCreateExclusive(destinationPath)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		_ = destination.Close()
		if !keep {
			_ = os.Remove(destinationPath)
		}
	}()
	compressor, err := gzip.NewWriterLevel(destination, gzip.BestSpeed)
	if err != nil {
		return ioFailure()
	}
	buffer := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			_ = compressor.Close()
			return ioFailure()
		}
		count, readErr := source.Read(buffer)
		if count > 0 {
			if _, err := compressor.Write(buffer[:count]); err != nil {
				_ = compressor.Close()
				return ioFailure()
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			_ = compressor.Close()
			return ioFailure()
		}
	}
	if err := compressor.Close(); err != nil {
		return ioFailure()
	}
	if err := destination.Sync(); err != nil {
		return ioFailure()
	}
	if err := destination.Close(); err != nil {
		return ioFailure()
	}
	keep = true
	if err := os.Remove(sourcePath); err != nil {
		return ioFailure()
	}
	return nil
}

func localFileFailure(err error, wroteAny bool) delivery.DeliveryResult {
	if wroteAny {
		return localResult(delivery.OutcomeAmbiguous)
	}
	if isUnsafeFailure(err) {
		return localResult(delivery.OutcomePermanentPayload)
	}
	return localResult(delivery.OutcomeTransient)
}
