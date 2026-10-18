// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//go:build windows

package connector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const atomicTransformV2MaxEABytes = 64 << 10

type atomicTransformEACopyability uint8

const (
	atomicTransformEAUnknown atomicTransformEACopyability = iota
	atomicTransformEACopyable
	atomicTransformEAUnsupportedKernel
)

var atomicTransformV2BackupWriteW = windows.NewLazySystemDLL("kernel32.dll").NewProc("BackupWrite")

func atomicTransformV2AllocationExpectedEA(dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt) (*atomicTransformV2WindowsMetadataStream, error) {
	name := filepath.Base(receipt.TargetPath)
	old, err := openAtomicTransformBoundFilePlatform(dir.file, name, false)
	if err != nil {
		return nil, err
	}
	defer old.Close()
	state, err := atomicTransformBoundStateFromOpen(old, name, atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformV2StateMatches(receipt.Old, state, true) || !atomicTransformV2PublishedMetadataMatches(receipt, state) {
		return nil, fmt.Errorf("prior config changed before allocation EA recovery: %w", errors.Join(err, errAtomicTransformConflict))
	}
	witness, err := atomicTransformV2WindowsMetadataFromOpen(old)
	if err != nil || witness.Digest != state.metadataDigest || witness.EACopyability != atomicTransformEACopyable {
		return nil, fmt.Errorf("prior EA source changed during allocation recovery: %w", errors.Join(err, errAtomicTransformConflict))
	}
	for _, stream := range witness.PreservedStreams {
		if stream.ID == 2 {
			return &stream, nil
		}
	}
	return nil, nil
}

func preserveAtomicTransformV2StageEA(dir *atomicTransformBoundDirectory, receipt atomicTransformV2Receipt, stage *os.File) error {
	old, err := openAtomicTransformBoundFilePlatform(dir.file, filepath.Base(receipt.TargetPath), false)
	if err != nil {
		return err
	}
	defer old.Close()
	state, err := atomicTransformBoundStateFromOpen(old, filepath.Base(receipt.TargetPath), atomicTransformMaxConfigBytes)
	if err != nil || !atomicTransformV2StateMatches(receipt.Old, state, true) {
		return fmt.Errorf("prior config changed before EA staging: %w", errors.Join(err, errAtomicTransformConflict))
	}
	if !atomicTransformV2PublishedMetadataMatches(receipt, state) {
		return fmt.Errorf("prior config EA witness changed before staging: %w", errAtomicTransformConflict)
	}
	return atomicTransformV2WindowsPreserveEA(old, stage, atomicTransformV2WindowsMetadataWitness{
		Digest: state.metadataDigest, EACopyability: atomicTransformEACopyable,
	})
}

// atomicTransformV2WindowsPreserveEA copies only the bounded, witnessed EA
// stream onto an already-bound private Stage handle. ReplaceFileW does not
// promise EA preservation. This must run before Stage receipt publication or
// any operation on the live target. No privilege is enabled and ACL, ADS,
// object-ID, link or primary-content backup streams are never written.
func atomicTransformV2WindowsPreserveEA(oldFile, stageFile *os.File, expectedOld atomicTransformV2WindowsMetadataWitness) error {
	if expectedOld.EACopyability != atomicTransformEACopyable {
		return errors.New("expected old EA source is not explicitly copyable")
	}
	if expectedOld.Digest == "" {
		return fmt.Errorf("old EA source witness is absent: %w", errAtomicTransformConflict)
	}
	before, err := atomicTransformV2WindowsMetadataFromOpen(oldFile)
	if err != nil {
		return fmt.Errorf("witness old EA source: %w", err)
	}
	if before.EACopyability != atomicTransformEACopyable {
		return errors.New("observed old EA source is not copyable")
	}
	if before.Digest != expectedOld.Digest {
		return fmt.Errorf("old EA source changed before staging: %w", errAtomicTransformConflict)
	}
	stageBefore, err := atomicTransformV2WindowsMetadataFromOpen(stageFile)
	if err != nil {
		return fmt.Errorf("witness EA staging handle: %w", err)
	}
	if stageBefore.EACopyability != atomicTransformEACopyable {
		return errors.New("observed EA staging handle is not copyable")
	}
	if before.Identity == stageBefore.Identity {
		return errors.New("EA staging must use a distinct owned inode")
	}
	reader := &atomicTransformV2BackupReader{file: oldFile}
	payload, stream, readErr := atomicTransformV2ReadEAStream(reader)
	closeErr := reader.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return fmt.Errorf("read bounded witnessed EA source: %w", err)
	}
	if !atomicTransformV2EAMatchesWitness(stream, before.Streams) {
		return fmt.Errorf("old EA source changed during reading: %w", errAtomicTransformConflict)
	}
	preservedPayload, err := atomicTransformV2CanonicalPreservedEA(payload)
	if err != nil {
		return fmt.Errorf("classify witnessed EA preservation: %w", err)
	}
	preservedStream := atomicTransformV2EAStreamForPayload(preservedPayload)
	afterRead, err := atomicTransformV2WindowsMetadataFromOpen(oldFile)
	if err != nil || afterRead.EACopyability != atomicTransformEACopyable || afterRead.Digest != expectedOld.Digest {
		return fmt.Errorf("old EA source changed after reading: %w", errors.Join(err, errAtomicTransformConflict))
	}
	if len(preservedPayload) > 0 {
		stageBeforeWrite, err := atomicTransformV2WindowsMetadataFromOpen(stageFile)
		if err != nil || stageBeforeWrite.EACopyability != atomicTransformEACopyable || stageBeforeWrite.Digest != stageBefore.Digest {
			return fmt.Errorf("EA staging handle changed before writing: %w", errors.Join(err, errAtomicTransformConflict))
		}
		if err := atomicTransformV2WriteEAStream(stageFile, preservedPayload); err != nil {
			return fmt.Errorf("preserve witnessed EA on private stage: %w", err)
		}
		if err := windows.FlushFileBuffers(windows.Handle(stageFile.Fd())); err != nil {
			return fmt.Errorf("flush staged EA: %w", err)
		}
	}
	stageAfter, err := atomicTransformV2WindowsMetadataFromOpen(stageFile)
	if err != nil {
		return fmt.Errorf("verify staged EA: %w", err)
	}
	if stageAfter.EACopyability != atomicTransformEACopyable {
		return errors.New("observed staged EA is not copyable")
	}
	stageRawEA, stagePreservedEA, err := atomicTransformV2WindowsPreservedEAFromOpen(stageFile)
	if err != nil {
		return fmt.Errorf("verify canonical staged EA: %w", err)
	}
	if stageAfter.Identity != stageBefore.Identity || !atomicTransformV2EAMatchesWitness(stageRawEA, stageAfter.Streams) || !atomicTransformV2EAMatchesWitness(preservedStream, atomicTransformV2EAStreamSlice(stagePreservedEA)) {
		return errors.New("private stage did not preserve the exact witnessed EA")
	}
	after, err := atomicTransformV2WindowsMetadataFromOpen(oldFile)
	if err != nil || after.EACopyability != atomicTransformEACopyable || after.Digest != expectedOld.Digest {
		return fmt.Errorf("old EA source changed during staging: %w", errors.Join(err, errAtomicTransformConflict))
	}
	return nil
}

// atomicTransformV2WindowsPreservedEAFromOpen returns the exact raw EA stream
// witness and the canonical preserved stream. Callers computing a full raw
// witness must compare raw with their separately captured Streams before using
// preserved. No payload bytes or names are returned to metadata diagnostics.
func atomicTransformV2WindowsPreservedEAFromOpen(file *os.File) (*atomicTransformV2WindowsMetadataStream, *atomicTransformV2WindowsMetadataStream, error) {
	raw, preserved, copyability, err := atomicTransformV2WindowsObserveEAFromOpen(file)
	if err != nil {
		return nil, nil, err
	}
	if copyability != atomicTransformEACopyable {
		return nil, nil, errors.New("non-purge kernel EA cannot be preserved from user mode")
	}
	return raw, preserved, nil
}

// Observation retains the exact validated raw witness even when copying its
// valid kernel entries is unsupported. Read/abort/structure failures never
// return a usable classification or partial stream witness.
func atomicTransformV2WindowsObserveEAFromOpen(file *os.File) (*atomicTransformV2WindowsMetadataStream, *atomicTransformV2WindowsMetadataStream, atomicTransformEACopyability, error) {
	return atomicTransformV2WindowsObserveEAFromReader(&atomicTransformV2BackupReader{file: file})
}

func atomicTransformV2WindowsObserveEAFromReader(reader *atomicTransformV2BackupReader) (*atomicTransformV2WindowsMetadataStream, *atomicTransformV2WindowsMetadataStream, atomicTransformEACopyability, error) {
	payload, raw, err := atomicTransformV2ReadEAStream(reader)
	err = errors.Join(err, reader.Close())
	if err != nil {
		return nil, nil, atomicTransformEAUnknown, err
	}
	copyability, canonical, err := atomicTransformV2ClassifyEAPreservation(payload)
	if err != nil {
		return nil, nil, atomicTransformEAUnknown, err
	}
	return raw, atomicTransformV2EAStreamForPayload(canonical), copyability, nil
}

func atomicTransformV2EAStreamForPayload(payload []byte) *atomicTransformV2WindowsMetadataStream {
	if len(payload) == 0 {
		return nil
	}
	return &atomicTransformV2WindowsMetadataStream{ID: 2, Size: int64(len(payload)), SHA256: atomicTransformDigest(payload)}
}

func atomicTransformV2EAStreamSlice(stream *atomicTransformV2WindowsMetadataStream) []atomicTransformV2WindowsMetadataStream {
	if stream == nil {
		return nil
	}
	return []atomicTransformV2WindowsMetadataStream{*stream}
}

// atomicTransformV2CanonicalPreservedEA retains exact flags, name bytes and
// value bytes for ordinary entries, normalizing only linked-entry offsets and
// alignment. It omits ONLY the documented kernel-only $Kernel.Purge. namespace:
// NTFS invalidates those cache entries on content changes and silently ignores
// user-mode attempts to copy them. Other kernel entries remain unsupported.
// The caller's full raw metadata Digest must continue to include all entries.
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/kernel-extended-attributes
func atomicTransformV2CanonicalPreservedEA(payload []byte) ([]byte, error) {
	copyability, canonical, err := atomicTransformV2ClassifyEAPreservation(payload)
	if err != nil {
		return nil, err
	}
	if copyability != atomicTransformEACopyable {
		return nil, errors.New("non-purge kernel EA cannot be preserved from user mode")
	}
	return canonical, nil
}

// Classification is separate from observation. The complete raw chain is
// validated before any unsupported status can be returned; no malformed or
// unknown entry is silently discarded. Canonical bytes are exposed only when
// the complete chain is copyable under the existing preservation rules.
func atomicTransformV2ClassifyEAPreservation(payload []byte) (atomicTransformEACopyability, []byte, error) {
	if len(payload) > atomicTransformV2MaxEABytes {
		return atomicTransformEAUnknown, nil, errors.New("EA preservation payload exceeds bound")
	}
	if err := atomicTransformV2ValidateEAPayload(payload); err != nil {
		return atomicTransformEAUnknown, nil, err
	}
	var entries [][]byte
	for offset := 0; offset < len(payload); {
		nameSize := int(payload[offset+5])
		valueSize := int(binary.LittleEndian.Uint16(payload[offset+6:]))
		entrySize := 8 + nameSize + 1 + valueSize
		name := strings.ToUpper(string(payload[offset+8 : offset+8+nameSize]))
		if strings.HasPrefix(name, "$KERNEL.PURGE.") {
			// This exact dotted prefix is kernel-only and documented as volatile.
		} else if strings.HasPrefix(name, "$KERNEL.") {
			return atomicTransformEAUnsupportedKernel, nil, nil
		} else {
			entry := append([]byte(nil), payload[offset:offset+entrySize]...)
			binary.LittleEndian.PutUint32(entry, 0)
			entries = append(entries, entry)
		}
		next := int(binary.LittleEndian.Uint32(payload[offset:]))
		if next == 0 {
			break
		}
		offset += next
	}
	var canonical []byte
	for index, entry := range entries {
		if index < len(entries)-1 {
			aligned := (len(entry) + 3) &^ 3
			binary.LittleEndian.PutUint32(entry, uint32(aligned))
			canonical = append(canonical, entry...)
			canonical = append(canonical, make([]byte, aligned-len(entry))...)
		} else {
			canonical = append(canonical, entry...)
		}
	}
	return atomicTransformEACopyable, canonical, nil
}

func atomicTransformV2EAMatchesWitness(expected *atomicTransformV2WindowsMetadataStream, streams []atomicTransformV2WindowsMetadataStream) bool {
	var found *atomicTransformV2WindowsMetadataStream
	for i := range streams {
		if streams[i].ID != 2 {
			continue
		}
		if found != nil || streams[i].Attributes != 0 || streams[i].Name != "" || streams[i].Size < 0 || streams[i].Size > atomicTransformV2MaxEABytes {
			return false
		}
		found = &streams[i]
	}
	// BackupRead may emit the empty EA header or omit it. Both carry no EA
	// entries, while the complete metadata Digest retains the exact raw form.
	empty := func(stream *atomicTransformV2WindowsMetadataStream) bool {
		return stream == nil || (stream.Size == 0 && stream.Attributes == 0 && stream.Name == "" && stream.SHA256 == atomicTransformDigest(nil))
	}
	if empty(expected) && empty(found) {
		return true
	}
	return expected != nil && found != nil && *expected == *found
}

func atomicTransformV2ReadEAStream(reader io.Reader) ([]byte, *atomicTransformV2WindowsMetadataStream, error) {
	var payload []byte
	var ea *atomicTransformV2WindowsMetadataStream
	var total int64
	for count := 0; ; count++ {
		var header atomicTransformV2BackupStreamHeader
		if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
			if err == io.EOF {
				return payload, ea, nil
			}
			return nil, nil, err
		}
		if count >= atomicTransformV2MaxBackupStreams || header.Size < 0 || header.Size > atomicTransformV2MaxBackupMetadataBytes-total || header.NameBytes > atomicTransformV2MaxBackupStreamName || header.NameBytes%2 != 0 {
			return nil, nil, errors.New("backup metadata exceeds EA staging bounds")
		}
		total += header.Size
		if header.ID == 2 && (ea != nil || header.Attributes != 0 || header.NameBytes != 0 || header.Size > atomicTransformV2MaxEABytes) {
			return nil, nil, errors.New("unsupported or duplicate EA backup stream")
		}
		if _, err := io.CopyN(io.Discard, reader, int64(header.NameBytes)); err != nil {
			return nil, nil, err
		}
		if header.ID != 2 {
			if _, err := io.CopyN(io.Discard, reader, header.Size); err != nil {
				return nil, nil, err
			}
			continue
		}
		payload = make([]byte, int(header.Size))
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, nil, err
		}
		if err := atomicTransformV2ValidateEAPayload(payload); err != nil {
			return nil, nil, err
		}
		ea = &atomicTransformV2WindowsMetadataStream{ID: 2, Size: header.Size, SHA256: atomicTransformDigest(payload)}
	}
}

func atomicTransformV2ValidateEAPayload(data []byte) error {
	seen := make(map[string]bool)
	for offset, count := 0, 0; offset < len(data); count++ {
		if count >= 1024 || len(data)-offset < 8 {
			return errors.New("invalid bounded EA entry chain")
		}
		next := int(binary.LittleEndian.Uint32(data[offset:]))
		flags, nameSize := data[offset+4], int(data[offset+5])
		valueSize := int(binary.LittleEndian.Uint16(data[offset+6:]))
		entrySize := 8 + nameSize + 1 + valueSize
		end := offset + entrySize
		if nameSize == 0 || flags&^byte(0x80) != 0 || end > len(data) || data[offset+8+nameSize] != 0 {
			return errors.New("unsupported EA entry dimensions or flags")
		}
		name := data[offset+8 : offset+8+nameSize]
		// NTFS EA names use a legacy byte encoding. Admit the unambiguous
		// printable ASCII subset rather than apply Unicode folding to a kernel
		// namespace or guess a machine-specific ANSI code page.
		for _, value := range name {
			if value < 0x20 || value > 0x7e {
				return errors.New("unsupported EA name encoding")
			}
		}
		key := strings.ToUpper(string(name))
		if bytes.IndexByte(name, 0) >= 0 || seen[key] {
			return errors.New("invalid or duplicate EA entry name")
		}
		seen[key] = true
		if next == 0 {
			if end != len(data) {
				return errors.New("EA payload has trailing data")
			}
			return nil
		}
		if next < entrySize || next%4 != 0 || next > len(data)-offset-8 {
			return errors.New("invalid EA entry offset")
		}
		// Padding is not semantic FILE_FULL_EA_INFORMATION entry data. Keep it
		// in the exact raw witness; canonical copies rebuild aligned offsets.
		offset += next
	}
	return nil
}

func atomicTransformV2WriteEAStream(file *os.File, payload []byte) (err error) {
	if len(payload) == 0 || len(payload) > atomicTransformV2MaxEABytes {
		return errors.New("unsupported EA staging payload size")
	}
	if err := atomicTransformV2ValidateEAPayload(payload); err != nil {
		return err
	}
	var stream bytes.Buffer
	if err := binary.Write(&stream, binary.LittleEndian, atomicTransformV2BackupStreamHeader{ID: 2, Size: int64(len(payload))}); err != nil {
		return err
	}
	_, _ = stream.Write(payload)
	data := stream.Bytes()
	var context uintptr
	defer func() {
		if context == 0 {
			return
		}
		result, _, callErr := atomicTransformV2BackupWriteW.Call(uintptr(file.Fd()), 0, 0, 0, 1, 0, uintptr(unsafe.Pointer(&context)))
		runtime.KeepAlive(file)
		if result == 0 {
			err = errors.Join(err, atomicTransformV2BackupWriteError(callErr))
		}
	}()
	for len(data) > 0 {
		var written uint32
		result, _, callErr := atomicTransformV2BackupWriteW.Call(uintptr(file.Fd()), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&written)), 0, 0, uintptr(unsafe.Pointer(&context)))
		runtime.KeepAlive(file)
		runtime.KeepAlive(data)
		if result == 0 {
			return atomicTransformV2BackupWriteError(callErr)
		}
		if written == 0 || int(written) > len(data) {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func atomicTransformV2BackupWriteError(err error) error {
	if err == nil || err == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return err
}
