// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	atomicTransformV2MaxBackupMetadataBytes = int64(64 << 20)
	atomicTransformV2MaxBackupStreams       = 1024
	atomicTransformV2MaxBackupStreamName    = 64 << 10
	atomicTransformV2BackupData             = uint32(1)
	atomicTransformV2BackupAlternateData    = uint32(4)
)

var atomicTransformV2BackupReadW = windows.NewLazySystemDLL("kernel32.dll").NewProc("BackupRead")

type atomicTransformV2WindowsMetadataStream struct {
	ID         uint32
	Attributes uint32
	Name       string
	Size       int64
	SHA256     string
}

type atomicTransformV2WindowsMetadataWitness struct {
	Digest           string
	PreservedDigest  string
	StageOwnedDigest string
	Identity         string
	ProtectionSHA256 string
	OwnerGroupSHA256 string
	DACLSHA256       string
	DACLCanonical    string
	CreationTime     uint64
	LastWriteTime    uint64
	FileAttributes   uint32
	Compression      uint16
	Streams          []atomicTransformV2WindowsMetadataStream
}

func atomicTransformV2WindowsDACLCanonicalFromOpen(file *os.File) (string, error) {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", err
	}
	sddl := descriptor.String()
	if sddl == "" {
		return "", fmt.Errorf("convert exact Windows DACL to SDDL")
	}
	return atomicTransformV2WindowsCanonicalDACLFromSDDL(sddl)
}

func atomicTransformV2WindowsCanonicalDACLFromSDDL(sddl string) (string, error) {
	// GetSecurityInfo(DACL_SECURITY_INFORMATION) can intermittently return a
	// descriptor whose String form also includes O:/G: components. Owner/group
	// have their own explicit witness; hashing them into the DACL witness makes
	// equivalent DACLs compare unequal. Extract only the top-level D: section.
	daclStart, daclEnd, depth := -1, len(sddl), 0
	for index := 0; index < len(sddl); index++ {
		switch sddl[index] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				return "", fmt.Errorf("Windows security descriptor has unbalanced parentheses")
			}
			depth--
		default:
			if depth != 0 || index+1 >= len(sddl) || sddl[index+1] != ':' ||
				!strings.ContainsRune("OGDS", rune(sddl[index])) {
				continue
			}
			if sddl[index] == 'D' {
				if daclStart >= 0 {
					return "", fmt.Errorf("Windows security descriptor has duplicate top-level DACLs")
				}
				daclStart = index
				continue
			}
			if daclStart >= 0 && daclEnd == len(sddl) {
				daclEnd = index
			}
		}
	}
	if depth != 0 {
		return "", fmt.Errorf("Windows security descriptor has unbalanced parentheses")
	}
	if daclStart < 0 || daclEnd <= daclStart+1 {
		return "", fmt.Errorf("Windows security descriptor has no top-level DACL")
	}
	sddl = sddl[daclStart:daclEnd]
	// ReplaceFileW can mark an otherwise byte-for-byte equivalent protected DACL
	// as auto-inherited (AI). AI/AR are provenance/control bookkeeping, while P
	// and the ordered ACE list are the effective file access contract. Normalize
	// only those non-semantic prefix flags; never rewrite ACE inheritance flags.
	aceStart := strings.IndexByte(sddl, '(')
	if aceStart < 0 {
		aceStart = len(sddl)
	}
	flags := strings.ReplaceAll(strings.ReplaceAll(sddl[2:aceStart], "AI", ""), "AR", "")
	sddl = "D:" + flags + sddl[aceStart:]
	return sddl, nil
}

// atomicTransformV2WindowsDACLIsReplaceNormalization recognizes only the
// one-way transformation observed from ReplaceFileW: a protected Old DACL with
// explicit ACEs becomes an unprotected target DACL whose corresponding ACEs are
// all marked inherited.  P/ID affect future inheritance, so this is not a
// general equivalence relation.  Reverse, partial, mixed, reordered, or
// otherwise changed descriptors remain foreign and are never rewritten.
func atomicTransformV2WindowsDACLIsReplaceNormalization(target, old string) (bool, error) {
	targetPrefix, targetACEs, err := atomicTransformV2WindowsDACLParts(target)
	if err != nil {
		return false, err
	}
	oldPrefix, oldACEs, err := atomicTransformV2WindowsDACLParts(old)
	if err != nil {
		return false, err
	}
	if oldPrefix != "D:P" || targetPrefix != "D:" || len(oldACEs) == 0 || len(targetACEs) != len(oldACEs) {
		return false, nil
	}
	for index := range oldACEs {
		oldACE, targetACE := oldACEs[index], targetACEs[index]
		oldFirst := strings.IndexByte(oldACE, ';')
		targetFirst := strings.IndexByte(targetACE, ';')
		if oldFirst < 0 || targetFirst < 0 {
			return false, fmt.Errorf("Windows DACL ACE has no flags field")
		}
		oldSecondRelative := strings.IndexByte(oldACE[oldFirst+1:], ';')
		targetSecondRelative := strings.IndexByte(targetACE[targetFirst+1:], ';')
		if oldSecondRelative < 0 || targetSecondRelative < 0 {
			return false, fmt.Errorf("Windows DACL ACE has an incomplete flags field")
		}
		oldSecond := oldFirst + 1 + oldSecondRelative
		targetSecond := targetFirst + 1 + targetSecondRelative
		oldFlags := oldACE[oldFirst+1 : oldSecond]
		targetFlags := targetACE[targetFirst+1 : targetSecond]
		if strings.Contains(oldFlags, "ID") || strings.Count(targetFlags, "ID") != 1 ||
			strings.Replace(targetFlags, "ID", "", 1) != oldFlags ||
			oldACE[:oldFirst+1] != targetACE[:targetFirst+1] ||
			oldACE[oldSecond:] != targetACE[targetSecond:] {
			return false, nil
		}
	}
	return true, nil
}

func atomicTransformV2WindowsDACLParts(sddl string) (string, []string, error) {
	canonical, err := atomicTransformV2WindowsCanonicalDACLFromSDDL(sddl)
	if err != nil {
		return "", nil, err
	}
	aceStart := strings.IndexByte(canonical, '(')
	if aceStart < 0 {
		return "", nil, fmt.Errorf("Windows DACL has no ACEs")
	}
	prefix := canonical[:aceStart]
	if !strings.HasPrefix(prefix, "D:") {
		return "", nil, fmt.Errorf("Windows DACL has an invalid prefix")
	}
	aces := make([]string, 0, 4)
	for cursor := aceStart; cursor < len(canonical); {
		if canonical[cursor] != '(' {
			return "", nil, fmt.Errorf("Windows DACL has data outside an ACE")
		}
		start := cursor
		depth := 0
		for ; cursor < len(canonical); cursor++ {
			switch canonical[cursor] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					cursor++
					goto aceComplete
				}
				if depth < 0 {
					return "", nil, fmt.Errorf("Windows DACL has unbalanced ACE parentheses")
				}
			}
		}
		return "", nil, fmt.Errorf("Windows DACL has an unterminated ACE")

	aceComplete:
		aces = append(aces, canonical[start:cursor])
	}
	return prefix, aces, nil
}

func atomicTransformV2WindowsOwnerGroupFromOpen(file *os.File) (string, string, error) {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()), windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION,
	)
	if err != nil {
		return "", "", err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return "", "", fmt.Errorf("query exact Windows owner: %w", err)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil {
		return "", "", fmt.Errorf("query exact Windows primary group: %w", err)
	}
	canonical := "O:" + owner.String() + "G:" + group.String()
	return canonical, atomicTransformDigest([]byte(canonical)), nil
}

func atomicTransformV2WindowsDACLFromOpen(file *os.File) (string, error) {
	sddl, err := atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	if err != nil {
		return "", err
	}
	return atomicTransformDigest([]byte(sddl)), nil
}

type atomicTransformV2WindowsBasicInfo struct {
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	FileAttributes uint32
	_              uint32
}

type atomicTransformV2BackupStreamHeader struct {
	ID         uint32
	Attributes uint32
	Size       int64
	NameBytes  uint32
}

type atomicTransformV2BackupReader struct {
	file    *os.File
	context uintptr
}

func (r *atomicTransformV2BackupReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	var read uint32
	result, _, callErr := atomicTransformV2BackupReadW.Call(
		uintptr(r.file.Fd()),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(uint32(len(buffer))),
		uintptr(unsafe.Pointer(&read)),
		0, // do not abort
		0, // DACL is witnessed separately from BackupRead
		uintptr(unsafe.Pointer(&r.context)),
	)
	runtime.KeepAlive(r.file)
	if result == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}
		return int(read), callErr
	}
	if read == 0 {
		return 0, io.EOF
	}
	return int(read), nil
}

func (r *atomicTransformV2BackupReader) Close() error {
	if r.context == 0 {
		return nil
	}
	result, _, callErr := atomicTransformV2BackupReadW.Call(
		uintptr(r.file.Fd()), 0, 0, 0, 1, 0,
		uintptr(unsafe.Pointer(&r.context)),
	)
	runtime.KeepAlive(r.file)
	r.context = 0
	if result == 0 && callErr != nil && callErr != syscall.Errno(0) {
		return callErr
	}
	return nil
}

func atomicTransformV2HashString(digest hash.Hash, value string) {
	_ = binary.Write(digest, binary.LittleEndian, uint32(len(value)))
	_, _ = digest.Write([]byte(value))
}

func atomicTransformV2WindowsBackupStreamsFromOpen(
	file *os.File,
) ([]atomicTransformV2WindowsMetadataStream, error) {
	reader := &atomicTransformV2BackupReader{file: file}
	defer reader.Close()
	streams := make([]atomicTransformV2WindowsMetadataStream, 0, 4)
	var total int64
	for {
		var header atomicTransformV2BackupStreamHeader
		if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read Windows backup stream header: %w", err)
		}
		if header.Size < 0 || header.NameBytes > atomicTransformV2MaxBackupStreamName ||
			header.NameBytes%2 != 0 {
			return nil, fmt.Errorf("invalid Windows backup stream dimensions")
		}
		if len(streams) >= atomicTransformV2MaxBackupStreams ||
			header.Size > atomicTransformV2MaxBackupMetadataBytes-total {
			return nil, fmt.Errorf("Windows metadata streams exceed bounded witness limit")
		}
		nameBytes := make([]byte, header.NameBytes)
		if _, err := io.ReadFull(reader, nameBytes); err != nil {
			return nil, fmt.Errorf("read Windows backup stream name: %w", err)
		}
		nameUTF16 := make([]uint16, len(nameBytes)/2)
		for index := range nameUTF16 {
			nameUTF16[index] = binary.LittleEndian.Uint16(nameBytes[index*2:])
		}
		streamDigest := sha256.New()
		if _, err := io.CopyN(streamDigest, reader, header.Size); err != nil {
			return nil, fmt.Errorf("read Windows backup stream contents: %w", err)
		}
		total += header.Size
		streams = append(streams, atomicTransformV2WindowsMetadataStream{
			ID: header.ID, Attributes: header.Attributes,
			Name: string(utf16.Decode(nameUTF16)), Size: header.Size,
			SHA256: hex.EncodeToString(streamDigest.Sum(nil)),
		})
	}
	sort.Slice(streams, func(left, right int) bool {
		if streams[left].ID != streams[right].ID {
			return streams[left].ID < streams[right].ID
		}
		if streams[left].Name != streams[right].Name {
			return streams[left].Name < streams[right].Name
		}
		if streams[left].Size != streams[right].Size {
			return streams[left].Size < streams[right].Size
		}
		return streams[left].SHA256 < streams[right].SHA256
	})
	return streams, nil
}

// atomicTransformV2WindowsMetadataFromOpen computes the bounded canonical
// witness used to detect same-principal ADS/content/attribute races. It runs on
// an already-bound exact handle; callers must keep that handle open across any
// validation-to-mutation boundary they intend to protect.
func atomicTransformV2WindowsMetadataFromOpen(
	file *os.File,
) (atomicTransformV2WindowsMetadataWitness, error) {
	var witness atomicTransformV2WindowsMetadataWitness
	handle := windows.Handle(file.Fd())
	var basic atomicTransformV2WindowsBasicInfo
	if err := windows.GetFileInformationByHandleEx(
		handle, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)),
	); err != nil {
		return witness, fmt.Errorf("query Windows config basic metadata: %w", err)
	}
	var err error
	witness.Identity, err = atomicTransformOpenFileIdentity(file)
	if err != nil {
		return witness, err
	}
	var compression uint16
	var returned uint32
	if err := windows.DeviceIoControl(
		handle, windows.FSCTL_GET_COMPRESSION, nil, 0,
		(*byte)(unsafe.Pointer(&compression)), uint32(unsafe.Sizeof(compression)), &returned, nil,
	); err != nil {
		return witness, fmt.Errorf("query Windows config compression: %w", err)
	}
	if returned < uint32(unsafe.Sizeof(compression)) {
		return witness, fmt.Errorf("query Windows config compression returned %d bytes", returned)
	}
	protection, err := atomicTransformProtectionDigest(file)
	if err != nil {
		return witness, err
	}
	daclCanonical, err := atomicTransformV2WindowsDACLCanonicalFromOpen(file)
	if err != nil {
		return witness, err
	}
	dacl := atomicTransformDigest([]byte(daclCanonical))
	_, ownerGroup, err := atomicTransformV2WindowsOwnerGroupFromOpen(file)
	if err != nil {
		return witness, err
	}
	streams, err := atomicTransformV2WindowsBackupStreamsFromOpen(file)
	if err != nil {
		return witness, err
	}
	witness.ProtectionSHA256 = protection
	witness.OwnerGroupSHA256 = ownerGroup
	witness.DACLSHA256 = dacl
	witness.DACLCanonical = daclCanonical
	witness.CreationTime = basic.CreationTime
	witness.LastWriteTime = basic.LastWriteTime
	witness.FileAttributes = basic.FileAttributes
	witness.Compression = compression
	witness.Streams = streams

	digest := sha256.New()
	atomicTransformV2HashString(digest, "DefenseClaw Windows metadata witness v1")
	atomicTransformV2HashString(digest, witness.Identity)
	atomicTransformV2HashString(digest, witness.ProtectionSHA256)
	atomicTransformV2HashString(digest, witness.OwnerGroupSHA256)
	atomicTransformV2HashString(digest, witness.DACLSHA256)
	_ = binary.Write(digest, binary.LittleEndian, witness.CreationTime)
	_ = binary.Write(digest, binary.LittleEndian, witness.LastWriteTime)
	_ = binary.Write(digest, binary.LittleEndian, witness.FileAttributes)
	_ = binary.Write(digest, binary.LittleEndian, witness.Compression)
	_ = binary.Write(digest, binary.LittleEndian, uint32(len(streams)))
	for _, stream := range streams {
		_ = binary.Write(digest, binary.LittleEndian, stream.ID)
		_ = binary.Write(digest, binary.LittleEndian, stream.Attributes)
		atomicTransformV2HashString(digest, stream.Name)
		_ = binary.Write(digest, binary.LittleEndian, stream.Size)
		atomicTransformV2HashString(digest, stream.SHA256)
	}
	witness.Digest = hex.EncodeToString(digest.Sum(nil))

	// ReplaceFileW deliberately keeps Stage's file ID and unnamed/main stream,
	// but is documented to transfer Old's creation time, DACL, compression/EFS
	// attributes, named streams, EAs, and object ID. This second digest excludes
	// identity, unnamed stream, and both timestamps; creation/last-write are
	// persisted explicitly because an internal provisional rename can alter
	// creation while ReplaceFileW takes creation from Old and last-write from New.
	preserved := sha256.New()
	atomicTransformV2HashString(preserved, "DefenseClaw Windows preserved metadata witness v1")
	// ReplaceFileW transfers Old's DACL, not its owner/group; New retains the
	// Stage owner/group. Hashing the full security descriptor here would reject
	// a valid hybrid descriptor even though the access-control contract holds.
	atomicTransformV2HashString(preserved, witness.DACLSHA256)
	// Native ReplaceFileW preserves Old's HIDDEN/SYSTEM/TEMPORARY/OFFLINE/
	// NOT_CONTENT_INDEXED/COMPRESSED/ENCRYPTED bits and drops Stage-only values,
	// but ARCHIVE is forced and NORMAL is only the absence of other bits.
	preservedAttributes := witness.FileAttributes &^
		(windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NORMAL)
	_ = binary.Write(preserved, binary.LittleEndian, preservedAttributes)
	_ = binary.Write(preserved, binary.LittleEndian, witness.Compression)
	preservedCount := uint32(0)
	for _, stream := range streams {
		if stream.ID != atomicTransformV2BackupData {
			preservedCount++
		}
	}
	_ = binary.Write(preserved, binary.LittleEndian, preservedCount)
	for _, stream := range streams {
		if stream.ID == atomicTransformV2BackupData {
			continue
		}
		_ = binary.Write(preserved, binary.LittleEndian, stream.ID)
		_ = binary.Write(preserved, binary.LittleEndian, stream.Attributes)
		atomicTransformV2HashString(preserved, stream.Name)
		_ = binary.Write(preserved, binary.LittleEndian, stream.Size)
		atomicTransformV2HashString(preserved, stream.SHA256)
	}
	witness.PreservedDigest = hex.EncodeToString(preserved.Sum(nil))

	// With no named ADS, native ReplaceFileW keeps Stage's last-write time. When
	// Old has an ADS, NTFS advances the published target to the ReplaceFileW call
	// interval instead. General attributes are deliberately excluded: native
	// probes show a mixed outcome (for example Old Hidden survives, Stage System
	// is dropped, and Archive can be forced), while Microsoft does not specify a
	// stable composition rule for them. Existing-file P therefore does not use
	// this diagnostic digest; Rp still witnesses Stage's exact pre-call state.
	stageOwned := sha256.New()
	atomicTransformV2HashString(stageOwned, "DefenseClaw Windows Stage-owned metadata witness v1")
	_ = binary.Write(stageOwned, binary.LittleEndian, witness.LastWriteTime)
	witness.StageOwnedDigest = hex.EncodeToString(stageOwned.Sum(nil))
	return witness, nil
}

func atomicTransformV2WindowsMetadataDigestFromOpen(file *os.File) (string, error) {
	witness, err := atomicTransformV2WindowsMetadataFromOpen(file)
	return witness.Digest, err
}

func atomicTransformV2WindowsPreservedComparison(
	target, old atomicTransformV2WindowsMetadataWitness,
) string {
	maskedAttributes := func(attributes uint32) uint32 {
		return attributes &^ (windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NORMAL)
	}
	type streamKey struct {
		id   uint32
		name string
	}
	filterStreams := func(streams []atomicTransformV2WindowsMetadataStream) map[streamKey]atomicTransformV2WindowsMetadataStream {
		filtered := make(map[streamKey]atomicTransformV2WindowsMetadataStream)
		for _, stream := range streams {
			if stream.ID != atomicTransformV2BackupData {
				filtered[streamKey{id: stream.ID, name: stream.Name}] = stream
			}
		}
		return filtered
	}
	targetStreams, oldStreams := filterStreams(target.Streams), filterStreams(old.Streams)
	keys := make(map[streamKey]struct{}, len(targetStreams)+len(oldStreams))
	for key := range targetStreams {
		keys[key] = struct{}{}
	}
	for key := range oldStreams {
		keys[key] = struct{}{}
	}
	var streamMismatches []string
	for key := range keys {
		targetStream, targetExists := targetStreams[key]
		oldStream, oldExists := oldStreams[key]
		if targetExists && oldExists && targetStream.Attributes == oldStream.Attributes &&
			targetStream.Size == oldStream.Size && targetStream.SHA256 == oldStream.SHA256 {
			continue
		}
		nameDigest := atomicTransformDigest([]byte(key.name))
		if len(nameDigest) > 12 {
			nameDigest = nameDigest[:12]
		}
		streamMismatches = append(streamMismatches, fmt.Sprintf(
			"id=%d name_sha=%s target=%t old=%t attrs=%t size=%t content=%t",
			key.id, nameDigest, targetExists, oldExists,
			targetExists && oldExists && targetStream.Attributes == oldStream.Attributes,
			targetExists && oldExists && targetStream.Size == oldStream.Size,
			targetExists && oldExists && targetStream.SHA256 == oldStream.SHA256,
		))
	}
	sort.Strings(streamMismatches)
	streamDetail := "none"
	if len(streamMismatches) != 0 {
		streamDetail = strings.Join(streamMismatches, ";")
	}
	return fmt.Sprintf(
		"dacl_canonical=%t dacl_digest=%t target_dacl=%q old_dacl=%q masked_attrs=%t target_attrs=0x%x old_attrs=0x%x "+
			"compression=%t target_compression=%d old_compression=%d stream_counts=%d/%d stream_mismatches=[%s]",
		target.DACLCanonical == old.DACLCanonical, target.DACLSHA256 == old.DACLSHA256,
		target.DACLCanonical, old.DACLCanonical,
		maskedAttributes(target.FileAttributes) == maskedAttributes(old.FileAttributes),
		maskedAttributes(target.FileAttributes), maskedAttributes(old.FileAttributes),
		target.Compression == old.Compression, target.Compression, old.Compression,
		len(targetStreams), len(oldStreams), streamDetail,
	)
}

func atomicTransformV2WindowsPreservedMatchesExceptDACL(
	target, old atomicTransformV2WindowsMetadataWitness,
) bool {
	maskedAttributes := func(attributes uint32) uint32 {
		return attributes &^ (windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_NORMAL)
	}
	if maskedAttributes(target.FileAttributes) != maskedAttributes(old.FileAttributes) ||
		target.Compression != old.Compression {
		return false
	}
	type streamKey struct {
		id   uint32
		name string
	}
	streams := func(witness atomicTransformV2WindowsMetadataWitness) map[streamKey]atomicTransformV2WindowsMetadataStream {
		result := make(map[streamKey]atomicTransformV2WindowsMetadataStream)
		for _, stream := range witness.Streams {
			if stream.ID != atomicTransformV2BackupData {
				result[streamKey{id: stream.ID, name: stream.Name}] = stream
			}
		}
		return result
	}
	targetStreams, oldStreams := streams(target), streams(old)
	if len(targetStreams) != len(oldStreams) {
		return false
	}
	for key, oldStream := range oldStreams {
		targetStream, ok := targetStreams[key]
		if !ok || targetStream.Attributes != oldStream.Attributes ||
			targetStream.Size != oldStream.Size || targetStream.SHA256 != oldStream.SHA256 {
			return false
		}
	}
	return true
}
