// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

// Windows system-call half of the Secure Client GUI peer
// authentication. The admission policy and the listener live in
// winpeer_auth.go; this file supplies the resolvers they need.
//
// Every lookup below works without opening the peer process. The
// gateway runs as a virtual service account, which the default DACL of
// an interactive user's process does not name, so OpenProcess on the
// GUI cannot be relied on. The kernel's per-PID image name and the
// system process snapshot are available to any caller.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// KindUnixPeer mirrors the unix constant so cross-platform code can
// reference the value unconditionally.
const KindUnixPeer = "UnixPeer"

// authpostureGAApproved satisfies the release gate in
// authposture_gagate.go. It lives here, next to the Windows peer
// authentication, so removing that authentication removes the
// approval with it.
const authpostureGAApproved = true

// peerIdentity mirrors the unix shape so Server.logReject compiles on
// every platform. The Windows accept path reports windowsPeerIdentity
// instead.
type peerIdentity struct {
	Kind string
	PID  int32
	UID  uint32
	GID  uint32
}

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID from afunix.h,
// _WSAIOR(IOC_VENDOR, 256): the PID of the process that created the
// peer end of a connected AF_UNIX socket.
const sioAFUnixGetPeerPID = windows.IOC_OUT | windows.IOC_VENDOR | 256

// productionWindowsPeerResolvers wires the real system lookups.
func productionWindowsPeerResolvers() windowsPeerResolvers {
	return windowsPeerResolvers{
		peerPID:   afUnixPeerPID,
		process:   queryWindowsPeerProcess,
		openImage: openWindowsPeerImage,
	}
}

// newWindowsSecureClientListener builds the admission policy from the
// protected machine Program Files roots and wraps inner with it. A
// failure here stops the IPC server from starting rather than serving
// without authentication.
func newWindowsSecureClientListener(
	inner net.Listener,
	images, signers []string,
	logReject func(windowsPeerIdentity, string),
) (net.Listener, error) {
	roots, err := winpath.ResolveTrustedMachineRoots()
	if err != nil {
		return nil, fmt.Errorf("ipc: windows peer auth: resolve trusted Program Files roots: %w", err)
	}
	policy, err := newWindowsPeerPolicy(
		[]string{roots.ProgramFilesX86, roots.ProgramFiles},
		images,
		signers,
		dosDeviceForDrive,
	)
	if err != nil {
		return nil, err
	}
	return newWindowsPeerAuthListener(inner, policy, productionWindowsPeerResolvers(), logReject)
}

// dosDeviceForDrive returns the NT device a drive letter ("C:") names
// in this process's DOS device namespace, for example
// `\Device\HarddiskVolume3`. The gateway service resolves it for the
// trusted Program Files roots only, so a drive mapping made inside an
// interactive user's logon session does not apply.
func dosDeviceForDrive(drive string) (string, error) {
	if len(drive) != 2 || drive[1] != ':' {
		return "", fmt.Errorf("drive %q is not a drive letter", drive)
	}
	name, err := windows.UTF16PtrFromString(drive)
	if err != nil {
		return "", fmt.Errorf("encode drive: %w", err)
	}
	buffer := make([]uint16, windows.MAX_PATH)
	for attempt := 0; attempt < 4; attempt++ {
		n, err := windows.QueryDosDevice(name, &buffer[0], uint32(len(buffer)))
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			buffer = make([]uint16, len(buffer)*4)
			continue
		}
		if err != nil {
			return "", fmt.Errorf("QueryDosDevice(%s): %w", drive, err)
		}
		if n == 0 || int(n) > len(buffer) {
			return "", fmt.Errorf("QueryDosDevice(%s) returned no target", drive)
		}
		// The result is a REG_MULTI_SZ-style list whose first entry is
		// the current mapping.
		return windows.UTF16ToString(buffer[:n]), nil
	}
	return "", fmt.Errorf("QueryDosDevice(%s) target kept growing", drive)
}

// afUnixPeerPID asks the AF_UNIX provider which process holds the
// other end of the connection.
func afUnixPeerPID(c net.Conn) (uint32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("expected *net.UnixConn, got %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("syscall conn: %w", err)
	}
	var (
		pid      uint32
		ioctlErr error
	)
	controlErr := raw.Control(func(fd uintptr) {
		var returned uint32
		ioctlErr = windows.WSAIoctl(
			windows.Handle(fd),
			sioAFUnixGetPeerPID,
			nil,
			0,
			(*byte)(unsafe.Pointer(&pid)),
			uint32(unsafe.Sizeof(pid)),
			&returned,
			nil,
			0,
		)
		// The provider fills the ULONG but does not always report the
		// byte count, so accept 0 as well as the full size and rely on
		// the PID value itself.
		if ioctlErr == nil && returned != 0 && returned != uint32(unsafe.Sizeof(pid)) {
			ioctlErr = fmt.Errorf("SIO_AF_UNIX_GETPEERPID returned %d bytes", returned)
		}
	})
	if controlErr != nil {
		return 0, fmt.Errorf("control: %w", controlErr)
	}
	if ioctlErr != nil {
		return 0, fmt.Errorf("SIO_AF_UNIX_GETPEERPID: %w", ioctlErr)
	}
	if pid == 0 {
		return 0, errors.New("SIO_AF_UNIX_GETPEERPID reported no peer process")
	}
	return pid, nil
}

// queryWindowsPeerProcess reads the peer's creation time and session,
// its image name, and its creation time again. The two snapshots
// bracket the image lookup, so a PID that exits and is reused in
// between is refused instead of being reported with another process's
// image.
func queryWindowsPeerProcess(pid uint32) (windowsPeerProcess, error) {
	before, err := systemProcessEntry(pid)
	if err != nil {
		return windowsPeerProcess{}, err
	}
	image, err := systemProcessImageName(pid)
	if err != nil {
		return windowsPeerProcess{}, err
	}
	after, err := systemProcessEntry(pid)
	if err != nil {
		return windowsPeerProcess{}, err
	}
	if before.createTime == 0 || before.createTime != after.createTime {
		return windowsPeerProcess{}, fmt.Errorf("pid %d changed identity during lookup", pid)
	}
	created := windows.Filetime{
		LowDateTime:  uint32(before.createTime),
		HighDateTime: uint32(uint64(before.createTime) >> 32),
	}
	return windowsPeerProcess{
		ImagePath: image,
		SessionID: before.sessionID,
		CreatedAt: time.Unix(0, created.Nanoseconds()),
	}, nil
}

// systemProcessIDInformation is SYSTEM_PROCESS_ID_INFORMATION.
type systemProcessIDInformation struct {
	ProcessID uintptr
	ImageName windows.NTUnicodeString
}

// systemProcessImageName returns the NT path of the executable the
// process was created from.
func systemProcessImageName(pid uint32) (string, error) {
	// UNICODE_STRING lengths are 16-bit byte counts; this buffer holds
	// the longest name one can describe.
	buffer := make([]uint16, 0x7fff)
	info := systemProcessIDInformation{ProcessID: uintptr(pid)}
	info.ImageName.MaximumLength = uint16(len(buffer) * 2)
	info.ImageName.Buffer = &buffer[0]
	if err := windows.NtQuerySystemInformation(
		windows.SystemProcessIdInformation,
		unsafe.Pointer(&info),
		uint32(unsafe.Sizeof(info)),
		nil,
	); err != nil {
		return "", fmt.Errorf("query image name of pid %d: %w", pid, err)
	}
	length := int(info.ImageName.Length / 2)
	if length == 0 || length > len(buffer) {
		return "", fmt.Errorf("pid %d has no image name", pid)
	}
	return windows.UTF16ToString(buffer[:length]), nil
}

type systemProcessSnapshotEntry struct {
	createTime int64
	sessionID  uint32
}

// maxSystemProcessSnapshotBytes bounds the process snapshot buffer.
const maxSystemProcessSnapshotBytes = 64 << 20

// systemProcessEntry finds pid in the system process snapshot.
func systemProcessEntry(pid uint32) (systemProcessSnapshotEntry, error) {
	size := uint32(1 << 20)
	for attempt := 0; attempt < 8; attempt++ {
		// []uint64 keeps the buffer 8-byte aligned for the entry casts.
		buffer := make([]uint64, (size+7)/8)
		byteLength := uint32(len(buffer) * 8)
		var needed uint32
		err := windows.NtQuerySystemInformation(
			windows.SystemProcessInformation,
			unsafe.Pointer(&buffer[0]),
			byteLength,
			&needed,
		)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH {
			next := size * 2
			if needed+(64<<10) > next {
				next = needed + (64 << 10)
			}
			if next > maxSystemProcessSnapshotBytes {
				return systemProcessSnapshotEntry{}, errors.New("system process snapshot exceeds its size bound")
			}
			size = next
			continue
		}
		if err != nil {
			return systemProcessSnapshotEntry{}, fmt.Errorf("query system process snapshot: %w", err)
		}
		return findSystemProcessEntry(unsafe.Pointer(&buffer[0]), uintptr(byteLength), pid)
	}
	return systemProcessSnapshotEntry{}, errors.New("system process snapshot kept growing")
}

func findSystemProcessEntry(base unsafe.Pointer, length uintptr, pid uint32) (systemProcessSnapshotEntry, error) {
	entrySize := unsafe.Sizeof(windows.SYSTEM_PROCESS_INFORMATION{})
	var offset uintptr
	for {
		if offset+entrySize > length {
			return systemProcessSnapshotEntry{}, errors.New("system process snapshot is truncated")
		}
		entry := (*windows.SYSTEM_PROCESS_INFORMATION)(unsafe.Add(base, offset))
		if entry.UniqueProcessID == uintptr(pid) {
			return systemProcessSnapshotEntry{createTime: entry.CreateTime, sessionID: entry.SessionID}, nil
		}
		if entry.NextEntryOffset == 0 {
			return systemProcessSnapshotEntry{}, fmt.Errorf("pid %d is not running", pid)
		}
		offset += uintptr(entry.NextEntryOffset)
	}
}

// openedWindowsPeerImage holds the peer executable open with read-only
// sharing, so nobody can write, rename, or delete it between the path
// check and WinVerifyTrust.
type openedWindowsPeerImage struct {
	handle    windows.Handle
	finalPath string
}

// openWindowsPeerImage opens an allowed executable by its canonical
// drive-letter path and resolves the canonical path of the file
// actually opened. The listener calls it only with a path from the
// admission policy.
func openWindowsPeerImage(drivePath string) (windowsPeerImage, error) {
	openPath, err := win32OpenPathForImage(drivePath)
	if err != nil {
		return nil, err
	}
	pathPtr, err := windows.UTF16PtrFromString(openPath)
	if err != nil {
		return nil, fmt.Errorf("encode image path: %w", err)
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("open image: %w", err)
	}
	image := &openedWindowsPeerImage{handle: handle}
	fail := func(cause error) (windowsPeerImage, error) {
		_ = image.Close()
		return nil, cause
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fail(fmt.Errorf("inspect image: %w", err))
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fail(errors.New("image is not a regular file"))
	}
	finalPath, err := finalDrivePathForHandle(handle)
	if err != nil {
		return fail(err)
	}
	if err := winpath.RejectReparseChain(finalPath); err != nil {
		return fail(fmt.Errorf("image path: %w", err))
	}
	image.finalPath = finalPath
	return image, nil
}

// win32OpenPathForImage maps a canonical drive-letter path to the
// extended-length form CreateFile is given. Device, UNC and relative
// paths are refused.
func win32OpenPathForImage(drivePath string) (string, error) {
	if drivePath == "" || strings.ContainsRune(drivePath, 0) {
		return "", errors.New("image path is empty or contains NUL")
	}
	if !isCanonicalWindowsDrivePath(drivePath) {
		return "", fmt.Errorf("image path %q is not a canonical drive path", drivePath)
	}
	return winpath.Extended(drivePath)
}

// finalDrivePathForHandle returns the normalized drive-letter path of
// an open file. Files without a drive-letter path (network shares,
// volumes with no mount point) are refused.
func finalDrivePathForHandle(handle windows.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for attempt := 0; attempt < 4; attempt++ {
		length, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", fmt.Errorf("resolve image final path: %w", err)
		}
		if length == 0 {
			return "", errors.New("image final path is empty")
		}
		if length >= uint32(len(buffer)) {
			buffer = make([]uint16, length+1)
			continue
		}
		value := windows.UTF16ToString(buffer[:length])
		if strings.HasPrefix(value, `\\?\UNC\`) || !strings.HasPrefix(value, `\\?\`) {
			return "", fmt.Errorf("image final path %q is not on a local drive", value)
		}
		value = strings.TrimPrefix(value, `\\?\`)
		if !isCanonicalWindowsDrivePath(value) {
			return "", fmt.Errorf("image final path %q is not a canonical drive path", value)
		}
		return value, nil
	}
	return "", errors.New("image final path kept growing")
}

func (i *openedWindowsPeerImage) FinalPath() string { return i.finalPath }

func (i *openedWindowsPeerImage) Close() error {
	if i.handle == 0 || i.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(i.handle)
	i.handle = 0
	return err
}

// VerifySigner runs WinVerifyTrust on the held handle and returns the
// leaf certificate of the primary signature it validated. Revocation
// is not fetched: the accept path must not wait on the network, and
// the installer applies the same offline policy to Cisco payloads.
func (i *openedWindowsPeerImage) VerifySigner() (windowsImageSigner, error) {
	pathPtr, err := winpath.UTF16Ptr(i.finalPath)
	if err != nil {
		return windowsImageSigner{}, fmt.Errorf("encode image path: %w", err)
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathPtr,
		File:     i.handle,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL |
			windows.WTD_REVOCATION_CHECK_NONE |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	defer func() {
		data.StateAction = windows.WTD_STATEACTION_CLOSE
		_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	}()
	if verifyErr != nil {
		return windowsImageSigner{}, fmt.Errorf("WinVerifyTrust: %w", verifyErr)
	}
	encoded, err := wintrustLeafCertificate(data.StateData)
	if err != nil {
		return windowsImageSigner{}, err
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		return windowsImageSigner{}, fmt.Errorf("parse signer certificate: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return windowsImageSigner{
		CommonName:       certificate.Subject.CommonName,
		Organizations:    append([]string(nil), certificate.Subject.Organization...),
		ThumbprintSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

var (
	modWintrust                        = windows.NewLazySystemDLL("wintrust.dll")
	procWTHelperProvDataFromStateData  = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
	procWTHelperGetProvCertFromChain   = modWintrust.NewProc("WTHelperGetProvCertFromChain")
)

// cryptProviderCertPrefix is the leading part of CRYPT_PROVIDER_CERT;
// only these fields are read.
type cryptProviderCertPrefix struct {
	Size uint32
	Cert *windows.CertContext
}

// wintrustLeafCertificate copies the DER leaf certificate of signer 0
// out of an open WinVerifyTrust state.
func wintrustLeafCertificate(state windows.Handle) ([]byte, error) {
	for _, proc := range []*windows.LazyProc{
		procWTHelperProvDataFromStateData,
		procWTHelperGetProvSignerFromChain,
		procWTHelperGetProvCertFromChain,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("resolve %s: %w", proc.Name, err)
		}
	}
	providerData, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if providerData == 0 {
		return nil, errors.New("WinVerifyTrust state has no provider data")
	}
	signer, _, _ := procWTHelperGetProvSignerFromChain.Call(providerData, 0, 0, 0)
	if signer == 0 {
		return nil, errors.New("WinVerifyTrust state has no primary signer")
	}
	providerCert, _, _ := procWTHelperGetProvCertFromChain.Call(signer, 0)
	if providerCert == 0 {
		return nil, errors.New("WinVerifyTrust signer has no certificate chain")
	}
	prefix := (*cryptProviderCertPrefix)(wintrustPointer(providerCert))
	if prefix.Size < uint32(unsafe.Sizeof(cryptProviderCertPrefix{})) || prefix.Cert == nil {
		return nil, errors.New("WinVerifyTrust signer certificate is malformed")
	}
	if prefix.Cert.EncodedCert == nil || prefix.Cert.Length == 0 || prefix.Cert.Length > 1<<20 {
		return nil, errors.New("WinVerifyTrust signer certificate is empty or oversized")
	}
	return append([]byte(nil), unsafe.Slice(prefix.Cert.EncodedCert, prefix.Cert.Length)...), nil
}

// wintrustPointer converts an address returned by wintrust.dll into a
// pointer. The memory belongs to the WinVerifyTrust state, never the Go
// heap, and stays valid until the state is closed.
func wintrustPointer(address uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&address))
}
