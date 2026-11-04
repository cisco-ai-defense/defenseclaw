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

package codesig

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const cmsgSignerInfoParam = 6 // CMSG_SIGNER_INFO_PARAM

var (
	modCrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modCrypt32.NewProc("CryptMsgClose")
)

// cmsgSignerInfo is the prefix of CMSG_SIGNER_INFO the signer lookup needs.
type cmsgSignerInfo struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// VerifyDarwin is available only on macOS.
func VerifyDarwin(ctx context.Context, path string, want Darwin, opts DarwinOptions) Result {
	return refused("code signatures are checked only on macOS")
}

// DarwinOptions tune VerifyDarwin on macOS.
type DarwinOptions struct {
	Pin      []string
	UID, GID uint32
}

// verifyAuthenticodeFile is the WinVerifyTrust and signer lookup; tests
// replace it.
var verifyAuthenticodeFile = authenticodeSigner

// readFileVersion is the file's VS_FIXEDFILEINFO product version; tests
// replace it.
var readFileVersion = fileProductVersion

// VerifyAuthenticode checks that path, a regular file reached through no
// reparse point, carries an embedded Authenticode signature WinVerifyTrust
// accepts and that its signer's display name is one of publishers. The file
// is held open without write or delete sharing for the whole check, so it
// cannot be changed, renamed or moved (nor any folder above it) while it is
// checked. Revocation is not fetched, so an offline device can verify; the
// chain must still build to a locally trusted root.
func VerifyAuthenticode(path string, publishers []string) Result {
	if !filepath.IsAbs(path) {
		return refused("%s is not an absolute path", path)
	}
	if len(publishers) == 0 {
		return refused("no expected publisher is configured")
	}
	if err := winpath.RejectReparseChain(path); err != nil {
		return refused("%s was not checked: %v", path, err)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return refused("%s was not checked: %v", path, err)
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return refused("%s cannot be opened: %v", path, err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return refused("%s cannot be read: %v", path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return refused("%s is not a regular file", path)
	}
	signer, err := verifyAuthenticodeFile(pointer, handle)
	if err != nil {
		return refused("the Authenticode signature of %s does not verify: %s", path, boundedText(err.Error()))
	}
	if !PublisherAllowed(signer, publishers) {
		return refused("%s is signed by %q, not by %s", path, signer, strings.Join(publishers, " or "))
	}
	// Still under the handle that denies writes: the version resource is
	// part of the signed image just verified.
	return Result{Verified: true, Version: readFileVersion(path)}
}

// fileProductVersion is the product version of path's VS_FIXEDFILEINFO as
// a.b.c.d, or "" when it has none.
func fileProductVersion(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > 1<<20 {
		return ""
	}
	buffer := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buffer[0])); err != nil {
		return ""
	}
	var info *windows.VS_FIXEDFILEINFO
	var length uint32
	if err := windows.VerQueryValue(unsafe.Pointer(&buffer[0]), `\`, unsafe.Pointer(&info), &length); err != nil ||
		info == nil || length < uint32(unsafe.Sizeof(windows.VS_FIXEDFILEINFO{})) || info.Signature != 0xFEEF04BD {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", info.ProductVersionMS>>16, info.ProductVersionMS&0xffff,
		info.ProductVersionLS>>16, info.ProductVersionLS&0xffff)
}

func authenticodeSigner(path *uint16, handle windows.Handle) (string, error) {
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: path,
		File:     handle,
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
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return "", fmt.Errorf("WinVerifyTrust: %w", verifyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close WinVerifyTrust state: %w", closeErr)
	}
	return embeddedSignerName(path)
}

// embeddedSignerName is the display name of the embedded signature's signer
// certificate.
func embeddedSignerName(path *uint16) (string, error) {
	var (
		encoding, contentType, formatType uint32
		store, message                    windows.Handle
	)
	if err := windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(path),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&store,
		&message,
		nil,
	); err != nil {
		return "", fmt.Errorf("read the embedded signature: %w", err)
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(message))

	var size uint32
	if ok, _, err := procCryptMsgGetParam.Call(uintptr(message), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", fmt.Errorf("size the signer: %w", lastError(err))
	}
	if size < uint32(unsafe.Sizeof(cmsgSignerInfo{})) || size > 1<<20 {
		return "", errors.New("the signer information has an invalid size")
	}
	buffer := make([]byte, size)
	if ok, _, err := procCryptMsgGetParam.Call(uintptr(message), cmsgSignerInfoParam, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size))); ok == 0 {
		return "", fmt.Errorf("read the signer: %w", lastError(err))
	}
	signerInfo := (*cmsgSignerInfo)(unsafe.Pointer(&buffer[0]))
	certInfo := windows.CertInfo{Issuer: signerInfo.Issuer, SerialNumber: signerInfo.SerialNumber}
	certificate, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0, windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&certInfo), nil)
	if err != nil {
		return "", fmt.Errorf("find the signer certificate: %w", err)
	}
	defer windows.CertFreeCertificateContext(certificate)
	chars := windows.CertGetNameString(certificate, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, nil, 0)
	if chars <= 1 || chars > 1024 {
		return "", errors.New("the signer certificate has no display name")
	}
	name := make([]uint16, chars)
	windows.CertGetNameString(certificate, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], chars)
	return windows.UTF16ToString(name), nil
}

func lastError(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) && errno != 0 {
		return errno
	}
	return errors.New("unknown error")
}
