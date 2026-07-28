// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func verifyEmbeddedAuthenticodeTrust(filePath string) error {
	path, err := winpath.UTF16Ptr(filePath)
	if err != nil {
		return fmt.Errorf("encode Authenticode path: %w", err)
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: path,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		// Installation must work offline. The signed manifest pins the exact
		// leaf and file digest; WinVerifyTrust still validates the embedded PE
		// signature, timestamp, and locally available trust chain without
		// turning network revocation availability into install liveness.
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL |
			windows.WTD_REVOCATION_CHECK_NONE |
			windows.WTD_DISABLE_MD2_MD4,
		UIContext: windows.WTD_UICONTEXT_INSTALL,
	}
	verifyErr := windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		data,
	)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeErr := windows.WinVerifyTrustEx(
		windows.InvalidHWND,
		&windows.WINTRUST_ACTION_GENERIC_VERIFY_V2,
		data,
	)
	if verifyErr != nil {
		return fmt.Errorf("WinVerifyTrust rejected embedded Authenticode: %w", verifyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close WinVerifyTrust state: %w", closeErr)
	}
	return nil
}

func verifyPublishedStableHookRuntime(source, published string) error {
	sourceFile, err := openStableHookVerificationFile(source)
	if err != nil {
		return fmt.Errorf("lock installed hook launcher source: %w", err)
	}
	defer sourceFile.Close()
	publishedFile, err := openStableHookVerificationFile(published)
	if err != nil {
		return fmt.Errorf("lock published stable hook launcher: %w", err)
	}
	defer publishedFile.Close()

	before, err := readStableHookRuntimeIdentity(sourceFile, publishedFile)
	if err != nil {
		return err
	}
	if before.Authenticode.Present {
		if err := verifyEmbeddedAuthenticodeTrust(published); err != nil {
			return fmt.Errorf("verify stable hook runtime Authenticode: %w", err)
		}
	}
	after, err := readStableHookRuntimeIdentity(sourceFile, publishedFile)
	if err != nil {
		return fmt.Errorf("revalidate stable hook runtime after Authenticode: %w", err)
	}
	if before != after {
		return errors.New("stable hook runtime identity changed during Authenticode verification")
	}
	return nil
}

func openStableHookVerificationFile(filePath string) (*os.File, error) {
	if err := winpath.RejectReparseChain(filePath); err != nil {
		return nil, err
	}
	encoded, err := winpath.UTF16Ptr(filePath)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		encoded,
		windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "lock", Path: filePath, Err: err}
	}
	file := os.NewFile(uintptr(handle), filePath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap stable hook verification handle")
	}
	fail := func(cause error) (*os.File, error) {
		_ = file.Close()
		return nil, cause
	}
	var information windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &information); err != nil {
		return fail(err)
	}
	if information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fail(errors.New("stable hook verification path is not a regular non-reparse file"))
	}
	finalPath, err := cleanupFinalPathForHandle(handle)
	if err != nil {
		return fail(err)
	}
	if !samePath(finalPath, filePath) {
		return fail(fmt.Errorf(
			"stable hook verification final identity changed: got %s, want %s",
			finalPath,
			filePath,
		))
	}
	if err := safefile.ValidatePrivateHandle(handle); err != nil {
		return fail(err)
	}
	return file, nil
}
