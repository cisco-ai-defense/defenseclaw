// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"errors"
	"fmt"
	"unsafe"

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
	sourceMetadata, err := inspectEmbeddedAuthenticode(source)
	if err != nil {
		return err
	}
	publishedMetadata, err := inspectEmbeddedAuthenticode(published)
	if err != nil {
		return err
	}
	if sourceMetadata.Present != publishedMetadata.Present ||
		sourceMetadata.SignerThumbprintSHA256 != publishedMetadata.SignerThumbprintSHA256 ||
		sourceMetadata.RFC3161TimestampPresent != publishedMetadata.RFC3161TimestampPresent {
		return errors.New("stable hook runtime Authenticode identity differs from installed source")
	}
	if sourceMetadata.Present {
		if err := verifyEmbeddedAuthenticodeTrust(published); err != nil {
			return fmt.Errorf("verify stable hook runtime Authenticode: %w", err)
		}
	}
	return nil
}
