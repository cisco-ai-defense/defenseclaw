// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// RepairWithContentProof runs repair while this process holds path open with
// read sharing only, so no other handle, one opened during the drift
// included, can write, rename or delete it, and the open itself fails while
// such a handle exists. repair runs only when the bytes match the record of
// the last trusted read, and RepairWithContentProof reports true only when
// they still match after it. When it reports false the caller must refuse
// the file; if repair did not run, the file keeps the descriptor the strict
// check refuses in every process (see trust_content.go).
func RepairWithContentProof(path string, repair func()) bool {
	recorded, ok := recordedTrustedContent(path)
	if !ok {
		return false
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		// A sharing violation is a handle that can still write the file.
		return false
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	if digest, ok := trustedContentDigestOf(file); !ok || digest != recorded {
		return false
	}
	repair()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false
	}
	digest, ok := trustedContentDigestOf(file)
	return ok && digest == recorded
}
