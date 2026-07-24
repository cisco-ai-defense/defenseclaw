// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// LockVerifiedGateway opens the exact installer-recorded gateway without
// write/delete sharing, verifies its protected file and digest through the
// held handle, and returns that handle to the caller. Keeping it open until the
// gateway's `start` command completes prevents replacement between digest
// verification and both the management process and daemon child launches.
func LockVerifiedGateway(state State) (*os.File, error) {
	if !state.ColdStartCapable() {
		return nil, errors.New("hook runtime state does not authorize gateway cold start")
	}
	if err := safefile.ValidatePrivateFile(state.GatewayPath); err != nil {
		return nil, fmt.Errorf("validate installer-owned gateway: %w", err)
	}
	path, err := winpath.UTF16Ptr(state.GatewayPath)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		path,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("lock installer-owned gateway: %w", err)
	}
	file := os.NewFile(uintptr(handle), state.GatewayPath)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("open installer-owned gateway handle")
	}
	fail := func(err error) (*os.File, error) {
		_ = file.Close()
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fail(fmt.Errorf("inspect installer-owned gateway handle: %w", err))
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fail(errors.New("installer-owned gateway handle is not a regular non-reparse file"))
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fail(fmt.Errorf("hash installer-owned gateway handle: %w", err))
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), state.GatewaySHA256) {
		return fail(errors.New("installer-owned gateway digest does not match hook runtime state"))
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fail(fmt.Errorf("rewind installer-owned gateway handle: %w", err))
	}
	return file, nil
}
