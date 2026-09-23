// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// readManagedTokenFile closes the metadata/read TOCTOU window left by a prior
// managed-runtime validation. The target user can still write the token by
// design, so the hook must pin identity, reject reparse/hard-link aliases, cap
// allocation, and require two byte-identical reads from the same handle.
func readManagedTokenFile(path string, maxBytes int64) ([]byte, error) {
	expected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if expected.Mode()&os.ModeSymlink != 0 || !expected.Mode().IsRegular() {
		return nil, fmt.Errorf("managed hook token is not a regular non-link file")
	}
	if expected.Size() < 0 || expected.Size() > maxBytes {
		return nil, fmt.Errorf("managed hook token exceeds %d-byte limit", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return nil, fmt.Errorf("managed hook token changed identity before open")
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(
		windows.Handle(file.Fd()),
		&handleInfo,
	); err != nil {
		return nil, err
	}
	if handleInfo.FileAttributes&
		(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		handleInfo.NumberOfLinks != 1 {
		return nil, fmt.Errorf(
			"managed hook token must be a no-reparse single-link regular file (links=%d)",
			handleInfo.NumberOfLinks,
		)
	}
	readOnce := func() ([]byte, error) {
		data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maxBytes {
			return nil, fmt.Errorf(
				"managed hook token exceeds %d-byte limit",
				maxBytes,
			)
		}
		return data, nil
	}
	first, err := readOnce()
	if err != nil {
		return nil, err
	}
	between, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	second, err := readOnce()
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if current.Mode()&os.ModeSymlink != 0 ||
		!current.Mode().IsRegular() ||
		!os.SameFile(opened, current) ||
		opened.Size() != int64(len(first)) ||
		between.Size() != opened.Size() ||
		after.Size() != opened.Size() ||
		!between.ModTime().Equal(opened.ModTime()) ||
		!after.ModTime().Equal(opened.ModTime()) ||
		!bytes.Equal(first, second) {
		return nil, fmt.Errorf("managed hook token changed during bounded read")
	}
	return first, nil
}
