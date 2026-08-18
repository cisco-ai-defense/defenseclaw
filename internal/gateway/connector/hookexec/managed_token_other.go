// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"
)

// readManagedTokenFile closes the metadata/read TOCTOU window left by a prior
// managed-runtime validation. Managed enterprise mode is supported outside
// Windows, so this reader mirrors the identity-pinning, alias rejection, and
// bounded stable double-read the Windows reader performs: reject symlinks
// up front, refuse hard-linked aliases, and require the two reads to observe
// the same size, mod-time, and bytes on the same inode.
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
	// O_NOFOLLOW closes the Lstat/Open TOCTOU window at the syscall boundary
	// on every Unix that DefenseClaw ships on.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
	if stat, ok := opened.Sys().(*syscall.Stat_t); ok && stat.Nlink != 1 {
		return nil, fmt.Errorf(
			"managed hook token must be a single-link regular file (links=%d)",
			stat.Nlink,
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
