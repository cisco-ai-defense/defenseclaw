//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// publishedSessionVolumeIsReadOnly reports a path on a read-only volume
// (FILE_READ_ONLY_VOLUME).
func publishedSessionVolumeIsReadOnly(path string) (bool, error) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false, err
	}
	volume := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumePathName(pointer, &volume[0], uint32(len(volume))); err != nil {
		return false, err
	}
	var flags uint32
	if err := windows.GetVolumeInformation(&volume[0], nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return false, err
	}
	return flags&windows.FILE_READ_ONLY_VOLUME != 0, nil
}
