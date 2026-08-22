// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func deferredVerifyParentImage(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("invalid parent process identity")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return "", err
	}
	if size == 0 || int(size) > len(buffer) {
		return "", fmt.Errorf("parent process image is empty or oversized")
	}
	return windows.UTF16ToString(buffer[:size]), nil
}
