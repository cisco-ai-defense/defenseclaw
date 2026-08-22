// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/windows"
)

func deferredVerifyParentImage(pid int) (deferredVerifyProcessIdentity, error) {
	if pid <= 0 {
		return deferredVerifyProcessIdentity{}, fmt.Errorf("invalid parent process identity")
	}
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE,
		false,
		uint32(pid),
	)
	if err != nil {
		return deferredVerifyProcessIdentity{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = windows.CloseHandle(handle)
		}
	}()
	actualPID, err := windows.GetProcessId(handle)
	if err != nil {
		return deferredVerifyProcessIdentity{}, err
	}
	if actualPID != uint32(pid) {
		return deferredVerifyProcessIdentity{}, errors.New("opened parent process identity changed")
	}
	if err := requireDeferredVerifyProcessLive(handle); err != nil {
		return deferredVerifyProcessIdentity{}, err
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return deferredVerifyProcessIdentity{}, err
	}
	if size == 0 || int(size) > len(buffer) {
		return deferredVerifyProcessIdentity{}, fmt.Errorf("parent process image is empty or oversized")
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return deferredVerifyProcessIdentity{}, err
	}
	startIdentity := creation.Nanoseconds()
	if startIdentity <= 0 {
		return deferredVerifyProcessIdentity{}, errors.New("parent process start identity is invalid")
	}
	if err := requireDeferredVerifyProcessLive(handle); err != nil {
		return deferredVerifyProcessIdentity{}, err
	}
	var handleMu sync.Mutex
	handleClosed := false
	closeOnError = false
	return deferredVerifyProcessIdentity{
		ImagePath:     windows.UTF16ToString(buffer[:size]),
		StartIdentity: strconv.FormatInt(startIdentity, 10),
		requireLive: func() error {
			handleMu.Lock()
			defer handleMu.Unlock()
			if handleClosed {
				return os.ErrProcessDone
			}
			actualPID, err := windows.GetProcessId(handle)
			if err != nil {
				return err
			}
			if actualPID != uint32(pid) {
				return errors.New("opened parent process identity changed")
			}
			return requireDeferredVerifyProcessLive(handle)
		},
		close: func() error {
			handleMu.Lock()
			defer handleMu.Unlock()
			if handleClosed {
				return nil
			}
			handleClosed = true
			return windows.CloseHandle(handle)
		},
	}, nil
}

func requireDeferredVerifyProcessLive(handle windows.Handle) error {
	waitResult, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return err
	}
	if waitResult == uint32(windows.WAIT_OBJECT_0) {
		return os.ErrProcessDone
	}
	if waitResult != uint32(windows.WAIT_TIMEOUT) {
		return fmt.Errorf("unexpected parent process wait result %#x", waitResult)
	}
	return nil
}
