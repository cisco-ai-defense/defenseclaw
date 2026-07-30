// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestReadRegularFileBoundedRejectsNamedPipeWithoutBlocking(t *testing.T) {
	pipePath := fmt.Sprintf(
		`\\.\pipe\defenseclaw-safefile-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
	name, err := windows.UTF16PtrFromString(pipePath)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateNamedPipe(
		name,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|
			windows.PIPE_NOWAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1,
		4096,
		4096,
		0,
		nil,
	)
	if err != nil {
		t.Fatalf("CreateNamedPipe: %v", err)
	}
	defer windows.CloseHandle(handle)

	result := make(chan error, 1)
	go func() {
		_, readErr := ReadRegularFileBounded(pipePath, 1024)
		result <- readErr
	}()

	select {
	case readErr := <-result:
		if readErr == nil {
			t.Fatal("ReadRegularFileBounded accepted a Windows named pipe")
		}
	case <-time.After(2 * time.Second):
		_ = windows.CloseHandle(handle)
		t.Fatal("ReadRegularFileBounded blocked while opening a Windows named pipe")
	}
}
