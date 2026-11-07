// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package procimage

import (
	"bytes"
	"errors"
	"syscall"
	"unsafe"
)

// Path asks the kernel for the absolute path of the image process pid runs,
// as proc_pidpath(3) does. Unlike the exec path it does not depend on the
// working directory the process had at exec time. It fails when that path no
// longer names a file.
func Path(pid int) (string, error) {
	// libproc's proc_pidpath is this one call; the binaries build without
	// cgo, so it is made directly. The kernel returns 0 for this flavor, not
	// the path length (proc_pidpath measures the copied path itself), so the
	// path ends at the first NUL of the zeroed buffer.
	const (
		sysProcInfo           = 336  // SYS_PROC_INFO
		procInfoCallPIDInfo   = 2    // PROC_INFO_CALL_PIDINFO
		procPIDPathInfo       = 11   // PROC_PIDPATHINFO
		procPIDPathInfoMaxLen = 4096 // PROC_PIDPATHINFO_MAXSIZE
	)
	if pid <= 0 {
		return "", errors.New("invalid process id")
	}
	buf := make([]byte, procPIDPathInfoMaxLen)
	_, _, errno := syscall.Syscall6(sysProcInfo, procInfoCallPIDInfo, uintptr(pid), procPIDPathInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return "", errno
	}
	if end := bytes.IndexByte(buf, 0); end >= 0 {
		buf = buf[:end]
	}
	if len(buf) == 0 {
		return "", errors.New("empty process image path")
	}
	return string(buf), nil
}
