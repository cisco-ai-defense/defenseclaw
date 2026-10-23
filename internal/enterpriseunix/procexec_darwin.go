// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterpriseunix

import (
	"bytes"
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// processExecPath reads the executable path from kern.procargs2: a 32-bit
// argc followed by the NUL-terminated path execve resolved through PATH
// (a relative path stays relative).
func processExecPath(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(buf) < 5 {
		return "", errors.New("short kern.procargs2")
	}
	path := buf[4:]
	if end := bytes.IndexByte(path, 0); end >= 0 {
		path = path[:end]
	}
	return string(path), nil
}

// processImagePath asks the kernel for the absolute path of the image
// process pid runs, as proc_pidpath(3) does (proc_info PROC_PIDPATHINFO).
// Unlike the exec path it does not depend on the working directory the
// process had at exec time. It fails when that path no longer names a file.
func processImagePath(pid int) (string, error) {
	// libproc's proc_pidpath is this one call; the binaries build without
	// cgo, so it is made directly.
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
