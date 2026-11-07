// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// sameHomeGatewayProcessDarwin diagnoses an account-owned foreground gateway
// without a PID record. The caller has already checked the listener UID; this
// result never authorizes a token or process control.
func sameHomeGatewayProcessPlatform(pid int, home, executable string) bool {
	before, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || before == nil || before.Proc.P_pid != int32(pid) || int(before.Eproc.Ucred.Uid) != os.Getuid() {
		return false
	}
	image, err := darwinForegroundProcessImage(pid)
	if err != nil || !sameForegroundFile(image, executable) {
		return false
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return false
	}
	processHome, ok := darwinForegroundProcessHome(raw)
	if !ok || !sameForegroundFile(processHome, home) {
		return false
	}
	after, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && after != nil && after.Proc.P_pid == before.Proc.P_pid &&
		after.Proc.P_starttime == before.Proc.P_starttime && after.Eproc.Ucred.Uid == before.Eproc.Ucred.Uid
}

func sameForegroundFile(left, right string) bool {
	if !filepath.IsAbs(left) || !filepath.IsAbs(right) {
		return false
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

// darwinForegroundProcessImage mirrors proc_pidpath without linking cgo.
func darwinForegroundProcessImage(pid int) (string, error) {
	const (
		sysProcInfo           = 336
		procInfoCallPIDInfo   = 2
		procPIDPathInfo       = 11
		procPIDPathInfoMaxLen = 4096
	)
	buf := make([]byte, procPIDPathInfoMaxLen)
	n, _, errno := syscall.Syscall6(sysProcInfo, procInfoCallPIDInfo, uintptr(pid), procPIDPathInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if errno != 0 {
		return "", errno
	}
	if n == 0 || int(n) > len(buf) {
		return "", syscall.EINVAL
	}
	if end := bytes.IndexByte(buf[:n], 0); end >= 0 {
		buf = buf[:end]
	} else {
		buf = buf[:n]
	}
	if len(buf) == 0 {
		return "", syscall.EINVAL
	}
	return string(buf), nil
}

// darwinForegroundProcessHome reads only the launch home from kern.procargs2.
func darwinForegroundProcessHome(raw []byte) (string, bool) {
	if len(raw) < 5 || len(raw) > 256*1024+4 {
		return "", false
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	rest := raw[4:]
	end := bytes.IndexByte(rest, 0)
	if argc <= 0 || argc > len(rest) || end < 0 {
		return "", false
	}
	rest = bytes.TrimLeft(rest[end:], "\x00")
	for range argc {
		end = bytes.IndexByte(rest, 0)
		if end < 0 {
			return "", false
		}
		rest = rest[end+1:]
	}
	rest = bytes.TrimLeft(rest, "\x00")
	var override, userHome string
	seenOverride, seenHome := false, false
	for len(rest) > 0 {
		end = bytes.IndexByte(rest, 0)
		if end < 0 {
			return "", false
		}
		if end == 0 {
			break
		}
		entry := string(rest[:end])
		rest = rest[end+1:]
		if strings.HasPrefix(entry, "DEFENSECLAW_HOME=") {
			if seenOverride {
				return "", false
			}
			seenOverride = true
			override = entry[len("DEFENSECLAW_HOME="):]
		} else if strings.HasPrefix(entry, "HOME=") {
			if seenHome {
				return "", false
			}
			seenHome = true
			userHome = entry[len("HOME="):]
		}
	}
	if seenOverride && override != "" {
		if !filepath.IsAbs(override) {
			return "", false
		}
		return override, true
	}
	if seenHome && filepath.IsAbs(userHome) {
		return filepath.Join(userHome, config.DefaultDataDirName), true
	}
	return "", false
}
