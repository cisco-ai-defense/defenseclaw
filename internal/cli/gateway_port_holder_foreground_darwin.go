// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package cli

import (
	"bytes"
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// sameHomeGatewayProcessPlatform diagnoses an account-owned foreground gateway
// without a PID record. The caller has already checked the listener UID; this
// result never authorizes a token or process control.
func sameHomeGatewayProcessPlatform(pid int, home, executable string) bool {
	before, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || before == nil || before.Proc.P_pid != int32(pid) || int(before.Eproc.Ucred.Uid) != os.Getuid() {
		return false
	}
	image, err := enterpriseunix.ProcessImagePath(pid)
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
	var environment []string
	for len(rest) > 0 {
		end = bytes.IndexByte(rest, 0)
		if end < 0 {
			return "", false
		}
		if end == 0 {
			break
		}
		environment = append(environment, string(rest[:end]))
		rest = rest[end+1:]
	}
	return foregroundLaunchHome(environment)
}
