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

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/procimage"
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

// ProcessImagePath is the one macOS resolver for the image a process runs.
// The gateway status same-home proof uses it; the call itself is
// procimage.Path, shared with internal/openshell.
func ProcessImagePath(pid int) (string, error) { return processImagePath(pid) }

// processImagePath is the kernel's absolute path of the image process pid
// runs (procimage.Path, the one proc_info caller).
func processImagePath(pid int) (string, error) { return procimage.Path(pid) }
