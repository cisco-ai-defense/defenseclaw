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
