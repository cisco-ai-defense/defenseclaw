// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Links reports the hard link count of path (followed).
func (osFS) Links(p string) (uint64, bool) {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}

// DentryPath is the name Tetragon gives a dentry of path: its path below
// the root of the file system it is on. It reads /proc/self/mountinfo and
// takes the deepest mount point at or above path.
func (osFS) DentryPath(p string) (string, bool) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", false
	}
	defer file.Close()
	best, bestRoot := "", ""
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		root, point := unescapeMount(fields[3]), unescapeMount(fields[4])
		if !inside(point, p) || len(point) < len(best) {
			continue
		}
		best, bestRoot = point, root
	}
	if scanner.Err() != nil || best == "" {
		return "", false
	}
	rel, err := filepath.Rel(best, p)
	if err != nil {
		return "", false
	}
	return filepath.Join(bestRoot, rel), true
}

// unescapeMount undoes mountinfo's octal escapes of space, tab, newline and
// backslash.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, ok := octal3(s[i+1 : i+4]); ok {
				b.WriteByte(v)
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func octal3(s string) (byte, bool) {
	if len(s) != 3 {
		return 0, false
	}
	v := 0
	for _, c := range []byte(s) {
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v*8 + int(c-'0')
	}
	if v > 255 {
		return 0, false
	}
	return byte(v), true
}
