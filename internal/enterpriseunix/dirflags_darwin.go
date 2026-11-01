// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterpriseunix

import (
	"strings"

	"golang.org/x/sys/unix"
)

// blockingFlags are the BSD file flags that make a folder refuse chmod,
// chown and changes to its entries.
var blockingFlags = []struct {
	bit  uint32
	name string
}{
	{unix.UF_IMMUTABLE, "uchg"},
	{unix.UF_APPEND, "uappnd"},
	{unix.SF_IMMUTABLE, "schg"},
	{unix.SF_APPEND, "sappnd"},
}

// clearBlockingFlags clears the immutable and append-only flags of path
// (see ensureDir) and names the ones it found.
func clearBlockingFlags(path string) (string, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return "", err
	}
	var names []string
	var set uint32
	for _, flag := range blockingFlags {
		if st.Flags&flag.bit != 0 {
			names = append(names, flag.name)
			set |= flag.bit
		}
	}
	if set == 0 {
		return "", nil
	}
	return strings.Join(names, ","), unix.Chflags(path, int(st.Flags&^set))
}
