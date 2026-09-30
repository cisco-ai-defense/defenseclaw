//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

const loginDefsPath = "/etc/login.defs"

var (
	localPasswdPath = "/etc/passwd"
	nsswitchPath    = "/etc/nsswitch.conf"
)

// platformLocalAccounts reads /etc/passwd, the files backend itself.
func platformLocalAccounts(context.Context) (map[string]int, error) {
	data, err := readSmallFile(localPasswdPath, 16<<20)
	if err != nil {
		return nil, err
	}
	return parseLocalPasswd(string(data)), nil
}

// platformDirectoryConfigured reads the passwd sources of nsswitch.conf. A
// missing file is glibc's default (files only); an unreadable one is
// treated as a directory host.
func platformDirectoryConfigured() bool {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	return ParseNSSwitchDirectoryConfigured(string(data))
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("unixidentity: %s exceeds %d bytes", path, limit)
	}
	return data, nil
}

// DefaultUIDRange reads UID_MIN/UID_MAX from /etc/login.defs, falling back
// to the shadow-utils defaults.
func DefaultUIDRange() (int, int) {
	file, err := os.Open(loginDefsPath)
	if err != nil {
		return 1000, 60000
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 256<<10))
	if err != nil {
		return 1000, 60000
	}
	return ParseLoginDefsUIDRange(string(data), 1000, 60000)
}

// Default returns the NSS resolver when a trusted getent exists, otherwise
// os/user, which sees only /etc/passwd and /etc/group.
func Default(ctx context.Context) Resolver {
	if nss, err := NewNSSResolver(ctx); err == nil {
		return NewCachingResolver(nss)
	}
	return NewCachingResolver(NewOSUserResolver(ctx))
}

// platformLocalUserLister has nothing better than NSS on Linux; the
// files-only fallback does not enumerate.
func platformLocalUserLister(context.Context, commandRunner) ([]Account, error) {
	return nil, nil
}
