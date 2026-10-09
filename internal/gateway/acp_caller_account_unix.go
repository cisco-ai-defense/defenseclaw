//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// acpHomePrincipalUID finds the enrolled home inside the service-owned
// directory record. A home principal stores a digest, so walk ancestors of
// its recorded user data directory until one matches. Missing older records
// fail closed; they can be repaired by enrolling again.
func acpHomePrincipalUID(digest, dataDir string) (int, bool) {
	if len(digest) != 64 || !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir {
		return 0, false
	}
	for home := dataDir; ; home = filepath.Dir(home) {
		if fmt.Sprintf("%x", sha256.Sum256([]byte(home))) == digest {
			info, err := os.Lstat(home)
			if err != nil || !info.IsDir() {
				return 0, false
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, false
			}
			return int(stat.Uid), true
		}
		if parent := filepath.Dir(home); parent == home {
			return 0, false
		}
	}
}
