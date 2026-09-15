// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

type rootOwnedIdentityDirectoryInfo struct{}

func (rootOwnedIdentityDirectoryInfo) Name() string       { return "identity" }
func (rootOwnedIdentityDirectoryInfo) Size() int64        { return 0 }
func (rootOwnedIdentityDirectoryInfo) Mode() os.FileMode  { return os.ModeDir | 0o700 }
func (rootOwnedIdentityDirectoryInfo) ModTime() time.Time { return time.Time{} }
func (rootOwnedIdentityDirectoryInfo) IsDir() bool        { return true }
func (rootOwnedIdentityDirectoryInfo) Sys() any           { return &syscall.Stat_t{Uid: 0} }

func TestIdentityDirectoryNamesRootOwnedSudoLeftover(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root caller")
	}
	err := validateFreshIdentityDirectoryPlatform(
		"/private/runtime",
		rootOwnedIdentityDirectoryInfo{},
	)
	if err == nil || !strings.Contains(err.Error(), "root-owned from a sudo-started gateway") {
		t.Fatalf("root-owned directory diagnostic=%v", err)
	}
}
