// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// managedHookUserProfileDir is the home directory the account database gives
// the process's uid (hookAccountHome). HOME is not read: the agent runtime
// that starts the hook can point it at any folder or unset it.
func managedHookUserProfileDir() (string, error) {
	uid := os.Geteuid()
	home, err := hookAccountHome(uid)
	if err != nil {
		return "", err
	}
	home = strings.TrimSpace(home)
	if !filepath.IsAbs(home) || filepath.Clean(home) == "/" {
		return "", fmt.Errorf("uid %d has no usable home directory in the account database (%q)", uid, home)
	}
	return filepath.Clean(home), nil
}
