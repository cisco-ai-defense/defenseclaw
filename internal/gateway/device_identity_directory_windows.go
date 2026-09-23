// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validateDeviceIdentityPathSyntax(target, dataDir string) error {
	for _, path := range []string{target, dataDir} {
		volume := filepath.VolumeName(path)
		if strings.Contains(path[len(volume):], ":") {
			return fmt.Errorf("gateway: device identity paths cannot use Windows alternate data streams")
		}
	}
	return nil
}

// Windows path ownership and full-chain reparse checks are enforced by
// safefile.ValidatePrivateDirectory immediately after this platform hook.
func validateFreshIdentityDirectoryPlatform(_ string, _ os.FileInfo) error { return nil }

func validateFreshIdentityFilePlatform(string) error { return nil }

// Windows does not support fsync on an opened directory handle. The file
// handle itself is flushed before this hook is reached.
func syncFreshIdentityDirectory(string) error { return nil }
