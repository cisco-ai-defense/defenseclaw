// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"syscall"
)

func hookAPIValidateOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	// Guardian commands normally run as root and may read an existing
	// service-owned token before repairing a user's hook. The long-running
	// gateway runs as the service user and still requires the token to be
	// owned by that service identity.
	if os.Getuid() == 0 || int(stat.Uid) == os.Getuid() {
		return nil
	}
	return fmt.Errorf("hook API token %s uid %d does not match current uid %d", path, stat.Uid, os.Getuid())
}
