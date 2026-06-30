// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux && !windows

package connector

import (
	"fmt"
	"runtime"
)

func hookAPIValidateDirectoryACL(path string) error {
	return fmt.Errorf("ACL validation is unavailable for hook API token path %s on %s", path, runtime.GOOS)
}
