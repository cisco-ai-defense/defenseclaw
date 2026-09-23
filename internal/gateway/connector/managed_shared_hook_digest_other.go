//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"strings"
)

func validateManagedSharedHookOpenedFile(_ *os.File, expectedOwnerSID string) error {
	if strings.TrimSpace(expectedOwnerSID) != "" {
		return fmt.Errorf("managed shared hook target SID validation is unsupported on this platform")
	}
	return nil
}
