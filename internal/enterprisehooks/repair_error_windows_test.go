// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestWindowsUserRuntimeMissingRepairClassifiesOnlyMissingFiles(t *testing.T) {
	for _, cause := range []error{os.ErrNotExist, os.ErrPermission, errors.New("untrusted path"), nil} {
		var input error
		if cause != nil {
			input = fmt.Errorf("read per-user runtime: %w", cause)
		}
		got := windowsUserRuntimeMissingRepair(input)
		if IsWindowsUserRuntimeRepairRequired(got) != errors.Is(cause, os.ErrNotExist) {
			t.Fatalf("cause=%v classified as repair: %v", cause, got)
		}
		if !errors.Is(got, cause) {
			t.Fatalf("cause=%v lost by classification: %v", cause, got)
		}
	}
}
