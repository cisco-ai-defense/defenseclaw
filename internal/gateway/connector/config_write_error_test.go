// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestConfigWriteErrorCarriesTargetAndPermissionCause(t *testing.T) {
	path := "/home/user/.claude/settings.json"
	cause := fmt.Errorf("rename: %w", os.ErrPermission)
	err := configWriteError(path, cause)
	var typed *ConfigNotWritableError
	if !errors.As(err, &typed) || !errors.Is(err, ErrConfigNotWritable) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("config write error lost type or OS cause: %v", err)
	}
	if typed.Path != path || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "tombstone") {
		t.Fatalf("config write error did not name the target cleanly: %v", err)
	}
	other := errors.New("target changed")
	if got := configWriteError(path, other); got != other {
		t.Fatalf("non-permission error was reclassified: %v", got)
	}
}
