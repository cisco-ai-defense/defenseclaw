// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"testing"
)

// GAP-1674: a standalone ensure with a relative --config is invalid
// arguments (1639) before anything opens the file, as the troubleshooting
// page and Linux say, not a 1603 preflight failure.
func TestWindowsStandaloneEnsureRefusesARelativeConfigAsInvalidArguments(t *testing.T) {
	opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", configPath: "relative.yaml"}
	err := resolveWindowsEnterpriseLifecycleProfile("ensure", opts)
	if !errors.Is(err, errWindowsEnterpriseInvalidArguments) {
		t.Fatalf("relative --config: err=%v, want invalid arguments", err)
	}
}
