// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestRunInstallRefusesBesideEnterpriseBeforeAnyStateChange(t *testing.T) {
	refusal := errors.New("enterprise deployment present")
	previous := refuseSetupBesideEnterprise
	refuseSetupBesideEnterprise = func() error { return refusal }
	t.Cleanup(func() { refuseSetupBesideEnterprise = previous })

	root := t.TempDir()
	installRoot := filepath.Join(root, "install")
	dataRoot := filepath.Join(root, "data")
	for _, action := range []string{"install", "upgrade", "repair"} {
		code, err := runInstallContext(
			context.Background(),
			options{Action: action, Quiet: true},
			installRoot,
			dataRoot,
		)
		if !errors.Is(err, refusal) || code != 1 {
			t.Fatalf("%s: runInstallContext = (%d, %v), want (1, enterprise refusal)", action, code, err)
		}
		if pathExists(installRoot) || pathExists(dataRoot) {
			t.Fatalf("%s: refused install created per-user state", action)
		}
	}
}
