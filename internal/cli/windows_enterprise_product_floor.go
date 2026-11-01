// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// windowsProductFloorRefused is the refusal code of a Windows Setup below
// the release floor of the confirmed bundle, the code the Linux and macOS
// package scripts use.
const windowsProductFloorRefused = "product_floor_refused"

// windowsSetupProductFloorRefusal refuses a Windows Setup that would put
// DefenseClaw candidate (the version of the Setup payload) on a device whose
// confirmed signed bundle requires a later release (min_product_version).
//
// The check runs in the Setup's own staged lifecycle, the payload Setup
// verified, so it never runs the installed binary, and it reads the bundle
// store directly, so it also holds after an uninstall that kept the state.
// It applies only while the trust anchors are installed. With anchors, a
// floor that cannot be read refuses (fail closed), and a repair or ensure
// that keeps the installed release is checked too, as on Linux and macOS.
func windowsSetupProductFloorRefusal(candidate string) error {
	path, err := bundleDefaultAnchors()
	if err != nil {
		return fmt.Errorf("%s: cannot locate the bundle trust anchors, so the release floor of the confirmed policy bundle is unknown: %v; nothing was changed", windowsProductFloorRefused, err)
	}
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%s: cannot check the bundle trust anchors, so the release floor of the confirmed policy bundle is unknown: %v; nothing was changed", windowsProductFloorRefused, err)
	}
	store, err := bundleStore()
	if err != nil {
		return fmt.Errorf("%s: cannot open the policy bundle store, so the release floor of the confirmed policy bundle is unknown: %v; nothing was changed", windowsProductFloorRefused, err)
	}
	floor, err := store.ConfirmedProductFloor()
	if err != nil {
		return fmt.Errorf("%s: cannot read the release floor of the confirmed policy bundle: %v; deliver a new signed bundle with enterprise bundle apply before retrying; nothing was changed", windowsProductFloorRefused, err)
	}
	if err := enterprisebundle.ReleaseFloorRefusal(strings.TrimSpace(candidate), floor); err != nil {
		return fmt.Errorf("%s: %v; nothing was changed", windowsProductFloorRefused, err)
	}
	return nil
}
