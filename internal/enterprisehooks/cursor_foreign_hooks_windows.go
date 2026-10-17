// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "errors"

// verifyWindowsCursorPublishedApprovedForeignHooks compares the allowlist in
// protected Cursor machine state with the administrator configuration, so a
// configuration change is reported and repaired by the next reconcile. A nil
// configured value means the caller has no configuration and skips the check.
func verifyWindowsCursorPublishedApprovedForeignHooks(configured []string) error {
	if configured == nil {
		return nil
	}
	artifacts, err := snapshotWindowsCursorManagedPublicArtifacts()
	if err != nil {
		return err
	}
	artifacts, err = validateWindowsCursorManagedPublicArtifacts(artifacts)
	if err != nil {
		return err
	}
	if !artifacts.active {
		return errors.New("enterprise hooks: Cursor enterprise policy is inactive")
	}
	equal, err := equalWindowsCursorApprovedForeignHooks(
		artifacts.parsed.ApprovedForeignHookSHA256,
		configured,
	)
	if err != nil {
		return err
	}
	if !equal {
		return errors.New(
			"enterprise hooks: published Cursor foreign-hook allowlist differs from connector_hooks.cursor.approved_foreign_hooks",
		)
	}
	return nil
}
