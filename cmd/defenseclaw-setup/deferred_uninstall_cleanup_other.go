// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import "errors"

func armDeferredUninstallCleanup(setupTransaction) error {
	return nil
}

func runDeferredUninstallCleanup(options) (int, error) {
	return 1, errors.New("deferred uninstall cleanup is available only on Windows")
}

func supersedeDeferredUninstallCleanup() error {
	return nil
}
