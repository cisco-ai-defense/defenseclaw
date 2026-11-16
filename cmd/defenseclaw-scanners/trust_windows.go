//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "github.com/defenseclaw/defenseclaw/internal/managed"

var runtimeCodeRoot = runtimeRoot

func validateRuntimeCodeTree() error {
	root, err := runtimeCodeRoot()
	if err != nil {
		return err
	}
	return managed.ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime")
}
