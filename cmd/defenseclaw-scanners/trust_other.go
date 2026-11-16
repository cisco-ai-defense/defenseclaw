//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

// The embedded scanner runtime runs only on Windows.
func validateRuntimeCodeTree() error { return nil }
