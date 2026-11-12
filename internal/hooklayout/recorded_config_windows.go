// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Package hooklayout resolves the per-user hook runtime's recorded layout.
package hooklayout

// RecordedConfig has no Windows sidecar; Windows uses installed runtime state.
func RecordedConfig(string) string { return "" }

// RecordedInstallHome has no Windows sidecar; Windows uses installed runtime state.
func RecordedInstallHome(string) string { return "" }
