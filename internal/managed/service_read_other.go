//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// ValidateServiceCanReadTree is a Windows preflight check: there Setup runs
// as LocalSystem while the gateway runs as an NT SERVICE virtual account.
func ValidateServiceCanReadTree(_, _, _ string) error { return nil }
