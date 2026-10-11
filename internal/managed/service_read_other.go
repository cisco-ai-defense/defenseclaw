//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

// ValidateServiceCanReadTree is a Windows preflight check: there Setup runs
// as LocalSystem while the gateway runs as an NT SERVICE virtual account.
func ValidateServiceCanReadTree(_, _, _ string) error { return nil }

// IsServiceAccountUnresolved is false off Windows: there is no account to
// resolve.
func IsServiceAccountUnresolved(error) bool { return false }

// ValidateServiceCanWriteFile is a Windows preflight check, like
// ValidateServiceCanReadTree.
func ValidateServiceCanWriteFile(_, _ string) error { return nil }
