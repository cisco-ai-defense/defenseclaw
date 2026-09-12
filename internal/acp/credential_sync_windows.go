//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

// Windows MoveFile and DeleteFile semantics provide the required process-level
// revocation ordering. Go cannot portably flush a directory handle on Windows.
func syncEnterpriseCredentialDirectory(string) error { return nil }
