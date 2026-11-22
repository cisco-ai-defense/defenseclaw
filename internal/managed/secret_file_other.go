// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

// RejectUntrustedSecretReaders is the Windows DACL check; POSIX callers check
// the mode and owner of the open file instead.
func RejectUntrustedSecretReaders(string) error { return nil }
