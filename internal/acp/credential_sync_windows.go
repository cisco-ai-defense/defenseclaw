//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// MoveFileEx with WRITE_THROUGH makes the authority-removing live-to-tombstone
// transition durable before revocation reports success. Tombstone deletion is
// cleanup only: a crash may restore that inert name, and an idempotent retry
// validates and removes it without restoring bearer authority.
func renameEnterpriseCredentialFile(source, destination string) error {
	sourcePtr, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	destinationPtr, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(sourcePtr, destinationPtr, windows.MOVEFILE_WRITE_THROUGH)
}

// The authority-changing rename is already write-through. Go cannot portably
// flush a Windows directory handle; subsequent removal only retires a tombstone.
func syncEnterpriseCredentialDirectory(string) error { return nil }
