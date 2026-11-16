//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

func loadExistingCorrelationKeyForOwnerPlatform(_ string, _ uint32) (CorrelationKey, error) {
	return CorrelationKey{}, keyStoreError(KeyStoreErrorUnsupported)
}
