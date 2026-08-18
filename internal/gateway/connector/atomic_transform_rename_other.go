// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux && !darwin

package connector

import "fmt"

func moveAtomicTransformPathNoReplace(source, target string) error {
	return fmt.Errorf("atomic compare-and-swap namespace moves are unsupported on this platform: %s -> %s", source, target)
}

func moveAtomicTransformPathNoReplaceAt(_ int, source, target string) error {
	return moveAtomicTransformPathNoReplace(source, target)
}
