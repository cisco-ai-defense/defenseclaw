//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// SelfRepairEnabled is macOS-only: the Windows services repair through their
// own descriptor batches, and Linux has no managed self repair.
func SelfRepairEnabled() bool { return false }

// RepairOwnedObject is macOS-only; elsewhere every result is
// CanonicalUnsupported.
func RepairOwnedObject(object OwnedObject) CanonicalResult {
	return CanonicalResult{Path: object.Path, Kind: object.Kind, Outcome: CanonicalUnsupported}
}

// RepairOwnedObjects is macOS-only; elsewhere every result is
// CanonicalUnsupported.
func RepairOwnedObjects(objects []OwnedObject) []CanonicalResult {
	results := make([]CanonicalResult, 0, len(objects))
	for _, object := range objects {
		results = append(results, RepairOwnedObject(object))
	}
	return results
}
