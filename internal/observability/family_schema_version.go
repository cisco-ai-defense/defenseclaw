// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

// FamilySchemaVersion returns the generated canonical schema version for one
// exact family ID. Physical trace producers use this authority so SDK span
// control attributes stay in parity when an individual family advances.
func FamilySchemaVersion(familyID string) (int64, bool) {
	contract, ok := generatedFamilyBaseContracts[familyID]
	if !ok || contract.familySchemaVersion == 0 {
		return 0, false
	}
	return int64(contract.familySchemaVersion), true
}
