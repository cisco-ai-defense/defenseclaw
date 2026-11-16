// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// LoadWindowsInventoryGrantLedger reads the grant ledger for manifestPath. A
// missing ledger returns an os.ErrNotExist error; one that is not an exact
// SYSTEM and Administrators only file, or does not parse, is refused.
func LoadWindowsInventoryGrantLedger(manifestPath string) ([]ManifestTarget, error) {
	data, err := readWindowsProtectedRecord(InventoryGrantLedgerPath(manifestPath), inventoryGrantLedgerMaxBytes)
	if err != nil {
		return nil, err
	}
	return ParseInventoryGrantLedger(data)
}

// SaveWindowsInventoryGrantLedger publishes the grant ledger for
// manifestPath.
func SaveWindowsInventoryGrantLedger(manifestPath string, targets []ManifestTarget) error {
	data, err := MarshalInventoryGrantLedger(targets)
	if err != nil {
		return err
	}
	_, err = WriteWindowsProtectedRecordAtomic(InventoryGrantLedgerPath(manifestPath), data)
	return err
}
