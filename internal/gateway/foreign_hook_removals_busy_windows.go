// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"

	"golang.org/x/sys/windows"
)

// foreignHookRemovalsReadBusy reports a ledger read that met the guardian's
// replacement of the ledger: Windows answers with a sharing or lock
// violation for that moment.
func foreignHookRemovalsReadBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
