// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"

	"golang.org/x/sys/windows"
)

// guardianRecordReplaceBusy reports a guardian record read that met the
// guardian's replacement of the record (or of its ACL): Windows answers with
// a sharing or lock violation for that moment.
func guardianRecordReplaceBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
