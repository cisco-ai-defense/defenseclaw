//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "errors"

// grantPublishedSessionReader has no access-list support here: no record is
// written, so the hook blocks during an outage.
func grantPublishedSessionReader(string, uint32) error {
	return errors.New("protected session records are not supported on this platform")
}
