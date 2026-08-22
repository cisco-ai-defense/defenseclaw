// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "errors"

func deferredVerifyParentImage(int) (deferredVerifyProcessIdentity, error) {
	return deferredVerifyProcessIdentity{}, errors.New("deferred uninstall connector verification is Windows-only")
}
