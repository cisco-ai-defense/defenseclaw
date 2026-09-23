// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import "errors"

func requireWindowsEnterpriseDeferredTargetPendingPlatform(ManifestTarget) error {
	return errors.New("enterprise hooks: deferred pending proof requires Windows")
}
