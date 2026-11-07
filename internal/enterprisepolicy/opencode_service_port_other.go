//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

func writeOpenCodeServiceConfig(_ string, path string, data []byte) error {
	return writePrivateUserFile(path, data)
}
