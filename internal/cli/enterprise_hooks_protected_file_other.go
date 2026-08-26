// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import "github.com/defenseclaw/defenseclaw/internal/safefile"

func writeEnterpriseHookProtectedFile(path string, data []byte) error {
	return safefile.Write(path, data)
}
