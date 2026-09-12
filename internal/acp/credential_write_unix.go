//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import "github.com/defenseclaw/defenseclaw/internal/safefile"

func writeEnterpriseCredentialFile(_, path, _ string, body []byte) error {
	return safefile.WritePrivate(path, body)
}
