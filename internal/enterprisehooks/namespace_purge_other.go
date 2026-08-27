//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "errors"

// PurgeWindowsNamespaceRoot is unavailable outside Windows.
func PurgeWindowsNamespaceRoot(
	request WindowsNamespacePurgeRequest,
) (WindowsNamespacePurgeReport, error) {
	report := WindowsNamespacePurgeReport{
		SchemaVersion:    WindowsNamespacePurgeSchemaVersion,
		Root:             request.Root,
		ExpectedIdentity: request.ExpectedIdentity,
	}
	err := errors.New("enterprise hooks: Windows namespace purge is unsupported on this platform")
	report.Error = err.Error()
	return report, err
}
