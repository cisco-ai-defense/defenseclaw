// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

const (
	// WindowsNamespacePurgeSchemaVersion is the exact request/report contract
	// understood by the native Windows namespace cleanup boundary.
	WindowsNamespacePurgeSchemaVersion = 1
)

// WindowsNamespacePurgeRequest authorizes cleanup of one already-identified
// managed directory tree. The native implementation derives every accepted
// descriptor from GatewayServiceSID; callers cannot supply an ACL allowlist.
//
// ExpectedIdentity is required for an existing root. An empty identity only
// authorizes an absent-root no-op and can never adopt a path that appeared
// after the caller's absence check.
type WindowsNamespacePurgeRequest struct {
	SchemaVersion     int    `json:"schema_version"`
	Root              string `json:"root"`
	ExpectedIdentity  string `json:"expected_identity"`
	GatewayServiceSID string `json:"gateway_service_sid"`
	ValidateOnly      bool   `json:"validate_only"`
}

// WindowsNamespacePurgeReport records the exact outcome of one native cleanup
// attempt. EntriesRemoved includes the root itself when removal succeeds.
type WindowsNamespacePurgeReport struct {
	SchemaVersion    int    `json:"schema_version"`
	OK               bool   `json:"ok"`
	Root             string `json:"root"`
	ExpectedIdentity string `json:"expected_identity"`
	Removed          bool   `json:"removed"`
	EntriesRemoved   int    `json:"entries_removed"`
	Error            string `json:"error"`
}
