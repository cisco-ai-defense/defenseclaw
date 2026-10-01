// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

const (
	// WindowsNamespacePurgeSchemaVersion is the exact request/report contract
	// understood by the native Windows namespace cleanup boundary.
	WindowsNamespacePurgeSchemaVersion = 1
	// WindowsNamespacePurgeModeUninstallStatePurge is a separately authorized
	// post-commit purge of the exact production ProgramData StateRoot. The
	// empty mode retains the original canonical InstallRoot contract.
	WindowsNamespacePurgeModeUninstallStatePurge = "uninstall_state_purge"
	// WindowsNamespacePurgeModeUninstallInstallPurge seals or removes the
	// identity-bound production InstallRoot during managed uninstall.
	WindowsNamespacePurgeModeUninstallInstallPurge = "uninstall_install_purge"
	WindowsNamespacePurgeOperationSealOnly         = "seal_only"
	WindowsNamespacePurgeOperationDelete           = "delete"
)

// WindowsNamespacePurgeRequest authorizes cleanup of one already-identified
// managed directory tree. The native implementation derives every accepted
// descriptor from GatewayServiceSID; callers cannot supply an ACL allowlist.
//
// ExpectedIdentity is required for an existing root. An empty identity only
// authorizes an absent-root no-op in canonical mode and can never adopt a
// path that appeared after the caller's absence check. The uninstall modes
// require the historical identity even if the root has already been removed.
type WindowsNamespacePurgeRequest struct {
	SchemaVersion     int    `json:"schema_version"`
	Mode              string `json:"mode,omitempty"`
	Operation         string `json:"operation,omitempty"`
	Root              string `json:"root"`
	ExpectedIdentity  string `json:"expected_identity"`
	GatewayServiceSID string `json:"gateway_service_sid"`
	ValidateOnly      bool   `json:"validate_only"`
}

// WindowsNamespacePurgeReport records the exact outcome of one native cleanup
// attempt. A successful seal_only report has Removed=false and
// EntriesRemoved=0; deletion counts the root itself when removal succeeds.
type WindowsNamespacePurgeReport struct {
	SchemaVersion    int    `json:"schema_version"`
	OK               bool   `json:"ok"`
	Root             string `json:"root"`
	ExpectedIdentity string `json:"expected_identity"`
	Removed          bool   `json:"removed"`
	EntriesRemoved   int    `json:"entries_removed"`
	Error            string `json:"error"`
}
