// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// PrivateAgentInstall is static evidence of one agent copy in an account's
// home. It is deliberately separate from the selected version in a manifest
// row: a supported copy must never hide an older copy the user can launch.
type PrivateAgentInstall struct {
	Connector  string `json:"connector"`
	Version    string `json:"version,omitempty"`
	Path       string `json:"path,omitempty"`
	Incomplete bool   `json:"incomplete,omitempty"`
}

const privateAgentInstallMaxEntries = 1024
const privateAgentInstallMaxFindings = 64
const PrivateAgentInstallMaxFindings = privateAgentInstallMaxFindings

func privateInstallReason(connector, version string) string {
	if version == "" {
		return "the installed agent's version could not be read, so its managed hook contract cannot be verified"
	}
	if refused := privateInstallContractReason(connector, version); refused != "" {
		return refused + "; this copy may ignore managed hooks or the documented version floor, so its tool calls are not protected"
	}
	return ""
}
