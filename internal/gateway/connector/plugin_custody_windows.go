// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// explainPluginArtifactRefusal adds the command that clears a refused plugin
// folder DACL to the refusal (GAP-0731). safefile names the account whose
// entry makes the DACL unsafe and the folder that holds the entry itself; the
// entry is removed there, because removing it from an inheriting child does
// nothing. Any other cause, and a DACL refusal that names no single entry,
// is returned unchanged.
func explainPluginArtifactRefusal(_ string, cause error) error {
	var refusal *safefile.UnsafePrivateDACLError
	if !errors.As(cause, &refusal) || refusal.Trustee == "" || refusal.Carrier == "" {
		return cause
	}
	scope := ":g"
	if refusal.Deny {
		scope = ":d"
	}
	fix := "icacls \"" + refusal.Carrier + "\" /remove" + scope + " \"" + refusal.Trustee + "\""
	return &pluginCustodyError{cause: cause, failing: []string{refusal.Carrier}, fix: fix}
}
