// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// explainPluginArtifactRefusal adds the command that clears a refused plugin
// folder DACL to the refusal (GAP-0731). safefile names the account whose
// entry makes the DACL unsafe and every folder that holds the entry itself;
// the entry is removed at each of them, because removing it from an inheriting
// child does nothing and one granted again higher up is inherited again. Any
// other cause, and a DACL refusal that names no single entry, is returned
// unchanged. Several commands are separated by a semicolon, which PowerShell runs
// in turn (&& is not available in Windows PowerShell 5).
func explainPluginArtifactRefusal(_ string, cause error) error {
	var refusal *safefile.UnsafePrivateDACLError
	if !errors.As(cause, &refusal) || refusal.Trustee == "" || len(refusal.Carriers) == 0 {
		return cause
	}
	scope := ":g"
	if refusal.Deny {
		scope = ":d"
	}
	steps := make([]string, len(refusal.Carriers))
	for i, carrier := range refusal.Carriers {
		steps[i] = "icacls \"" + carrier + "\" /remove" + scope + " \"" + refusal.Trustee + "\""
	}
	return &pluginCustodyError{cause: cause, failing: refusal.Carriers, fix: strings.Join(steps, "; ")}
}
