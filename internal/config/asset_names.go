// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

// NormalizeAssetName is the form asset_policy compares skill, MCP and plugin
// names in: trimmed and in Unicode NFC. Terminals type the composed spelling
// of a name like "café" and some tools write the decomposed one; both show
// the same text, so a rule written in one form must match the other
// (GAP-0432). cli/defenseclaw/enforce/admission.py asset_name_key is the
// Python twin.
func NormalizeAssetName(name string) string {
	return norm.NFC.String(strings.TrimSpace(name))
}

// SameAssetName reports whether two asset names name the same asset: equal
// after NormalizeAssetName, ignoring case.
func SameAssetName(a, b string) bool {
	return strings.EqualFold(NormalizeAssetName(a), NormalizeAssetName(b))
}

// sameRuleName compares a rule name with an asset name. A Secure Client
// host keeps the trimmed, case-insensitive compare of main (issue #1092).
func sameRuleName(ruleName, name string, unicodeNames bool) bool {
	if unicodeNames {
		return SameAssetName(ruleName, name)
	}
	return strings.EqualFold(strings.TrimSpace(ruleName), strings.TrimSpace(name))
}
