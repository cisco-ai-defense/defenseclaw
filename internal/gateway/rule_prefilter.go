// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/rxprefilter"

// firstAcceptedRuleMatchIn is firstAcceptedRuleMatch for a text the scan
// checks against many rules: a rule regex runs only when the text holds the
// literals every match of it contains (rxprefilter; GAP-2279).
func firstAcceptedRuleMatchIn(rule PatternRule, scan *rxprefilter.Text) []int {
	if !scan.MayMatch(rule.Pattern) {
		return nil
	}
	return firstAcceptedRuleMatch(rule, scan.String())
}
