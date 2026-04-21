// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
)

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// SynthesizeRuleID builds "<scanner>.<category>.<slug>" when upstream
// scanners omit rule_id. Never returns an empty string.
func SynthesizeRuleID(scannerName, category, title, id string) string {
	cat := strings.TrimSpace(category)
	if cat == "" {
		cat = "finding"
	}
	slug := slugify(title)
	if slug == "" {
		slug = slugify(id)
	}
	if slug == "" {
		slug = "unknown"
	}
	prefix := scannerSlugPrefix(scannerName)
	return prefix + "." + cat + "." + slug
}

// EnsureRuleID returns f.RuleID when set, otherwise SynthesizeRuleID.
func EnsureRuleID(f *Finding, scannerName string) string {
	if f == nil {
		return SynthesizeRuleID(scannerName, "finding", "", "")
	}
	if strings.TrimSpace(f.RuleID) != "" {
		return f.RuleID
	}
	return SynthesizeRuleID(scannerName, f.Category, f.Title, f.ID)
}

func scannerSlugPrefix(scannerName string) string {
	s := strings.TrimSpace(scannerName)
	if s == "" {
		return "scanner"
	}
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	// Collapse common suffixes for readability.
	s = strings.TrimSuffix(s, "-scanner")
	if s == "" {
		return "scanner"
	}
	return s
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	s = nonSlug.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if len(s) > 64 {
		s = s[:64]
		s = strings.Trim(s, "-")
	}
	return s
}
