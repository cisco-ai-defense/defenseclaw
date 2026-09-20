// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"strings"
)

// POSIXUnrestrictedSudoersGrantWriteFact is a value-free proof of one exact,
// closed-schema write containing a literal unrestricted passwordless grant.
type POSIXUnrestrictedSudoersGrantWriteFact struct{}

var exactUnrestrictedSudoersGrantLine = regexp.MustCompile(
	`^(%?[A-Za-z_][A-Za-z0-9_.-]*|ALL)[\t ]+ALL[\t ]*=[\t ]*\([\t ]*ALL(?:[\t ]*:[\t ]*ALL)?[\t ]*\)[\t ]+NOPASSWD[\t ]*:[\t ]*ALL[\t ]*$`,
)

// ExactPOSIXUnrestrictedSudoersGrantWrite reports only the reviewed structured
// write proof. Unstructured shell writers are deliberately excluded.
func ExactPOSIXUnrestrictedSudoersGrantWrite(facts Facts) bool {
	return facts.Authoritative() && facts.EnforcementEligible() &&
		len(facts.POSIXUnrestrictedSudoersGrantWrites) == 1
}

func projectPOSIXUnrestrictedSudoersGrantWrites(
	input Input,
) []POSIXUnrestrictedSudoersGrantWriteFact {
	if input.Command != "" || len(input.Argv) != 0 ||
		!exactStructuredWriteTool(input.Tool) {
		return nil
	}
	object, problem := exactJSONObject(input.Args)
	if problem.status != "" || len(object) != 2 {
		return nil
	}
	for key := range object {
		if key != "path" && key != "content" {
			return nil
		}
	}
	target, targetOK := object["path"].(string)
	content, contentOK := object["content"].(string)
	if !targetOK || !contentOK || !exactSudoersWriteTarget(target) ||
		content == "" || len(content) > maxCommandBytes ||
		strings.ContainsAny(content, "\x00\r") || containsUnresolvedPasswdTemplate(content) {
		return nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		if exactUnrestrictedSudoersGrantLine.MatchString(line) &&
			!strings.HasPrefix(line, "root ") {
			return []POSIXUnrestrictedSudoersGrantWriteFact{{}}
		}
	}
	return nil
}

func exactSudoersWriteTarget(value string) bool {
	if value == "/etc/sudoers" {
		return true
	}
	const prefix = "/etc/sudoers.d/"
	child := strings.TrimPrefix(value, prefix)
	return child != value && child != "" &&
		!strings.Contains(child, "/") && child != "." && child != ".."
}
