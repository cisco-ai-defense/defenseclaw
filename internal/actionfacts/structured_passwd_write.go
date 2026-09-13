// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"strconv"
	"strings"
)

const posixPasswdPath = "/etc/passwd"

var posixPasswdUserName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*[$]?$`)

// POSIXNonRootUIDZeroAccountWriteFact is a value-free proof that one closed
// structured write replaces /etc/passwd with complete records containing a
// non-root account whose UID field is exactly zero. No account name, password
// field, file content, home directory, or shell crosses the ActionFacts
// boundary.
type POSIXNonRootUIDZeroAccountWriteFact struct{}

// ExactPOSIXNonRootUIDZeroAccountWrite reports only the reviewed closed proof.
func ExactPOSIXNonRootUIDZeroAccountWrite(facts Facts) bool {
	return facts.Authoritative() && facts.EnforcementEligible() &&
		len(facts.POSIXNonRootUIDZeroAccountWrites) == 1
}

func projectPOSIXNonRootUIDZeroAccountWrites(
	input Input,
) []POSIXNonRootUIDZeroAccountWriteFact {
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
	if !targetOK || !contentOK || target != posixPasswdPath ||
		content == "" || len(content) > maxCommandBytes ||
		strings.ContainsAny(content, "\x00\r") ||
		containsUnresolvedPasswdTemplate(content) ||
		!containsCompleteNonRootUIDZeroPasswdRecord(content) {
		return nil
	}
	return []POSIXNonRootUIDZeroAccountWriteFact{{}}
}

func exactStructuredWriteTool(tool string) bool {
	switch strings.ToLower(tool) {
	case "write_file", "write-file", "writefile":
		return true
	default:
		return false
	}
}

func containsUnresolvedPasswdTemplate(content string) bool {
	return strings.Contains(content, "${") ||
		strings.Contains(content, "$(") ||
		strings.Contains(content, "{{") ||
		strings.Contains(content, "}}") ||
		strings.ContainsRune(content, '`')
}

func containsCompleteNonRootUIDZeroPasswdRecord(content string) bool {
	if strings.HasSuffix(content, "\n") {
		content = strings.TrimSuffix(content, "\n")
	}
	if content == "" || strings.HasSuffix(content, "\n") {
		return false
	}
	seenUsers := make(map[string]struct{})
	found := false
	for _, line := range strings.Split(content, "\n") {
		if line == "" || strings.TrimSpace(line) != line ||
			strings.HasPrefix(line, "#") {
			return false
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 || !validCompletePOSIXPasswdRecord(fields) {
			return false
		}
		if _, duplicate := seenUsers[fields[0]]; duplicate {
			return false
		}
		seenUsers[fields[0]] = struct{}{}
		if fields[0] != "root" && fields[2] == "0" {
			found = true
		}
	}
	return found
}

func validCompletePOSIXPasswdRecord(fields []string) bool {
	if len(fields) != 7 || !posixPasswdUserName.MatchString(fields[0]) ||
		fields[1] == "" || strings.IndexFunc(fields[1], passwdControlOrSpace) >= 0 ||
		!canonicalPasswdID(fields[2]) || !canonicalPasswdID(fields[3]) ||
		strings.IndexFunc(fields[4], passwdControl) >= 0 ||
		!exactAbsolutePasswdField(fields[5]) ||
		!exactAbsolutePasswdField(fields[6]) {
		return false
	}
	return true
}

func canonicalPasswdID(value string) bool {
	if value == "" || value != "0" && strings.HasPrefix(value, "0") {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(value, 10, 32)
	return err == nil
}

func exactAbsolutePasswdField(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" &&
		strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, passwdControlOrSpace) < 0
}

func passwdControl(r rune) bool {
	return r < ' ' || r == 0x7f
}

func passwdControlOrSpace(r rune) bool {
	return passwdControl(r) || r == ' '
}
