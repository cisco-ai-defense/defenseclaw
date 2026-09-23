// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
	"unicode/utf8"
)

// PAMAuthenticationBypassProof is a value-safe classification of an exact
// structured mutation that installs pam_permit.so in an active PAM auth line.
// It deliberately retains neither the protected path nor any file content.
type PAMAuthenticationBypassProof string

const (
	// PAMAuthenticationBypassFullReplacement proves a closed Write operation
	// that replaces an entire protected PAM configuration file.
	PAMAuthenticationBypassFullReplacement PAMAuthenticationBypassProof = "full_replacement"
	// PAMAuthenticationBypassLiteralInsertion proves a closed Edit operation
	// whose literal replacement adds a new active matching PAM line. The
	// surrounding file is not known, so callers can give this weaker proof a
	// stricter posture than a full replacement.
	PAMAuthenticationBypassLiteralInsertion PAMAuthenticationBypassProof = "literal_insertion"
)

// ExactPAMAuthenticationBypass recognizes only the reviewed structured Write
// and Edit contracts used by coding agents. It does not inspect shell command
// text, resolve paths, read files, or retain attacker-controlled values.
func ExactPAMAuthenticationBypass(input Input) (PAMAuthenticationBypassProof, bool) {
	if input.Command != "" || len(input.Argv) != 0 ||
		strings.TrimSpace(input.Tool) != input.Tool {
		return "", false
	}

	object, problem := exactJSONObject(input.Args)
	if problem.status != "" {
		return "", false
	}

	switch {
	case strings.EqualFold(input.Tool, "Write"):
		if len(object) != 2 || !exactPAMObjectKeys(object, "file_path", "content") {
			return "", false
		}
		target, pathOK := object["file_path"].(string)
		content, contentOK := object["content"].(string)
		if !pathOK || !contentOK || !exactProtectedPAMPath(target) {
			return "", false
		}
		lines, ok := exactPAMLines(target, content)
		if !ok || !hasExactPAMPermitAuthLine(lines) {
			return "", false
		}
		return PAMAuthenticationBypassFullReplacement, true

	case strings.EqualFold(input.Tool, "Edit"):
		if len(object) != 4 || !exactPAMObjectKeys(
			object,
			"file_path",
			"old_string",
			"new_string",
			"replace_all",
		) {
			return "", false
		}
		target, pathOK := object["file_path"].(string)
		oldText, oldOK := object["old_string"].(string)
		newText, newOK := object["new_string"].(string)
		replaceAll, replaceAllOK := object["replace_all"].(bool)
		if !pathOK || !oldOK || !newOK || !replaceAllOK || !replaceAll ||
			oldText == "" || oldText == newText || !exactProtectedPAMPath(target) {
			return "", false
		}
		oldLines, oldValid := exactPAMLines(target, oldText)
		newLines, newValid := exactPAMLines(target, newText)
		if !oldValid || !newValid || !addsExactPAMPermitAuthLine(oldLines, newLines) {
			return "", false
		}
		return PAMAuthenticationBypassLiteralInsertion, true
	default:
		return "", false
	}
}

type exactPAMLine struct {
	fingerprint string
	permitAuth  bool
}

func exactPAMObjectKeys(object map[string]any, expected ...string) bool {
	if len(object) != len(expected) {
		return false
	}
	for _, key := range expected {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func exactProtectedPAMPath(value string) bool {
	if value == "" || len(value) > maxScalarBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 ||
		path.Clean(value) != value || hasUnresolvedPathSyntax(value) {
		return false
	}
	if value == "/etc/pam.conf" {
		return true
	}
	const directory = "/etc/pam.d/"
	if !strings.HasPrefix(value, directory) {
		return false
	}
	leaf := strings.TrimPrefix(value, directory)
	if !exactPAMServiceName(leaf) || pamDocumentationOrScriptName(leaf) {
		return false
	}
	return true
}

func exactPAMServiceName(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func pamDocumentationOrScriptName(value string) bool {
	lower := strings.ToLower(value)
	if lower == "readme" || strings.HasPrefix(lower, "readme.") {
		return true
	}
	for _, suffix := range []string{
		".bash", ".md", ".markdown", ".pl", ".py", ".rb", ".rst", ".sh", ".txt", ".zsh",
	} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func exactPAMLines(target, content string) ([]exactPAMLine, bool) {
	if content == "" || len(content) > maxCommandBytes || !utf8.ValidString(content) ||
		strings.ContainsAny(content, "\x00\r") {
		return nil, false
	}

	pamConf := target == "/etc/pam.conf"
	lines := make([]exactPAMLine, 0, 4)
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.Trim(rawLine, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, "#\\") {
			return nil, false
		}
		fields, ok := exactPAMFields(line)
		if !ok {
			return nil, false
		}
		facilityIndex, controlIndex, moduleIndex := 0, 1, 2
		if pamConf {
			if len(fields) < 4 || !exactPAMServiceName(fields[0]) {
				return nil, false
			}
			facilityIndex, controlIndex, moduleIndex = 1, 2, 3
		} else if len(fields) < 3 {
			return nil, false
		}
		if !exactPAMFacility(fields[facilityIndex]) ||
			!exactPAMBypassControl(fields[controlIndex]) ||
			!exactPAMModule(fields[moduleIndex]) {
			return nil, false
		}
		for _, argument := range fields[moduleIndex+1:] {
			if !exactPAMModuleArgument(argument) {
				return nil, false
			}
		}
		lines = append(lines, exactPAMLine{
			fingerprint: canonicalPAMBypassLine(fields, controlIndex),
			permitAuth: fields[facilityIndex] == "auth" &&
				path.Base(fields[moduleIndex]) == "pam_permit.so",
		})
	}
	return lines, len(lines) != 0
}

func canonicalPAMBypassLine(fields []string, controlIndex int) string {
	canonical := append([]string(nil), fields...)
	control := canonical[controlIndex]
	if len(control) >= 3 && control[0] == '[' && control[len(control)-1] == ']' {
		canonical[controlIndex] = "[" +
			strings.Join(strings.Fields(control[1:len(control)-1]), " ") + "]"
	}
	return strings.Join(canonical, "\x1f")
}

func exactPAMFields(line string) ([]string, bool) {
	fields := make([]string, 0, 6)
	for offset := 0; offset < len(line); {
		for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
			offset++
		}
		if offset == len(line) {
			break
		}
		start := offset
		if line[offset] == '[' {
			offset++
			for offset < len(line) && line[offset] != ']' {
				if line[offset] == '[' || line[offset] < ' ' || line[offset] == 0x7f {
					return nil, false
				}
				offset++
			}
			if offset == len(line) || offset == start+1 {
				return nil, false
			}
			offset++
			if offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
				return nil, false
			}
		} else {
			for offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
				if line[offset] < ' ' || line[offset] == 0x7f || line[offset] == '[' || line[offset] == ']' {
					return nil, false
				}
				offset++
			}
		}
		fields = append(fields, line[start:offset])
		if len(fields) > 32 {
			return nil, false
		}
	}
	return fields, len(fields) != 0
}

func exactPAMFacility(value string) bool {
	switch value {
	case "auth", "account", "password", "session":
		return true
	default:
		return false
	}
}

func exactPAMBypassControl(value string) bool {
	switch value {
	case "required", "requisite", "sufficient", "optional":
		return true
	}
	return len(value) >= 3 && value[0] == '[' && value[len(value)-1] == ']' &&
		!strings.ContainsAny(value[1:len(value)-1], "[]#;|&$`<>{}()\"'")
}

func exactPAMModule(value string) bool {
	if value == "" || strings.ContainsAny(value, "$`{}[];|&<>()\"'") {
		return false
	}
	if strings.Contains(value, "/") {
		return strings.HasPrefix(value, "/") && path.Clean(value) == value
	}
	return value != "." && value != ".."
}

func exactPAMModuleArgument(value string) bool {
	if value == "" || strings.ContainsAny(value, "$`{}[];|&<>()\"'") {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == 0x7f {
			return false
		}
	}
	return true
}

func hasExactPAMPermitAuthLine(lines []exactPAMLine) bool {
	for _, line := range lines {
		if line.permitAuth {
			return true
		}
	}
	return false
}

func addsExactPAMPermitAuthLine(oldLines, newLines []exactPAMLine) bool {
	oldCounts := make(map[string]int, len(oldLines))
	for _, line := range oldLines {
		oldCounts[line.fingerprint]++
	}
	newCounts := make(map[string]int, len(newLines))
	for _, line := range newLines {
		newCounts[line.fingerprint]++
		if line.permitAuth && newCounts[line.fingerprint] > oldCounts[line.fingerprint] {
			return true
		}
	}
	return false
}
