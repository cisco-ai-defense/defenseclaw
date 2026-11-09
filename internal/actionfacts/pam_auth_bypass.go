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

// ExactPAMAuthenticationBypass recognizes the text a native file-tool call
// (nativeFileWrites: a whole-file write, an edit, a multi-edit or a patch,
// whatever the tool calls its arguments) puts into a protected PAM
// configuration file, named directly or reached through an existing link the
// facts record (PathFact.Linked). It does not inspect shell command text, read
// files, or retain attacker-controlled values.
func ExactPAMAuthenticationBypass(input Input, facts Facts) (PAMAuthenticationBypassProof, bool) {
	if input.Command != "" || len(input.Argv) != 0 {
		return "", false
	}
	writes := nativeFileWrites(input.Tool, input.Args)
	for _, write := range writes {
		for _, file := range nativeWriteFiles(input, facts, writes, write, false) {
			if proof, proven := pamBypassProof(file, write); proven {
				return proof, true
			}
		}
	}
	return "", false
}

// pamBypassProof judges the text of one write against one protected file.
func pamBypassProof(file string, write nativeFileWrite) (PAMAuthenticationBypassProof, bool) {
	if !exactProtectedPAMPath(file) {
		return "", false
	}
	newLines, newValid := exactPAMLines(file, write.added)
	if !newValid {
		return "", false
	}
	if write.whole {
		if hasExactPAMPermitAuthLine(newLines) {
			return PAMAuthenticationBypassFullReplacement, true
		}
		return "", false
	}
	var oldLines []exactPAMLine
	if write.replaced != "" {
		var oldValid bool
		if oldLines, oldValid = exactPAMLines(file, write.replaced); !oldValid {
			return "", false
		}
	}
	if addsExactPAMPermitAuthLine(oldLines, newLines) {
		return PAMAuthenticationBypassLiteralInsertion, true
	}
	return "", false
}

type exactPAMLine struct {
	fingerprint string
	permitAuth  bool
}

func exactProtectedPAMPath(value string) bool {
	if value == "" || len(value) > maxScalarBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 ||
		path.Clean(value) != value || hasUnresolvedPathSyntax(value) {
		return false
	}
	value = EtcSpelling(value)
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

// exactPAMLines reads the logical lines of PAM text. Every member of a stack
// is an ordinary line to the proof: a module line, an `include` or `substack`
// control, an `@include` directive, a type with the leading "-" that ignores a
// missing module, a line with a trailing comment and a continued line. A line
// the grammar does not read stays a member too (an opaque line), judged by
// what it says about pam_permit.so, so one line outside the grammar never
// hides a permit-all inserted beside it. Text that is not PAM text at all (a
// NUL, a bare CR, invalid UTF-8, over the bound) is not read.
func exactPAMLines(target, content string) ([]exactPAMLine, bool) {
	if content == "" || len(content) > maxCommandBytes || !utf8.ValidString(content) ||
		strings.ContainsAny(content, "\x00\r") {
		return nil, false
	}
	pamConf := EtcSpelling(target) == "/etc/pam.conf"
	physical := strings.Split(content, "\n")
	lines := make([]exactPAMLine, 0, len(physical))
	for index := 0; index < len(physical); index++ {
		logical := physical[index]
		for strings.HasSuffix(strings.TrimRight(logical, " \t"), "\\") && index+1 < len(physical) {
			logical = strings.TrimSuffix(strings.TrimRight(logical, " \t"), "\\") + " " + physical[index+1]
			index++
		}
		line := strings.Trim(pamWithoutComment(logical), " \t")
		if line == "" {
			continue
		}
		lines = append(lines, exactPAMLineOf(line, pamConf))
	}
	return lines, true
}

// pamWithoutComment drops the comment of a PAM line: a "#" outside a
// bracketed word starts it, as in a line the module reads.
func pamWithoutComment(line string) string {
	inBracket := false
	for offset := 0; offset < len(line); offset++ {
		switch line[offset] {
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		case '#':
			if !inBracket {
				return line[:offset]
			}
		}
	}
	return line
}

// exactPAMLineOf is one non-empty logical line: read by the grammar when it
// fits, else an opaque member.
func exactPAMLineOf(line string, pamConf bool) exactPAMLine {
	if parsed, ok := exactPAMGrammarLine(line, pamConf); ok {
		return parsed
	}
	words := strings.Fields(line)
	opaque := exactPAMLine{fingerprint: "?\x1f" + strings.Join(words, "\x1f")}
	if pamConf && len(words) != 0 {
		words = words[1:]
	}
	if len(words) < 3 || strings.TrimPrefix(words[0], "-") != "auth" {
		return opaque
	}
	for _, word := range words[2:] {
		if path.Base(word) == "pam_permit.so" {
			opaque.permitAuth = true
		}
	}
	return opaque
}

// exactPAMGrammarLine reads one line of the grammar: type, control, module
// and arguments (the service name leads in pam.conf), or `@include name`.
func exactPAMGrammarLine(line string, pamConf bool) (exactPAMLine, bool) {
	fields, ok := exactPAMFields(line)
	if !ok {
		return exactPAMLine{}, false
	}
	if fields[0] == "@include" {
		if len(fields) != 2 || !exactPAMIncludeName(fields[1]) {
			return exactPAMLine{}, false
		}
		return exactPAMLine{fingerprint: canonicalPAMBypassLine(fields, 1)}, true
	}
	facilityIndex, controlIndex, moduleIndex := 0, 1, 2
	if pamConf {
		if len(fields) < 4 || !exactPAMServiceName(fields[0]) {
			return exactPAMLine{}, false
		}
		facilityIndex, controlIndex, moduleIndex = 1, 2, 3
	} else if len(fields) < 3 {
		return exactPAMLine{}, false
	}
	facility := strings.TrimPrefix(fields[facilityIndex], "-")
	if !exactPAMFacility(facility) || !exactPAMBypassControl(fields[controlIndex]) {
		return exactPAMLine{}, false
	}
	including := fields[controlIndex] == "include" || fields[controlIndex] == "substack"
	if including && !exactPAMIncludeName(fields[moduleIndex]) || !including && !exactPAMModule(fields[moduleIndex]) {
		return exactPAMLine{}, false
	}
	for _, argument := range fields[moduleIndex+1:] {
		if !exactPAMModuleArgument(argument) {
			return exactPAMLine{}, false
		}
	}
	return exactPAMLine{
		fingerprint: canonicalPAMBypassLine(fields, controlIndex),
		permitAuth:  !including && facility == "auth" && path.Base(fields[moduleIndex]) == "pam_permit.so",
	}, true
}

// exactPAMIncludeName is the stack an include, substack or @include line
// names: a service name or an absolute path.
func exactPAMIncludeName(value string) bool {
	if strings.HasPrefix(value, "/") {
		return exactPAMModule(value)
	}
	return exactPAMServiceName(value)
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
	case "required", "requisite", "sufficient", "optional", "include", "substack":
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
