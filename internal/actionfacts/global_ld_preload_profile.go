// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
	"unicode/utf8"
)

const globalLDPreloadProfileDirectory = "/etc/profile.d/"

// ExactGlobalLDPreloadProfileWrite proves that one closed-schema structured
// file write installs a system-wide LD_PRELOAD assignment in one direct
// /etc/profile.d shell fragment. It retains neither the path nor file content.
func ExactGlobalLDPreloadProfileWrite(input Input, facts Facts) bool {
	if input.Command != "" || len(input.Argv) != 0 ||
		!facts.Authoritative() || !facts.EnforcementEligible() ||
		facts.Tool != input.Tool || len(facts.Paths) != 1 {
		return false
	}

	object, problem := exactJSONObject(input.Args)
	if problem.status != "" || len(object) != 2 {
		return false
	}
	pathKey := ""
	switch input.Tool {
	case "Write":
		pathKey = "file_path"
	case "write_file", "write-file", "writefile":
		pathKey = "path"
	default:
		return false
	}
	for key := range object {
		if key != pathKey && key != "content" {
			return false
		}
	}
	target, targetOK := object[pathKey].(string)
	content, contentOK := object["content"].(string)
	if !targetOK || !contentOK || !ExactGlobalLDPreloadProfilePath(target) ||
		!ExactGlobalLDPreloadProfileContent(content) {
		return false
	}

	candidate := facts.Paths[0]
	return candidate.Access == PathAccessWrite && candidate.Flavor == PathFlavorPOSIX &&
		candidate.Value == target && candidate.Normalized == target &&
		candidate.Resolved == target && candidate.Absolute
}

// ExactGlobalLDPreloadProfilePath accepts only one canonical direct shell
// fragment under /etc/profile.d. Nested paths, templates, and documentation
// files are intentionally outside the proof grammar.
func ExactGlobalLDPreloadProfilePath(value string) bool {
	if value == "" || len(value) > maxScalarBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.IndexByte(value, 0) >= 0 ||
		path.Clean(value) != value || hasUnresolvedPathSyntax(value) ||
		!strings.HasPrefix(value, globalLDPreloadProfileDirectory) {
		return false
	}
	leaf := strings.TrimPrefix(value, globalLDPreloadProfileDirectory)
	if leaf == "" || strings.ContainsRune(leaf, '/') || !strings.HasSuffix(leaf, ".sh") {
		return false
	}
	stem := strings.TrimSuffix(leaf, ".sh")
	if stem == "" {
		return false
	}
	for _, character := range stem {
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

// ExactGlobalLDPreloadProfileContent accepts comments and blank lines plus
// exactly one active, literal `export LD_PRELOAD=/absolute/library.so` line.
// Any additional executable shell content or interpolation causes abstention.
func ExactGlobalLDPreloadProfileContent(content string) bool {
	if content == "" || len(content) > maxCommandBytes || !utf8.ValidString(content) ||
		strings.ContainsAny(content, "\x00\r") {
		return false
	}
	assignmentSeen := false
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.Trim(rawLine, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if assignmentSeen || !strings.HasPrefix(line, "export ") {
			return false
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "export" {
			return false
		}
		name, value, ok := strings.Cut(fields[1], "=")
		if !ok || name != "LD_PRELOAD" {
			return false
		}
		value, ok = exactGlobalLDPreloadLiteral(value)
		if !ok {
			return false
		}
		assignmentSeen = exactGlobalLDPreloadSharedObject(value)
		if !assignmentSeen {
			return false
		}
	}
	return assignmentSeen
}

func exactGlobalLDPreloadLiteral(value string) (string, bool) {
	if len(value) >= 2 && (value[0] == '\'' && value[len(value)-1] == '\'' ||
		value[0] == '"' && value[len(value)-1] == '"') {
		quote := value[0]
		value = value[1 : len(value)-1]
		if strings.ContainsRune(value, rune(quote)) {
			return "", false
		}
	}
	if value == "" || strings.ContainsAny(value, "$`{}()[]*?!\\;|&<> \t\n\r") {
		return "", false
	}
	return value, true
}

func exactGlobalLDPreloadSharedObject(value string) bool {
	if !strings.HasPrefix(value, "/") || path.Clean(value) != value ||
		hasUnresolvedPathSyntax(value) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '/' || character == '_' || character == '-' ||
			character == '.' || character == '+' {
			continue
		}
		return false
	}
	base := path.Base(value)
	marker := strings.Index(base, ".so")
	return marker > 0 && (marker+3 == len(base) || base[marker+3] == '.')
}
