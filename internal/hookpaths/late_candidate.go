// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// CallMayReachProtected is the bounded text phase of a late hook answer.
// Names must be complete path components: a project file whose name merely
// contains a protected component is still an ordinary file.
func CallMayReachProtected(text, home string) bool {
	if text == "" || home == "" {
		return true
	}
	lower := strings.ToLower(text)
	for _, name := range []string{
		"authorized_keys", ".ssh", ".defenseclaw", "id_rsa", "id_ed25519",
		"id_ecdsa", "id_dsa", "administrators_authorized_keys",
	} {
		if lateTextHasPathComponent(lower, name) {
			return true
		}
	}
	for _, spelling := range []string{"~/", "$HOME/", "${HOME}/", "%USERPROFILE%\\"} {
		if strings.Contains(text, spelling) {
			return true
		}
	}
	// Expansions and patterns can supply a name absent from the literal text.
	if strings.ContainsAny(text, "*?[]`") {
		return true
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '$' {
			continue
		}
		length := 0
		for _, value := range []string{"$PWD", "${PWD}", "$USER", "${USER}"} {
			if strings.HasPrefix(text[i:], value) {
				length = len(value)
				break
			}
		}
		if length == 0 || i+length < len(text) && !lateValueEnd(text[i+length]) ||
			i > 0 && (text[i-1] == '/' || text[i-1] == '\\') {
			return true
		}
		i += length - 1
	}
	return false
}

func lateTextHasPathComponent(text, name string) bool {
	for start := 0; start < len(text); {
		index := strings.Index(text[start:], name)
		if index < 0 {
			return false
		}
		index += start
		before := index == 0 || lateNameBoundary(text[index-1])
		end := index + len(name)
		after := end == len(text) || lateNameBoundary(text[end])
		if before && after {
			return true
		}
		start = index + 1
	}
	return false
}

func lateNameBoundary(c byte) bool {
	return strings.ContainsRune("/\\ \t\r\n'\"=;|&<>(){}:,", rune(c))
}

func lateValueEnd(c byte) bool {
	return strings.ContainsRune(" \t\r\n'\";|&<>(){}:,", rune(c))
}
