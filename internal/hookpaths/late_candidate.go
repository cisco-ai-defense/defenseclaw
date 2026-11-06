// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// CallMayReachProtected is the bounded text phase of a late hook answer.
// It deliberately treats an unresolved spelling as a candidate; only text
// with none of these names can receive a local ordinary-call proof.
func CallMayReachProtected(text, home string) bool {
	if text == "" || home == "" {
		return true
	}
	lower := strings.ToLower(text)
	for _, name := range []string{
		"authorized_keys", ".ssh", ".defenseclaw", "id_rsa", "id_ed25519",
		"id_ecdsa", "id_dsa", "administrators_authorized_keys",
	} {
		if strings.Contains(lower, name) {
			return true
		}
	}
	for _, spelling := range []string{"~/", "$HOME/", "${HOME}/", "%USERPROFILE%\\"} {
		if strings.Contains(text, spelling) {
			return true
		}
	}
	// Expansions and patterns can supply a name absent from the literal text.
	return strings.ContainsAny(text, "*?[]$`")
}
