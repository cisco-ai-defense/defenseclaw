// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package envvars

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strings"
)

// The gateway token lives in ~/.defenseclaw/.env under two spellings. When the
// gateway adopts the token OpenClaw holds in openclaw.json it writes both, and
// records the SHA-256 of what it wrote in a comment line (the marker). A
// spelling that still holds that value is an adopted copy. When the other
// spelling holds a different value, the operator saved it, and the adopted copy
// must not shadow it: every .env reader leaves the adopted copy out
// (GAP-0847). The marker is a comment, so a reader that does not know it, and
// a file it was lost from, behave as before: the earlier spelling wins.

const (
	gatewayTokenCanonicalName = "DEFENSECLAW_GATEWAY_TOKEN"
	gatewayTokenLegacyName    = "OPENCLAW_GATEWAY_TOKEN"
	adoptedGatewayTokenMarker = "# defenseclaw: adopted gateway token sha256="
)

// AdoptedGatewayTokenMarker returns the .env comment line that records token
// as the value the gateway adopted.
func AdoptedGatewayTokenMarker(token string) string {
	return adoptedGatewayTokenMarker + gatewayTokenDigest(token)
}

// IsAdoptedGatewayTokenMarker reports whether a .env line is that comment.
func IsAdoptedGatewayTokenMarker(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), adoptedGatewayTokenMarker)
}

func gatewayTokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ShadowedNames are the gateway token variable names a reader leaves out.
type ShadowedNames []string

// Has reports whether key names one of them, with the key comparison of the
// platform (case-insensitive on Windows).
func (s ShadowedNames) Has(key string) bool {
	key = strings.TrimSpace(key)
	for _, name := range s {
		if gatewayTokenNameEqual(name, key) {
			return true
		}
	}
	return false
}

func gatewayTokenNameEqual(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

// ShadowedAdoptedGatewayTokens returns the gateway token spellings of a .env
// body that hold only the adopted copy while the other spelling holds a
// different value. It returns nothing when the body has no marker, when both
// spellings agree, or when neither is an adopted copy.
func ShadowedAdoptedGatewayTokens(body []byte) ShadowedNames {
	var digest string
	explicit := map[string]bool{}
	adopted := map[string]bool{}
	names := []string{gatewayTokenCanonicalName, gatewayTokenLegacyName}
	type entry struct{ name, value string }
	var entries []entry
	for _, raw := range bytes.Split(body, []byte("\n")) {
		line := strings.TrimSpace(string(raw))
		if line == "" {
			continue
		}
		if line[0] == commentByte {
			if digest == "" && strings.HasPrefix(line, adoptedGatewayTokenMarker) {
				digest = strings.TrimSpace(strings.TrimPrefix(line, adoptedGatewayTokenMarker))
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == value[len(value)-1] && (value[0] == doubleQuoteByte || value[0] == singleQuoteByte) {
			value = value[1 : len(value)-1]
		}
		if value == "" || IsSecretRefText(value) {
			continue
		}
		for _, name := range names {
			if gatewayTokenNameEqual(name, key) {
				entries = append(entries, entry{name, value})
			}
		}
	}
	if digest == "" {
		return nil
	}
	for _, e := range entries {
		if gatewayTokenDigest(e.value) == digest {
			adopted[e.name] = true
		} else {
			explicit[e.name] = true
		}
	}
	if len(explicit) == 0 {
		return nil
	}
	var shadowed ShadowedNames
	for _, name := range names {
		if adopted[name] && !explicit[name] {
			shadowed = append(shadowed, name)
		}
	}
	return shadowed
}

// The ASCII bytes the .env line parser looks for.
const (
	commentByte     = 0x23
	doubleQuoteByte = 0x22
	singleQuoteByte = 0x27
)
