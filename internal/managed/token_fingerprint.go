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
// See the License for the specific language governing
// permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ScopedTokenFingerprint is the canonical non-secret SHA-256 hex digest of a
// connector-scoped hook token. Public guardian and rotation state must persist
// only this form — never the raw or encoded token.
func ScopedTokenFingerprint(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// ValidScopedTokenFingerprint reports whether value is a lowercase SHA-256 hex
// digest in the rotation/guardian public-state format.
func ValidScopedTokenFingerprint(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
