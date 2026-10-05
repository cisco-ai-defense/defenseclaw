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

package sandboxauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// TokenPrefix marks every sandbox binding credential. The main API refuses
// any bearer with this prefix outright, and secret scanners can recognise a
// leaked value.
const TokenPrefix = "dcsb_"

// tokenBytes is the credential entropy: 256 bits from the OS CSPRNG.
const tokenBytes = 32

var (
	tokenPattern     = regexp.MustCompile(`^dcsb_[A-Za-z0-9_-]{43}$`)
	tokenHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// LooksLikeToken reports whether s has the shape of a binding credential.
// It is a cheap pre-filter, not authentication.
func LooksLikeToken(s string) bool {
	return tokenPattern.MatchString(s)
}

// HasTokenPrefix reports whether s claims to be a binding credential,
// whatever its length. The main API uses it to refuse sandbox credentials
// before any other comparison runs.
func HasTokenPrefix(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), TokenPrefix)
}

// HashToken returns the hex SHA-256 digest the store keeps instead of the
// credential. The credential is 256 random bits, so an unsalted digest
// cannot be reversed or dictionary-attacked.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sandboxauth: read credential entropy: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

func newBindingID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sandboxauth: read binding id entropy: %w", err)
	}
	return "sb_" + hex.EncodeToString(buf), nil
}
