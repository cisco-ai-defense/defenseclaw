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

package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// MaxTokenBytes bounds a compact JWS the verifiers parse. Actor tokens are
// well under 2 KiB; anything near this is not a Substrate token.
const MaxTokenBytes = 8 << 10

// jwsHeader is the protected header of a compact JWS.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
	// Crit lists extensions the verifier must understand. None are, so a
	// token with any is refused (RFC 7515 4.1.11).
	Crit []string `json:"crit,omitempty"`
}

// parsedJWS is a compact JWS split into its parts, not yet verified.
type parsedJWS struct {
	header    jwsHeader
	claims    []byte
	signed    []byte // header.payload, the signing input
	signature []byte
}

func b64url(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/") {
		return nil, errors.New("not base64url without padding")
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// parseJWS splits a compact JWS. It decodes but verifies nothing.
func parseJWS(token string) (parsedJWS, error) {
	if token == "" {
		return parsedJWS{}, reasonf(ReasonMissing, "no token")
	}
	if len(token) > MaxTokenBytes {
		return parsedJWS{}, reasonf(ReasonMalformed, "token is longer than %d bytes", MaxTokenBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return parsedJWS{}, reasonf(ReasonMalformed, "token is not a compact JWS")
	}
	hb, err := b64url(parts[0])
	if err != nil {
		return parsedJWS{}, reasonf(ReasonMalformed, "token header is not base64url")
	}
	var h jwsHeader
	if err := strictJSON(hb, &h); err != nil {
		return parsedJWS{}, reasonf(ReasonMalformed, "token header is not a JSON object")
	}
	if len(h.Crit) > 0 {
		return parsedJWS{}, reasonf(ReasonMalformed, "token header lists critical extensions")
	}
	cb, err := b64url(parts[1])
	if err != nil {
		return parsedJWS{}, reasonf(ReasonMalformed, "token claims are not base64url")
	}
	sig, err := b64url(parts[2])
	if err != nil {
		return parsedJWS{}, reasonf(ReasonMalformed, "token signature is not base64url")
	}
	return parsedJWS{header: h, claims: cb, signed: []byte(parts[0] + "." + parts[1]), signature: sig}, nil
}

// strictJSON decodes one JSON object and refuses trailing data and
// duplicate top-level members, so two parsers cannot read different claims
// out of the same bytes.
func strictJSON(b []byte, v any) error {
	if err := checkDuplicateKeys(b); err != nil {
		return err
	}
	// Unmarshal refuses trailing data after the object.
	return json.Unmarshal(b, v)
}

// checkDuplicateKeys refuses an object with a repeated top-level member.
func checkDuplicateKeys(b []byte) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := kt.(string)
		if seen[k] {
			return fmt.Errorf("duplicate member %q", k)
		}
		seen[k] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	return nil
}

// verifySignature checks sig over signed with key for alg. Only the
// algorithms Substrate (ES256, RS256) and the session tokens (ES256,
// EdDSA) use are accepted; "none" and the HMAC family never are.
func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	switch alg {
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return reasonf(ReasonSignature, "key does not match alg ES256")
		}
		if len(sig) != 64 {
			return reasonf(ReasonSignature, "ES256 signature has the wrong length")
		}
		d := sha256.Sum256(signed)
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, d[:], r, s) {
			return reasonf(ReasonSignature, "signature is invalid")
		}
		return nil
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return reasonf(ReasonSignature, "key does not match alg RS256")
		}
		if k.N.BitLen() < 2048 {
			return reasonf(ReasonSignature, "RSA key is shorter than 2048 bits")
		}
		d := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig); err != nil {
			return reasonf(ReasonSignature, "signature is invalid")
		}
		return nil
	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return reasonf(ReasonSignature, "key does not match alg EdDSA")
		}
		if !ed25519.Verify(k, signed, sig) {
			return reasonf(ReasonSignature, "signature is invalid")
		}
		return nil
	default:
		return reasonf(ReasonAlgorithm, "alg %q is not accepted", alg)
	}
}

// audience is the aud claim: a JSON array, or a single string.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a audience) contains(want string) bool {
	for _, v := range a {
		if v == want {
			return true
		}
	}
	return false
}
