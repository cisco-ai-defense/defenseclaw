// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

const (
	AuthKeyIDHeader       = "X-DefenseClaw-ACP-Key-ID"
	AuthNonceHeader       = "X-DefenseClaw-ACP-Nonce"
	AuthRequestMACHeader  = "X-DefenseClaw-ACP-Request-MAC"
	AuthResponseMACHeader = "X-DefenseClaw-ACP-Response-MAC"

	httpAuthDomain = "defenseclaw-acp-http-auth-v1"
)

// HTTPAuthKeyID is a non-secret lookup key for one scoped ACP credential.
func HTTPAuthKeyID(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// NewHTTPAuthNonce returns a fresh challenge for one evaluator exchange.
func NewHTTPAuthNonce() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func HTTPRequestMAC(token, keyID, nonce, method, path string, body []byte) string {
	return httpMAC(token, "request", keyID, nonce, method, path, "", body)
}

func HTTPResponseMAC(token, keyID, nonce string, status int, body []byte) string {
	return httpMAC(token, "response", keyID, nonce, "", "", strconv.Itoa(status), body)
}

func VerifyHTTPRequestMAC(token, keyID, nonce, method, path string, body []byte, candidate string) bool {
	want, err := hex.DecodeString(HTTPRequestMAC(token, keyID, nonce, method, path, body))
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(candidate)
	return err == nil && hmac.Equal(want, got)
}

func VerifyHTTPResponseMAC(token, keyID, nonce string, status int, body []byte, candidate string) bool {
	want, err := hex.DecodeString(HTTPResponseMAC(token, keyID, nonce, status, body))
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(candidate)
	return err == nil && hmac.Equal(want, got)
}

func httpMAC(token, kind, keyID, nonce, method, path, status string, body []byte) string {
	bodyDigest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(token))
	for _, field := range []string{httpAuthDomain, kind, keyID, nonce, method, path, status, hex.EncodeToString(bodyDigest[:])} {
		_, _ = mac.Write([]byte(strconv.Itoa(len(field))))
		_, _ = mac.Write([]byte{':'})
		_, _ = mac.Write([]byte(field))
	}
	return hex.EncodeToString(mac.Sum(nil))
}
