// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
)

const (
	AuthKeyIDHeader          = "X-DefenseClaw-ACP-Key-ID"
	AuthNonceHeader          = "X-DefenseClaw-ACP-Nonce"
	AuthRequestMACHeader     = "X-DefenseClaw-ACP-Request-MAC"
	AuthResponseMACHeader    = "X-DefenseClaw-ACP-Response-MAC"
	AuthChallengeNonceHeader = "X-DefenseClaw-ACP-Challenge-Nonce"
	AuthServerNonceHeader    = "X-DefenseClaw-ACP-Server-Nonce"

	httpAuthDomain       = "defenseclaw-acp-http-auth-v1"
	httpPayloadKeyDomain = "defenseclaw-acp-http-payload-key-v1"
	httpPayloadAADDomain = "defenseclaw-acp-http-payload-aad-v1"
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

// SealHTTPPayload encrypts an ACP evaluation only after the evaluator has
// authenticated a fresh gateway challenge. The request nonce supplies the
// unique AES-GCM nonce; both challenge nonces and all routing metadata are
// bound into the derived key and associated data.
func SealHTTPPayload(token, keyID, challengeNonce, serverNonce, requestNonce, method, path string, plaintext []byte) ([]byte, error) {
	aead, nonce, aad, err := httpPayloadAEAD(token, keyID, challengeNonce, serverNonce, requestNonce, method, path)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// OpenHTTPPayload verifies and decrypts one challenge-bound ACP evaluation.
func OpenHTTPPayload(token, keyID, challengeNonce, serverNonce, requestNonce, method, path string, ciphertext []byte) ([]byte, error) {
	aead, nonce, aad, err := httpPayloadAEAD(token, keyID, challengeNonce, serverNonce, requestNonce, method, path)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, errors.New("ACP evaluator payload authentication failed")
	}
	return plaintext, nil
}

func httpPayloadAEAD(token, keyID, challengeNonce, serverNonce, requestNonce, method, path string) (cipher.AEAD, []byte, []byte, error) {
	if token == "" || len(keyID) != 64 || !hmac.Equal([]byte(HTTPAuthKeyID(token)), []byte(keyID)) {
		return nil, nil, nil, errors.New("ACP evaluator payload credential is malformed")
	}
	decodedNonce, err := hex.DecodeString(requestNonce)
	if err != nil || len(decodedNonce) != 32 {
		return nil, nil, nil, errors.New("ACP evaluator request nonce is malformed")
	}
	for label, value := range map[string]string{
		"challenge": challengeNonce,
		"server":    serverNonce,
	} {
		decoded, decodeErr := hex.DecodeString(value)
		if decodeErr != nil || len(decoded) != 32 {
			return nil, nil, nil, fmt.Errorf("ACP evaluator %s nonce is malformed", label)
		}
	}
	transcript := httpAuthTranscript(keyID, challengeNonce, serverNonce, requestNonce, method, path)
	keyMAC := hmac.New(sha256.New, []byte(token))
	writeHTTPAuthFields(keyMAC, httpPayloadKeyDomain, string(transcript))
	block, err := aes.NewCipher(keyMAC.Sum(nil))
	if err != nil {
		return nil, nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	aad := httpAuthTranscript(httpPayloadAADDomain, keyID, challengeNonce, serverNonce, requestNonce, method, path)
	return aead, decodedNonce[:aead.NonceSize()], aad, nil
}

func httpAuthTranscript(fields ...string) []byte {
	var transcript bytes.Buffer
	writeHTTPAuthFields(&transcript, fields...)
	return transcript.Bytes()
}

func httpMAC(token, kind, keyID, nonce, method, path, status string, body []byte) string {
	bodyDigest := sha256.Sum256(body)
	mac := hmac.New(sha256.New, []byte(token))
	writeHTTPAuthFields(mac, httpAuthDomain, kind, keyID, nonce, method, path, status, hex.EncodeToString(bodyDigest[:]))
	return hex.EncodeToString(mac.Sum(nil))
}

func writeHTTPAuthFields(writer io.Writer, fields ...string) {
	for _, field := range fields {
		_, _ = writer.Write([]byte(strconv.Itoa(len(field))))
		_, _ = writer.Write([]byte{':'})
		_, _ = writer.Write([]byte(field))
	}
}
