// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Per-user credentials for the standalone profile.
//
// A connector-scoped token is one value per machine: every user of that
// connector holds the same bearer, so on the loopback TCP API one user could
// present it with another user's identity headers. The standalone guardian
// instead hands each enrolled user credentials bound to that user's OS
// identity (the uid on Unix, the SID on Windows). Each credential is
//
//	HMAC-SHA256(key, "defenseclaw.user-scoped-credential.v1" 0 kind 0 scope 0 identity)
//
// hex-encoded, so it has the same 64-character shape every token reader
// already accepts. The key is a random secret kept beside the gateway's own
// tokens and never given to a user. The gateway derives the credentials of
// every protected target in the guardian's authorization ledger, so a
// credential authenticates only while its user is protected, and the gateway
// attributes the request to the identity the credential is bound to.

const (
	userScopedTokenKeyFileName = ".user-scoped-token.key"
	userScopedTokenDomain      = "defenseclaw.user-scoped-credential.v1"

	// UserScopedHookCredential authenticates a connector's hook, notify and
	// inspect routes.
	UserScopedHookCredential = "hook"
	// UserScopedOTLPCredential authenticates a connector's OTLP source.
	UserScopedOTLPCredential = "otlp"
)

// UserScopedTokenKeyPath is the per-machine key the per-user credentials are
// derived from. It lives beside the connector-scoped tokens in the gateway's
// data directory, with the same custody.
func UserScopedTokenKeyPath(dataDir string) (string, error) {
	if strings.TrimSpace(dataDir) == "" {
		return "", fmt.Errorf("UserScopedTokenKeyPath: empty dataDir")
	}
	return filepath.Join(dataDir, "hooks", userScopedTokenKeyFileName), nil
}

// EnsureUserScopedTokenKey returns the per-user credential key, minting it
// on first use. An existing key is reused so repair runs do not invalidate
// installed credentials.
func EnsureUserScopedTokenKey(dataDir string) (string, error) {
	path, err := UserScopedTokenKeyPath(dataDir)
	if err != nil {
		return "", err
	}
	hookAPITokenMu.Lock()
	defer hookAPITokenMu.Unlock()
	key, err := ensureHookAPITokenFileLocked(dataDir, path)
	if err != nil {
		return "", fmt.Errorf("per-user credential key: %w", err)
	}
	return key, nil
}

// LoadUserScopedTokenKey reads the per-user credential key with the same
// trust checks as a connector-scoped token. A missing key returns "" and no
// error: no per-user credential has been issued yet.
func LoadUserScopedTokenKey(dataDir string) (string, error) {
	path, err := UserScopedTokenKeyPath(dataDir)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("inspect per-user credential key: %w", err)
	}
	key, err := readSecureHookAPITokenFile(dataDir, path)
	if err != nil {
		return "", fmt.Errorf("per-user credential key: %w", err)
	}
	return key, nil
}

// CanonicalUserScopedIdentity normalizes the OS identity a per-user
// credential is bound to: a decimal POSIX uid, or a Windows SID in upper
// case. Anything else is refused, so a credential can never be bound to an
// account name or an agent-supplied value.
func CanonicalUserScopedIdentity(identity string) (string, bool) {
	identity = strings.TrimSpace(identity)
	switch useridentity.KindForID(identity) {
	case useridentity.KindPOSIXUID:
		uid, err := strconv.ParseUint(identity, 10, 32)
		if err != nil {
			return "", false
		}
		return strconv.FormatUint(uid, 10), true
	case useridentity.KindWindowsSID:
		return strings.ToUpper(identity), true
	default:
		return "", false
	}
}

// UserScopedHookAPIToken derives the hook credential of one user for one
// connector.
func UserScopedHookAPIToken(key, connectorName, identity string) (string, error) {
	scope, err := normalizeHookAPITokenScope(connectorName)
	if err != nil {
		return "", err
	}
	return deriveUserScopedToken(key, UserScopedHookCredential, scope, identity)
}

// UserScopedOTLPPathToken derives the OTLP credential of one user for one
// OTLP source.
func UserScopedOTLPPathToken(key string, scope OTLPPathTokenScope, identity string) (string, error) {
	if !validOTLPScope(scope) {
		return "", fmt.Errorf("invalid OTLP scope %q", scope)
	}
	return deriveUserScopedToken(key, UserScopedOTLPCredential, string(scope), identity)
}

func deriveUserScopedToken(key, kind, scope, identity string) (string, error) {
	key = strings.TrimSpace(key)
	if !otlpTokenHexRE.MatchString(key) {
		return "", errors.New("per-user credential key is not a 64-character lowercase hex secret")
	}
	secret, err := hex.DecodeString(key)
	if err != nil {
		return "", errors.New("per-user credential key is not hex")
	}
	canonical, ok := CanonicalUserScopedIdentity(identity)
	if !ok {
		return "", fmt.Errorf("per-user credential identity %q is neither a uid nor a SID", identity)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(userScopedTokenDomain + "\x00" + kind + "\x00" + scope + "\x00" + canonical))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// Listener proof.
//
// The Windows standalone in-agent plugins (OpenCode, Amp) reach the gateway
// over loopback TCP, where any local user can bind the port while the
// gateway is stopped or restarting. Unlike the hook binary they cannot
// compare the listener with the SCM gateway process, so before a plugin
// sends its per-user hook credential or any hook payload it asks the
// listener to prove that it can derive that credential. The request
// carries only the credential's key ID (its SHA-256, which authenticates
// nothing) and a fresh 32-byte nonce; the answer is
//
//	HMAC-SHA256(credential, "defenseclaw.listener-proof.v1" 0 connector 0 nonce)
//
// hex-encoded. Only the gateway, which holds the per-machine key, can derive
// the credential, so a listener that cannot answer is not the gateway and
// the plugin sends it nothing else: no credential to replay, no payload,
// and no verdict it would trust.
const (
	// UserScopedListenerProofPath is the gateway route that answers a
	// listener proof. It is served before bearer authentication.
	UserScopedListenerProofPath = "/api/v1/hook-listener-proof"
	// UserScopedListenerKeyIDHeader carries UserScopedCredentialKeyID.
	UserScopedListenerKeyIDHeader = "X-DefenseClaw-Listener-Key-Id"
	// UserScopedListenerNonceHeader carries the plugin's fresh nonce.
	UserScopedListenerNonceHeader = "X-DefenseClaw-Listener-Nonce"
	// UserScopedListenerProofHeader carries the gateway's answer.
	UserScopedListenerProofHeader = "X-DefenseClaw-Listener-Proof"

	userScopedListenerProofDomain = "defenseclaw.listener-proof.v1"
)

// UserScopedCredentialKeyID is the non-secret identifier a listener proof
// names a credential by: the hex SHA-256 of the credential.
func UserScopedCredentialKeyID(credential string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(credential)))
	return hex.EncodeToString(digest[:])
}

// UserScopedListenerProof is the proof that the holder of credential (a
// per-user hook credential for connectorName) answered nonce. The nonce
// must be 64 lowercase hex characters (32 random bytes).
func UserScopedListenerProof(credential, connectorName, nonce string) (string, error) {
	credential = strings.TrimSpace(credential)
	if !otlpTokenHexRE.MatchString(credential) {
		return "", errors.New("listener proof credential is not a 64-character lowercase hex credential")
	}
	scope, err := normalizeHookAPITokenScope(connectorName)
	if err != nil {
		return "", err
	}
	if !otlpTokenHexRE.MatchString(nonce) {
		return "", errors.New("listener proof nonce is not 64 lowercase hex characters")
	}
	mac := hmac.New(sha256.New, []byte(credential))
	_, _ = mac.Write([]byte(userScopedListenerProofDomain + "\x00" + scope + "\x00" + nonce))
	return hex.EncodeToString(mac.Sum(nil)), nil
}
