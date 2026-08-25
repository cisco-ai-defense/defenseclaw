// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
)

// DefenseClaw writes its own gateway token into the agent config files it
// manages — the OTLP header block in ~/.claude/settings.json carries it four
// times. Any tool result that reads one of those files therefore contains a
// live-looking bearer token, and the credential rules dutifully raised a HIGH
// finding about DefenseClaw's own configuration.
//
// Registering the token here lets the credential validators recognise a value
// the product itself installed. Only exact matches are suppressed: this is an
// identity check on one known secret, not a pattern that could hide an
// unrelated credential that happens to look similar.
//
// Digests are stored rather than plaintext so the registry never becomes a
// second place a live token can be read out of memory or accidentally logged.

// minSelfIssuedCredentialLen refuses to register a short value. Allowlisting a
// handful of characters would suppress unrelated findings that merely share
// them; a real gateway token is far longer than this floor.
const minSelfIssuedCredentialLen = 16

var selfIssuedCredentials sync.Map // digest string -> struct{}

func selfIssuedCredentialDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// RegisterSelfIssuedCredential records a secret that DefenseClaw itself wrote
// into a managed agent configuration. Values shorter than
// minSelfIssuedCredentialLen are ignored.
func RegisterSelfIssuedCredential(secret string) {
	trimmed := strings.TrimSpace(secret)
	if len(trimmed) < minSelfIssuedCredentialLen {
		return
	}
	selfIssuedCredentials.Store(selfIssuedCredentialDigest(trimmed), struct{}{})
	// Credential candidates reach the validators after quoting and header
	// prefixes are stripped, and sometimes after compaction. Register the
	// compacted form too so the identity check survives either shape.
	if compact := compactCredential(trimmed); compact != trimmed && len(compact) >= minSelfIssuedCredentialLen {
		selfIssuedCredentials.Store(selfIssuedCredentialDigest(compact), struct{}{})
	}
}

// isSelfIssuedCredential reports whether a candidate is a secret DefenseClaw
// installed itself.
func isSelfIssuedCredential(candidate string) bool {
	trimmed := strings.TrimSpace(candidate)
	if len(trimmed) < minSelfIssuedCredentialLen {
		return false
	}
	if _, ok := selfIssuedCredentials.Load(selfIssuedCredentialDigest(trimmed)); ok {
		return true
	}
	compact := compactCredential(trimmed)
	if compact == trimmed || len(compact) < minSelfIssuedCredentialLen {
		return false
	}
	_, ok := selfIssuedCredentials.Load(selfIssuedCredentialDigest(compact))
	return ok
}

// resetSelfIssuedCredentialsForTest clears the registry between tests.
func resetSelfIssuedCredentialsForTest() {
	selfIssuedCredentials.Range(func(key, _ any) bool {
		selfIssuedCredentials.Delete(key)
		return true
	})
}
