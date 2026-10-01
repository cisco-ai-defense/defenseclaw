// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestUserScopedTokenKeyIsMintedOnceAndReused(t *testing.T) {
	dataDir := t.TempDir()
	if key, err := LoadUserScopedTokenKey(dataDir); err != nil || key != "" {
		t.Fatalf("missing key: %q %v", key, err)
	}
	first, err := EnsureUserScopedTokenKey(dataDir)
	if err != nil || !otlpTokenHexRE.MatchString(first) {
		t.Fatalf("mint key: %v (valid=%v)", err, otlpTokenHexRE.MatchString(first))
	}
	second, err := EnsureUserScopedTokenKey(dataDir)
	if err != nil || second != first {
		t.Fatalf("second ensure rotated or failed: same=%v err=%v", second == first, err)
	}
	loaded, err := LoadUserScopedTokenKey(dataDir)
	if err != nil || loaded != first {
		t.Fatalf("load key: same=%v err=%v", loaded == first, err)
	}
	path, err := UserScopedTokenKeyPath(dataDir)
	if err != nil || path != filepath.Join(dataDir, "hooks", ".user-scoped-token.key") {
		t.Fatalf("key path = %q %v", path, err)
	}
	// The key is not a connector token: no connector name maps to it.
	if tokens, err := LoadHookAPITokens(dataDir, []string{"codex", "user-scoped-token"}); err != nil || len(tokens) != 0 {
		t.Fatalf("key readable as a connector token: %v %v", tokens, err)
	}
}

func TestUserScopedTokensAreBoundToIdentityKindAndScope(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	alice, err := UserScopedHookAPIToken(key, "codex", "1001")
	if err != nil || !otlpTokenHexRE.MatchString(alice) {
		t.Fatalf("derive: %v", err)
	}
	again, _ := UserScopedHookAPIToken(key, "Codex", " 1001 ")
	if again != alice {
		t.Fatal("derivation must be deterministic over canonical inputs")
	}
	distinct := map[string]string{"alice codex hook": alice}
	add := func(label, token string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		for other, value := range distinct {
			if value == token {
				t.Fatalf("%s collides with %s", label, other)
			}
		}
		distinct[label] = token
	}
	bob, err := UserScopedHookAPIToken(key, "codex", "1002")
	add("bob codex hook", bob, err)
	claude, err := UserScopedHookAPIToken(key, "claudecode", "1001")
	add("alice claudecode hook", claude, err)
	otlp, err := UserScopedOTLPPathToken(key, OTLPScopeCodex, "1001")
	add("alice codex otlp", otlp, err)
	sid, err := UserScopedHookAPIToken(key, "codex", "S-1-5-21-1-2-3-1001")
	add("sid codex hook", sid, err)
	other, err := UserScopedHookAPIToken("f"+key[1:], "codex", "1001")
	add("other key", other, err)

	lower, _ := UserScopedHookAPIToken(key, "codex", "s-1-5-21-1-2-3-1001")
	if lower != sid {
		t.Fatal("a SID must bind case-insensitively")
	}
	for _, identity := range []string{"", "alice", "01001", "-1", "99999999999", "S-1"} {
		if _, err := UserScopedHookAPIToken(key, "codex", identity); err == nil {
			t.Errorf("identity %q accepted", identity)
		}
	}
	for _, badKey := range []string{"", "short", key + "0", "Z" + key[1:]} {
		if _, err := UserScopedHookAPIToken(badKey, "codex", "1001"); err == nil {
			t.Errorf("key %q accepted", badKey)
		}
	}
	if _, err := UserScopedOTLPPathToken(key, "../x", "1001"); err == nil {
		t.Error("invalid OTLP scope accepted")
	}
}

// The listener proof is an HMAC under the credential itself, bound to the
// connector and the nonce; the key ID is the credential's SHA-256 and is not
// itself a credential.
func TestUserScopedListenerProofIsBoundToCredentialConnectorAndNonce(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	nonce := strings.Repeat("ab", 32)
	alice, _ := UserScopedHookAPIToken(key, "opencode", "S-1-5-21-1-2-3-1001")
	bob, _ := UserScopedHookAPIToken(key, "opencode", "S-1-5-21-1-2-3-1002")

	// Known answer: HMAC-SHA256(credential, domain 0 connector 0 nonce).
	mac := hmac.New(sha256.New, []byte(alice))
	mac.Write([]byte("defenseclaw.listener-proof.v1\x00opencode\x00" + nonce))
	want := hex.EncodeToString(mac.Sum(nil))
	proof, err := UserScopedListenerProof(alice, "OpenCode", nonce)
	if err != nil || proof != want {
		t.Fatalf("proof = %q, %v; want %q", proof, err, want)
	}
	for label, other := range map[string]func() (string, error){
		"another user":      func() (string, error) { return UserScopedListenerProof(bob, "opencode", nonce) },
		"another connector": func() (string, error) { return UserScopedListenerProof(alice, "amp", nonce) },
		"another nonce":     func() (string, error) { return UserScopedListenerProof(alice, "opencode", strings.Repeat("cd", 32)) },
	} {
		if got, err := other(); err != nil || got == proof {
			t.Errorf("%s: proof %q, %v; must differ", label, got, err)
		}
	}
	for label, call := range map[string]func() (string, error){
		"short nonce":      func() (string, error) { return UserScopedListenerProof(alice, "opencode", "ab") },
		"upper-case nonce": func() (string, error) { return UserScopedListenerProof(alice, "opencode", strings.Repeat("AB", 32)) },
		"bad credential":   func() (string, error) { return UserScopedListenerProof("not-a-credential", "opencode", nonce) },
		"bad connector":    func() (string, error) { return UserScopedListenerProof(alice, "../x", nonce) },
	} {
		if _, err := call(); err == nil {
			t.Errorf("%s accepted", label)
		}
	}

	digest := sha256.Sum256([]byte(alice))
	if got := UserScopedCredentialKeyID(" " + alice + "\n"); got != hex.EncodeToString(digest[:]) || got == alice {
		t.Fatalf("key ID = %q", got)
	}
}
