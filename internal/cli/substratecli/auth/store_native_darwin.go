// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package auth

import "github.com/defenseclaw/defenseclaw/internal/keystore"

// The launcher keeps its sealing key with the Security framework itself
// (GAP-0165), not through /usr/bin/security: an item the launcher creates
// trusts the launcher binary, so reading it asks nothing, also from SSH or
// tmux while the keychain is unlocked, and any other program (the security
// tool included) needs the person's approval. The calls live in
// internal/keystore, shared with the sandbox vault.

// secNative is the Security framework.
type secNative struct{ k keystore.Keychain }

func newNativeKeychain() nativeKeychain { return secNative{keystore.NewKeychain()} }

func (s secNative) find(service, account string) ([]byte, int32) { return s.k.Find(service, account) }

func (s secNative) add(service, account string, secret []byte) int32 {
	return s.k.Add(service, account, secret)
}
