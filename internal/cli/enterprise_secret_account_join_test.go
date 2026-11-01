// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestAccountJoinSecretFormatAtSet(t *testing.T) {
	good := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	short := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	for _, name := range []string{"account-join-key", "account-join-key-next"} {
		if err := accountJoinSecretFormatError(name, []byte(good)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, bad := range []string{short, "hunter2-canary", strings.Repeat("A", 44) + "!"} {
			err := accountJoinSecretFormatError(name, []byte(bad))
			if err == nil || !strings.Contains(err.Error(), "32 random bytes") || strings.Contains(err.Error(), bad) {
				t.Fatalf("%s %q: %v", name, bad, err)
			}
		}
	}
	if err := accountJoinSecretFormatError("ai-defense-key", []byte("anything")); err != nil {
		t.Fatalf("other names are not checked: %v", err)
	}
}
