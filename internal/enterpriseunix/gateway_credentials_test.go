// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
)

// rel-1-0-6:GAP-0301: the gateway is given the credentials it uses, not
// the tenant secrets of the account join key, which only root reads.
// systemd 247+ passes no LoadCredential for them; where the gateway reads
// credentials through the secrets folder's group (an older systemd, macOS)
// they are root-only 0600, also an existing 0640 one after the next ensure.
// Root (enterprise status, verify, account-keys) still reads them.
func TestTheGatewayIsNotGivenTheAccountJoinSecrets(t *testing.T) {
	secrets := []string{accountjoin.SecretName, accountjoin.NextSecretName}
	write := func(t *testing.T, h *testHost, name, value string) string {
		t.Helper()
		if err := h.env.WriteSecret(context.Background(), name, []byte(value)); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(h.env.Layout.SecretsDir, name)
	}
	rootOnly := func(t *testing.T, h *testHost, path string) {
		t.Helper()
		if mode := h.mode(path); mode != 0o600 {
			t.Errorf("%s is %04o, want 0600", path, mode)
		}
		if uid, gid, err := h.env.OwnerOf(h.env.P(path)); err != nil || uid != 0 || gid != 0 {
			t.Errorf("%s is owned %d:%d (%v), want root:root", path, uid, gid, err)
		}
	}

	t.Run("linux systemd 255", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		write(t, h, "ai-defense-api-key", "k")
		for _, name := range secrets {
			rootOnly(t, h, write(t, h, name, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"))
		}
		requireOK(t, h.run(Options{Action: ActionEnsure}))
		dropin := h.read("/etc/systemd/system/" + unitGateway + ".d/" + dropinCredentials)
		if !strings.Contains(dropin, "LoadCredential=ai-defense-api-key:") || !strings.Contains(dropin, "InaccessiblePaths=-/etc/defenseclaw/secrets") {
			t.Fatalf("the gateway lost the credentials it uses: %s", dropin)
		}
		for _, name := range secrets {
			if strings.Contains(dropin, "LoadCredential="+name+":") {
				t.Errorf("the gateway is given %s: %s", name, dropin)
			}
		}
		for _, name := range secrets {
			if value, err := h.env.SecretValue(name); err != nil || len(value) == 0 {
				t.Errorf("root cannot read %s: %v", name, err)
			}
		}
	})

	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos+" group-readable store", func(t *testing.T) {
			h := newTestHost(t, goos)
			if goos == "linux" {
				h.services.version = 239
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			used := write(t, h, "ai-defense-api-key", "k")
			if mode := h.mode(used); mode != 0o640 {
				t.Fatalf("the credential the gateway uses is %04o, want 0640", mode)
			}
			join := write(t, h, accountjoin.SecretName, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
			rootOnly(t, h, join)
			// One stored before this change (group-readable) is closed by
			// the next ensure.
			if err := os.Chmod(h.env.P(join), 0o640); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			rootOnly(t, h, join)
			if mode := h.mode(used); mode != 0o640 {
				t.Fatalf("ensure changed the credential the gateway uses to %04o", mode)
			}
			if value, err := h.env.SecretValue(accountjoin.SecretName); err != nil || len(value) == 0 {
				t.Fatalf("root cannot read the account join secret: %v", err)
			}
		})
	}
}
