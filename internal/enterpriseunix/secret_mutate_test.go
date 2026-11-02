// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
)

// A credential change runs inside the lifecycle lock: an apply watcher that
// the write wakes cannot start its own ensure until the change is applied.
func TestSecretChangeIsWrittenAndAppliedUnderOneLock(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			var raced error
			r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
				if err := h.env.WriteSecret(ctx, "ai-defense-api-key", []byte("s3cr3t")); err != nil {
					return err
				}
				lock, err := h.env.acquireLock(ctx)
				if err == nil {
					lock.release()
				}
				raced = err
				return nil
			}})
			requireOK(t, r)
			if !errors.Is(raced, errLockBusy) {
				t.Fatalf("a concurrent lifecycle run could take the lock during the change: %v", raced)
			}
			if r.Noop {
				t.Fatal("the new credential must be applied by the same run")
			}
			if !exists(filepath.Join(h.env.P(h.env.Layout.SecretsDir), "ai-defense-api-key")) {
				t.Fatal("credential not written")
			}
			if !h.run(Options{Action: ActionEnsure}).Noop {
				t.Fatal("the watcher's follow-up ensure should find nothing left to apply")
			}
		})
	}
}

// A config that cannot be inspected gives no proof that a stored credential
// is unused. Remove must leave the credential in place for both Unix layouts.
func TestRemoveSecretRefusesAnUnprovenInstalledConfig(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct {
			name, want string
			makeConfig func(string) error
			untrusted  bool
		}{
			{name: "missing", want: "cannot read the installed config"},
			{name: "not a file", want: "cannot read the installed config", makeConfig: func(path string) error { return os.Mkdir(path, 0o700) }},
			{name: "malformed", want: "cannot load the installed config", makeConfig: func(path string) error {
				return os.WriteFile(path, []byte("guardrail: [\n"), 0o600)
			}},
			{name: "untrusted", want: "cannot trust the installed config", makeConfig: func(path string) error {
				return os.WriteFile(path, []byte("config_version: 9\n"), 0o600)
			}, untrusted: true},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				layout, err := managed.StandaloneLayoutFor(goos)
				if err != nil {
					t.Fatal(err)
				}
				env := &Env{GOOS: goos, Root: t.TempDir(), Layout: layout, Trust: func(string, TrustKind) error { return nil }}
				configPath := env.P(layout.ConfigPath)
				if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if tc.makeConfig != nil {
					if err := tc.makeConfig(configPath); err != nil {
						t.Fatal(err)
					}
				}
				if tc.untrusted {
					env.Trust = func(path string, kind TrustKind) error {
						if path == configPath && kind == TrustAdminFile {
							return errors.New("administrator trust check failed")
						}
						return nil
					}
				}
				secret := filepath.Join(env.P(layout.SecretsDir), "ai-key")
				if err := os.MkdirAll(filepath.Dir(secret), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(secret, []byte("stored-value"), 0o600); err != nil {
					t.Fatal(err)
				}
				err = env.RemoveSecret("ai-key")
				if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "nothing was removed") {
					t.Fatalf("remove with %s config = %v", tc.name, err)
				}
				if code := enterprisebundle.CodeOf(err); code != enterprisebundle.CodeStateInvalid {
					t.Fatalf("refusal code = %q, want state_invalid", code)
				}
				if got, readErr := os.ReadFile(secret); readErr != nil || string(got) != "stored-value" {
					t.Fatalf("credential changed on refusal: %q, %v", got, readErr)
				}
			})
		}
	}
}

func TestSecretRemoveWithMissingConfigKeepsTheGatewayRunning(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			secret := filepath.Join(h.env.P(h.env.Layout.SecretsDir), "ai-key")
			if err := os.WriteFile(secret, []byte("stored-value"), 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := h.env.P(h.env.Layout.ConfigPath)
			if err := os.Rename(configPath, configPath+".held"); err != nil {
				t.Fatal(err)
			}
			before := len(h.services.calls)
			r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
				return h.env.RemoveSecret("ai-key")
			}})
			requireError(t, r, string(enterprisebundle.CodeStateInvalid))
			if got, err := os.ReadFile(secret); err != nil || string(got) != "stored-value" {
				t.Fatalf("credential changed: %q, %v", got, err)
			}
			if exists(configPath) {
				t.Fatal("the refused remove regenerated the config")
			}
			gateway := unitGateway
			if goos == "darwin" {
				gateway = labelGateway
			}
			if !h.services.isActive(gateway) {
				t.Fatal("the refused remove stopped the gateway")
			}
			for _, call := range h.services.calls[before:] {
				if strings.Contains(call, gateway) {
					t.Fatalf("the refused remove touched the gateway: %v", h.services.calls[before:])
				}
			}
		})
	}
}

func testSecretRemovalWithGatewayConfigReadDenied(t *testing.T, putBack bool) {
	t.Helper()
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	const name = "ai-key"
	secret := filepath.Join(h.env.P(h.env.Layout.SecretsDir), name)
	if err := h.env.WriteSecret(t.Context(), name, []byte("stored-value")); err != nil {
		t.Fatal(err)
	}
	configPath := h.env.P(h.env.Layout.ConfigPath)
	if putBack {
		// The prior installed config may still name a value added by a
		// failed rotation. Its put-back must make the same read proof.
		cfg := strings.Replace(string(DefaultConfig(h.env.Layout)), "  profile: standalone\n",
			"  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-key\n", 1)
		if err := os.WriteFile(configPath, []byte(cfg), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	entry := "user:" + h.env.Layout.ServiceUser + " deny read"
	h.runner.acls = map[string][]string{configPath: {entry}}
	h.runner.replies = map[string]fakeReply{
		"chmod -h -a# 0 " + configPath: {err: errors.New("ACL repair denied")},
	}
	undone := false
	r := h.run(Options{Action: ActionEnsure, Reason: "secret",
		Mutate: func(context.Context) error {
			if putBack {
				if _, err := h.env.InstalledSecretConfig(false); err != nil {
					return err
				}
				return h.env.RemoveRotatedSecret(name)
			}
			return h.env.RemoveSecret(name)
		},
		MutateUndo: func(ctx context.Context) error {
			undone = true
			return h.env.WriteSecret(ctx, name, []byte("stored-value"))
		}})
	if got, err := os.ReadFile(secret); err != nil || string(got) != "stored-value" {
		t.Fatalf("credential deleted after gateway read denial: %q, %v; result=%+v, undo=%v", got, err, r.Errors, undone)
	}
	requireError(t, r, string(enterprisebundle.CodeStateInvalid))
	if got := messagesOf(r.Errors, string(enterprisebundle.CodeStateInvalid)); !strings.Contains(got, entry) || !strings.Contains(got, "nothing was removed") ||
		!strings.Contains(got, "retry") {
		t.Fatalf("refusal does not name the gateway read denial and next step: %+v", r.Errors)
	}
}

func TestR502RemoveWithGatewayConfigReadDenial(t *testing.T) {
	testSecretRemovalWithGatewayConfigReadDenied(t, false)
}

func TestR502PutBackWithGatewayConfigReadDenial(t *testing.T) {
	testSecretRemovalWithGatewayConfigReadDenied(t, true)
}

func TestR502RemoveRefusesUnreadableServiceConfigMode(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			secret := filepath.Join(h.env.P(h.env.Layout.SecretsDir), "ai-key")
			if err := h.env.WriteSecret(t.Context(), "ai-key", []byte("stored-value")); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.env.P(h.env.Layout.ConfigPath), 0o600); err != nil {
				t.Fatal(err)
			}
			err := h.env.RemoveSecret("ai-key")
			if enterprisebundle.CodeOf(err) != enterprisebundle.CodeStateInvalid ||
				!strings.Contains(err.Error(), "0600") || !strings.Contains(err.Error(), h.env.Layout.ServiceUser) {
				t.Fatalf("unreadable config mode: %v", err)
			}
			if got, err := os.ReadFile(secret); err != nil || string(got) != "stored-value" {
				t.Fatalf("credential changed: %q, %v", got, err)
			}
		})
	}
}

func TestR502RemoveRefusesLinuxNamedUserACLDenial(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if err := h.env.WriteSecret(t.Context(), "ai-key", []byte("stored-value")); err != nil {
		t.Fatal(err)
	}
	configPath := h.env.P(h.env.Layout.ConfigPath)
	account := h.accounts.accounts[h.env.Layout.ServiceUser]
	before := secretConfigACLReader
	t.Cleanup(func() { secretConfigACLReader = before })
	secretConfigACLReader = fakeJSONLACLReader(func(path string, mode os.FileMode) (posixacl.View, error) {
		if path == configPath {
			return posixacl.View{Present: true, Owner: 6, Group: 4, Other: 0, Mask: 4,
				Users: []posixacl.Entry{{Kind: "user", ID: account.UID, Perm: 0}}}, nil
		}
		return posixacl.View{}, nil
	})
	err := h.env.RemoveSecret("ai-key")
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeStateInvalid || !strings.Contains(err.Error(), "cannot read") {
		t.Fatalf("named-user ACL denial: %v", err)
	}
	if !exists(filepath.Join(h.env.P(h.env.Layout.SecretsDir), "ai-key")) {
		t.Fatal("credential deleted through named-user ACL denial")
	}
}

func TestR502RemovalIsPutBackOnApplyFailure(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	const name = "ai-key"
	secret := filepath.Join(h.env.P(h.env.Layout.SecretsDir), name)
	if err := h.env.WriteSecret(t.Context(), name, []byte("stored-value")); err != nil {
		t.Fatal(err)
	}
	gatewayPath := filepath.Join(h.env.P(h.env.Layout.BinDir), binGateway)
	h.runner.acls = map[string][]string{gatewayPath: {"user:developer allow write"}}
	h.runner.replies = map[string]fakeReply{
		"chmod -h -a# 0 " + gatewayPath: {err: errors.New("ACL repair denied")},
	}
	removed, undone := false, false
	r := h.run(Options{Action: ActionEnsure, Reason: "secret",
		Mutate: func(context.Context) error {
			if err := h.env.RemoveSecret(name); err != nil {
				return err
			}
			removed = !exists(secret)
			return nil
		},
		MutateUndo: func(ctx context.Context) error {
			undone = true
			return h.env.WriteSecret(ctx, name, []byte("stored-value"))
		}})
	requireError(t, r, codeApply)
	if !removed || !undone || !strings.Contains(messagesOf(r.Warnings, codeChange), "put back") {
		t.Fatalf("deleted credential was not restored and reported: removed=%v undone=%v errors=%+v warnings=%+v", removed, undone, r.Errors, r.Warnings)
	}
	if got, err := os.ReadFile(secret); err != nil || string(got) != "stored-value" {
		t.Fatalf("credential absent after apply_failed: %q, %v", got, err)
	}
}

func TestFailedSecretChangeAppliesNothing(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	before := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
		return errors.New("credential name is not valid")
	}})
	if r.OK || len(r.Errors) == 0 || r.Errors[0].Code != codeChange {
		t.Fatalf("result %+v", r)
	}
	// Only the apply watcher's pause around the change (GAP-2261).
	if got, want := h.services.calls[before:], []string{"stop " + unitApplyPath, "start " + unitApplyPath}; !slices.Equal(got, want) {
		t.Fatalf("a failed change touched services: %v", got)
	}
	if r := h.run(Options{Action: ActionRepair, Mutate: func(context.Context) error { return nil }}); r.OK {
		t.Fatal("a change outside ensure must be refused")
	}
}

// A secret set the signed bundle refuses (a value it does not bind) fails
// with the bundle's code, so the agent can tell a rotation that needs a new
// bundle from a failed write (GAP-0335).
func TestSecretChangeRefusalKeepsTheBundleCode(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	confirmed := &enterprisebundle.Manifest{TenantID: "acme", SecretRefs: []enterprisebundle.SecretRef{{Ref: "secret://splunk-token", Required: true,
		ValueSHA256: enterprisebundle.CredentialValueSHA256("acme", "splunk-token", []byte("v1"))}}}
	r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
		return enterprisebundle.CheckCredentialChange(confirmed, nil, "splunk-token", []byte("v2"))
	}})
	if r.OK || len(r.Errors) == 0 || r.Errors[0].Code != string(enterprisebundle.CodeSecretRefMismatch) {
		t.Fatalf("result %+v, want secret_ref_mismatch", r)
	}
}

// The apply watcher does not see the change's own write: it would start a
// redundant ensure that holds the lock after this run returns, so a command
// typed right after secret set failed lifecycle_busy (GAP-2261).
func TestSecretChangePausesTheApplyWatcher(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if !h.services.isActive(unitApplyPath) {
		t.Fatal("the apply watcher should run after install")
	}
	watching := true
	r := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
		watching = h.services.isActive(unitApplyPath)
		return h.env.WriteSecret(ctx, "ai-defense-api-key", []byte("s3cr3t"))
	}})
	requireOK(t, r)
	if watching {
		t.Fatal("the apply watcher was watching while the credential was written")
	}
	if !h.services.isActive(unitApplyPath) {
		t.Fatal("the apply watcher was not started again")
	}
}

// GAP-1734: a credential change whose ensure then refuses the config before
// it changes anything (an untrusted pack in use) is put back: the credential
// store holds what it held, as the result's "the refused config changed
// nothing" says.
func TestRefusedSecretChangeIsPutBack(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	const pack = "/etc/defenseclaw/policies/guardrail/custom"
	if err := os.MkdirAll(h.env.P(pack), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := writeChangedConfig(t, h, "rule_pack: default",
		"rule_pack: acme\n  custom_packs:\n    acme: {path: "+pack+", digest: \"sha256:"+strings.Repeat("a", 64)+"\"}")
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: cfg}))
	h.env.Trust = func(path string, kind TrustKind) error {
		if kind == TrustRulePack && path == h.env.P(pack) {
			return errors.New(path + ": group/other writable permissions 0775 are not trusted")
		}
		return nil
	}
	secret := filepath.Join(h.env.P(h.env.Layout.SecretsDir), "galileo-api-key")
	undone := false
	r := h.run(Options{Action: ActionEnsure, Reason: "secret",
		Mutate: func(ctx context.Context) error {
			return h.env.WriteSecret(ctx, "galileo-api-key", []byte("s3cr3t"))
		},
		MutateUndo: func(context.Context) error {
			undone = true
			return h.env.RemoveRotatedSecret("galileo-api-key")
		}})
	requireError(t, r, codeConfig)
	if !r.ConfigRefused || !undone {
		t.Fatalf("refused=%v undone=%v errors=%+v", r.ConfigRefused, undone, r.Errors)
	}
	if exists(secret) {
		t.Fatal("the refused credential change left the new credential on disk")
	}
	// A change the run applies is kept.
	h.env.Trust = func(string, TrustKind) error { return nil }
	undone = false
	r = h.run(Options{Action: ActionEnsure, Reason: "secret",
		Mutate: func(ctx context.Context) error {
			return h.env.WriteSecret(ctx, "galileo-api-key", []byte("s3cr3t"))
		},
		MutateUndo: func(context.Context) error { undone = true; return nil }})
	requireOK(t, r)
	if undone || !exists(secret) {
		t.Fatalf("an applied credential change was put back: undone=%v", undone)
	}
}
