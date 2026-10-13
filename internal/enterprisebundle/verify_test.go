// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

var (
	signedAt = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	verifyAt = signedAt.Add(time.Hour)
)

const tamperBundleID = "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A"

type anchorKey struct {
	id, status, notBefore, notAfter string
	public                          crypto.PublicKey
}

func anchors(t *testing.T, tenant string, groups []string, minVersion uint64, keys ...anchorKey) *enterprisebundle.Anchors {
	t.Helper()
	var parts []string
	for _, k := range keys {
		spki, err := x509.MarshalPKIXPublicKey(k.public)
		if err != nil {
			t.Fatal(err)
		}
		alg, _ := enterprisebundle.KeyAlg(k.public)
		parts = append(parts, fmt.Sprintf(`{"key_id":%q,"alg":%q,"public_key":%q,"not_before":%q,"not_after":%q,"status":%q}`,
			k.id, alg, base64.StdEncoding.EncodeToString(spki), k.notBefore, k.notAfter, k.status))
	}
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = fmt.Sprintf("%q", g)
	}
	a, err := enterprisebundle.DecodeAnchors([]byte(fmt.Sprintf(`{"schema_version":1,"tenant_id":%q,"device_groups":[%s],"min_version":%d,"keys":[%s]}`,
		tenant, strings.Join(quoted, ","), minVersion, strings.Join(parts, ","))))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func activeKey(id string, public crypto.PublicKey) anchorKey {
	return anchorKey{id: id, status: enterprisebundle.KeyActive, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", public: public}
}

type fixture struct {
	key    ed25519.PrivateKey
	in     enterprisebundle.ComposeInput
	raw    []byte
	bundle *enterprisebundle.Bundle
}

func newFixture(t *testing.T, configYAML string, edit func(*enterprisebundle.ComposeInput)) *fixture {
	t.Helper()
	root, b := writeBundle(t, configYAML)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	in := enterprisebundle.ComposeInput{
		Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
		CreatedAt: signedAt, CreatedBy: "operator:alice", ChangeSummary: "tamper matrix",
		ProductVersion: "1.0.2", HostPlatform: runtime.GOOS, Digester: digester,
	}
	if edit != nil {
		edit(&in)
	}
	_, raw, err := enterprisebundle.Compose(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{key: key, in: in, raw: raw}
	f.bundle = f.signed(t, raw)
	return f
}

func (f *fixture) signed(t *testing.T, raw []byte) *enterprisebundle.Bundle {
	t.Helper()
	sig, err := enterprisebundle.Sign(raw, f.key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	sigRaw, _ := sig.Marshal()
	return &enterprisebundle.Bundle{Manifest: raw, Signature: sigRaw, Files: maps.Clone(f.in.Bundle.Files)}
}

func (f *fixture) input(t *testing.T, b *enterprisebundle.Bundle, a *enterprisebundle.Anchors) enterprisebundle.VerifyInput {
	return enterprisebundle.VerifyInput{
		Bundle: b, Anchors: a, Platform: enterprisebundle.PlatformLinux, Now: verifyAt,
		ProductVersion: "1.0.2", HostPlatform: runtime.GOOS, Digester: digester,
		Stage: func(b *enterprisebundle.Bundle) (string, error) {
			root := t.TempDir()
			for name, data := range b.Files {
				full := filepath.Join(root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
					return "", err
				}
				if err := os.WriteFile(full, data, 0o600); err != nil {
					return "", err
				}
			}
			return root, nil
		},
	}
}

func flip(data []byte, i int) []byte {
	out := append([]byte(nil), data...)
	out[i] ^= 0x01
	return out
}

// The tamper matrix: every change to a signed bundle, its anchors or the
// device facts is refused with its code, before anything is installed;
// the untouched bundle verifies with its digest compared.
func TestVerifyTamperMatrix(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, bundleConfig(t), nil)
	public := f.key.Public()
	good := anchors(t, "acme", []string{"eng"}, 0, activeKey("k1", public))

	res, err := enterprisebundle.Verify(ctx, f.input(t, f.bundle, good))
	if err != nil || !res.DigestVerified || res.AlreadyApplied || res.EffectivePolicyDigest != res.ExpectedDigest {
		t.Fatalf("untouched bundle: %+v %v", res, err)
	}

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherEd, _, _ := ed25519.GenerateKey(rand.Reader)
	reSigned := func(edit func(*enterprisebundle.Manifest)) *enterprisebundle.Bundle {
		m, err := enterprisebundle.DecodeManifest(f.raw)
		if err != nil {
			t.Fatal(err)
		}
		edit(m)
		raw, _ := m.Marshal()
		return f.signed(t, raw)
	}
	withFiles := func(edit func(map[string][]byte)) *enterprisebundle.Bundle {
		b := &enterprisebundle.Bundle{Manifest: f.bundle.Manifest, Signature: f.bundle.Signature, Files: maps.Clone(f.bundle.Files)}
		edit(b.Files)
		return b
	}
	bareSig := func() []byte {
		raw := ed25519.Sign(f.key, f.raw) // no domain prefix
		return []byte(fmt.Sprintf(`{"schema_version":1,"key_id":"k1","alg":"ed25519","sig":%q}`, base64.StdEncoding.EncodeToString(raw)))
	}

	cases := map[string]struct {
		bundle  *enterprisebundle.Bundle
		anchors *enterprisebundle.Anchors
		edit    func(*enterprisebundle.VerifyInput)
		code    enterprisebundle.Code
	}{
		"no anchors":            {anchors: nil, code: enterprisebundle.CodeAnchorMissing},
		"no signature":          {bundle: &enterprisebundle.Bundle{Manifest: f.raw, Files: f.bundle.Files}, code: enterprisebundle.CodeSignatureInvalid},
		"manifest byte flipped": {bundle: &enterprisebundle.Bundle{Manifest: flip(f.raw, strings.Index(string(f.raw), "tamper")), Signature: f.bundle.Signature, Files: f.bundle.Files}, code: enterprisebundle.CodeSignatureInvalid},
		"signature flipped": {bundle: func() *enterprisebundle.Bundle {
			sig, _ := enterprisebundle.DecodeSignature(f.bundle.Signature)
			raw, _ := base64.StdEncoding.DecodeString(sig.Sig)
			sig.Sig = base64.StdEncoding.EncodeToString(flip(raw, 10))
			out, _ := sig.Marshal()
			return &enterprisebundle.Bundle{Manifest: f.raw, Signature: out, Files: f.bundle.Files}
		}(), code: enterprisebundle.CodeSignatureInvalid},
		"no domain prefix":   {bundle: &enterprisebundle.Bundle{Manifest: f.raw, Signature: bareSig(), Files: f.bundle.Files}, code: enterprisebundle.CodeSignatureInvalid},
		"unknown key":        {anchors: anchors(t, "acme", nil, 0, activeKey("k2", public)), code: enterprisebundle.CodeKeyUnknown},
		"other key, same id": {anchors: anchors(t, "acme", nil, 0, activeKey("k1", otherEd)), code: enterprisebundle.CodeSignatureInvalid},
		"algorithm mismatch": {anchors: anchors(t, "acme", nil, 0, activeKey("k1", &ecKey.PublicKey)), code: enterprisebundle.CodeSignatureInvalid},
		"revoked key":        {anchors: anchors(t, "acme", nil, 0, anchorKey{id: "k1", status: enterprisebundle.KeyRevoked, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", public: public}), code: enterprisebundle.CodeKeyRevoked},
		"expired key":        {edit: func(in *enterprisebundle.VerifyInput) { in.Now = time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC) }, code: enterprisebundle.CodeKeyExpired},
		"created before key": {anchors: anchors(t, "acme", nil, 0, anchorKey{id: "k1", status: enterprisebundle.KeyActive, notBefore: "2026-10-12T09:30:00Z", notAfter: "2027-01-01T00:00:00Z", public: public}), code: enterprisebundle.CodeKeyExpired},
		"retired key":        {anchors: anchors(t, "acme", nil, 0, anchorKey{id: "k1", status: enterprisebundle.KeyRetired, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", public: public}), code: enterprisebundle.CodeKeyExpired},
		"other tenant":       {anchors: anchors(t, "globex", nil, 0, activeKey("k1", public)), code: enterprisebundle.CodeTenantMismatch},
		"other device group": {anchors: anchors(t, "acme", []string{"ops"}, 0, activeKey("k1", public)), code: enterprisebundle.CodeTargetMismatch},
		"platform not targeted": {bundle: reSigned(func(m *enterprisebundle.Manifest) {
			m.Target.Platforms = []string{"darwin"}
			m.EffectivePolicy.Digests = map[string]string{"darwin": m.EffectivePolicy.Digests["darwin"]}
		}), code: enterprisebundle.CodeTargetMismatch},
		"below anchor floor": {anchors: anchors(t, "acme", nil, 5, activeKey("k1", public)), code: enterprisebundle.CodeVersionNotNewer},
		"replay of older": {edit: func(in *enterprisebundle.VerifyInput) {
			in.Confirmed = enterprisebundle.Confirmed{Version: 6, BundleID: "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2B"}
		}, code: enterprisebundle.CodeVersionNotNewer},
		"product too old": {bundle: reSigned(func(m *enterprisebundle.Manifest) { m.MinProductVersion = "9.0.0" }), code: enterprisebundle.CodeProductTooOld},
		"file changed":    {bundle: withFiles(func(files map[string][]byte) { files["discovery/confidence.yaml"] = []byte("version: 2\n") }), code: enterprisebundle.CodeFileHashMismatch},
		"file added":      {bundle: withFiles(func(files map[string][]byte) { files["discovery/extra.yaml"] = []byte("x: 1\n") }), code: enterprisebundle.CodeFileExtra},
		"file removed":    {bundle: withFiles(func(files map[string][]byte) { delete(files, "discovery/confidence.yaml") }), code: enterprisebundle.CodeFileMissing},
		"digest mismatch": {bundle: reSigned(func(m *enterprisebundle.Manifest) {
			m.EffectivePolicy.Digests["linux"] = "sha256:" + strings.Repeat("0", 64)
		}), code: enterprisebundle.CodeDigestMismatch},
	}
	for name, tc := range cases {
		b := tc.bundle
		if b == nil {
			b = f.bundle
		}
		a := tc.anchors
		if a == nil && name != "no anchors" {
			a = good
		}
		in := f.input(t, b, a)
		if tc.edit != nil {
			tc.edit(&in)
		}
		if _, err := enterprisebundle.Verify(ctx, in); enterprisebundle.CodeOf(err) != tc.code {
			t.Errorf("%s: want %s, got %v", name, tc.code, err)
		}
	}

	// The confirmed bundle verifies as already applied, also with a key
	// retired since; another product version cannot compare the digest.
	retired := anchors(t, "acme", nil, 0, anchorKey{id: "k1", status: enterprisebundle.KeyRetired, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", public: public})
	in := f.input(t, f.bundle, retired)
	sum := sha256.Sum256(f.bundle.Manifest)
	confirmed := enterprisebundle.Confirmed{Version: 5, BundleID: tamperBundleID, ManifestSHA256: hex.EncodeToString(sum[:])}
	in.Confirmed = confirmed
	if res, err := enterprisebundle.Verify(ctx, in); err != nil || !res.AlreadyApplied || res.Floor != 5 {
		t.Fatalf("already applied: %+v %v", res, err)
	}
	// The retired key cannot sign other content under the confirmed id and
	// version: that is not the applied bundle.
	in = f.input(t, reSigned(func(m *enterprisebundle.Manifest) { m.ChangeSummary = "other content" }), retired)
	in.Confirmed = confirmed
	if _, err := enterprisebundle.Verify(ctx, in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeVersionNotNewer {
		t.Fatalf("retired key, other manifest under the confirmed id: %v", err)
	}
	in = f.input(t, f.bundle, good)
	in.ProductVersion = "1.0.3"
	res, err = enterprisebundle.Verify(ctx, in)
	if err != nil || res.DigestVerified || len(res.Warnings) == 0 || res.Warnings[0].Code != enterprisebundle.WarnDigestUnverifiable {
		t.Fatalf("other product version: %+v %v", res, err)
	}
}

// A signer and verifier stage the same files in different directories. Path
// defaults derived from those directories must not change the signed digest.
func TestVerifyBundleWithDefaultedPaths(t *testing.T) {
	const base = `config_version: 9
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  enabled: true
  mode: action
  block_at: HIGH
  rule_pack: default
  profiles:
    engineering:
      mode: action
      block_at: HIGH
  profile_assignments:
    - profile: engineering
      match:
        groups: [engineering]
asset_policy:
  enabled: true
  mode: action
  skill:
    default: deny
ai_discovery:
  enabled: true
  signature_packs:
    - discovery/signature-packs/team.json
`
	for _, tc := range []struct {
		name, prefix                     string
		defaultDataDir, defaultPolicyDir bool
	}{
		{name: "data_dir omitted, policy_dir empty", prefix: "policy_dir: \"\"\n", defaultDataDir: true},
		{name: "data_dir and policy_dir omitted", defaultDataDir: true, defaultPolicyDir: true},
		{name: "data_dir explicit", prefix: "data_dir: /var/lib/defenseclaw\npolicy_dir: \"\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := tc.prefix + base
			if tc.defaultPolicyDir {
				start, end := strings.Index(source, "guardrail:\n"), strings.Index(source, "asset_policy:\n")
				source = source[:start] + source[end:]
			}
			f := newFixture(t, source, func(in *enterprisebundle.ComposeInput) {
				if !tc.defaultPolicyDir {
					return
				}
				const name = "policies/guardrail/default/rules/local-patterns.yaml"
				data := []byte("version: 1\ninjection: []\n")
				in.Bundle.Files[name] = data
				full := filepath.Join(in.Root, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, data, 0o644); err != nil {
					t.Fatal(err)
				}
			})
			a := anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
			checkDefaultPaths := func(cfg *config.Config, root string) {
				t.Helper()
				if !tc.defaultDataDir {
					return
				}
				for _, field := range []struct{ name, got, suffix string }{
					{"data_dir", cfg.DataDir, ""},
					{"audit_db", cfg.AuditDB, config.DefaultAuditDBName},
					{"judge_bodies_db", cfg.JudgeBodiesDB, config.DefaultJudgeBodiesDBName},
					{"quarantine_dir", cfg.QuarantineDir, "quarantine"},
					{"plugin_dir", cfg.PluginDir, "plugins"},
					{"scanners.codeguard", cfg.Scanners.CodeGuard, "codeguard-rules"},
					{"ai_discovery.confidence_policy_path", cfg.AIDiscovery.ConfidencePolicyPath, "confidence.yaml"},
					{"firewall.config_file", cfg.Firewall.ConfigFile, "firewall.yaml"},
					{"firewall.rules_file", cfg.Firewall.RulesFile, "firewall.pf.conf"},
					{"openshell.pack_dir", cfg.OpenShell.PackDir, filepath.Join("policies", config.DefaultOpenShellPackDirName)},
					{"gateway.device_key_file", cfg.Gateway.DeviceKeyFile, "device.key"},
				} {
					if want := filepath.Join(root, field.suffix); field.got != want {
						t.Errorf("%s = %q, want %q", field.name, field.got, want)
					}
				}
				if tc.defaultPolicyDir && cfg.PolicyDir != filepath.Join(root, "policies") {
					t.Errorf("policy_dir = %q, want default under %q", cfg.PolicyDir, root)
				}
			}
			cfg, raw, err := enterprisebundle.LoadConfig(f.in.Bundle, f.in.Root)
			if err != nil {
				t.Fatal(err)
			}
			checkDefaultPaths(cfg, f.in.Root)
			signedPolicy, err := gateway.ComputeEffectivePolicyFor(context.Background(), cfg, gateway.EffectivePolicyOptions{GOOS: "linux", BundleRoot: f.in.Root, Raw: raw})
			if err != nil {
				t.Fatal(err)
			}
			in := f.input(t, f.bundle, a)
			in.Digester = func(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
				checkDefaultPaths(cfg, root)
				policy, err := gateway.ComputeEffectivePolicyFor(ctx, cfg, gateway.EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
				for key, want := range signedPolicy.Components {
					if got := policy.Components[key]; got != want {
						t.Errorf("component %s: signed %s, verified %s", key, want, got)
					}
				}
				return policy.Digest, err
			}
			res, err := enterprisebundle.Verify(context.Background(), in)
			if err != nil || !res.DigestVerified {
				t.Fatalf("signed bundle did not verify after staging elsewhere: digest=%s expected=%s: %v", res.EffectivePolicyDigest, res.ExpectedDigest, err)
			}
		})
	}
}

// A required credential the device lacks keeps the bundle out
// (secret_ref_missing); an unreadable store only warns.
func TestVerifySecretPresence(t *testing.T) {
	cfg := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	f := newFixture(t, cfg, nil)
	m, _ := enterprisebundle.DecodeManifest(f.raw)
	if len(m.SecretRefs) != 1 || m.SecretRefs[0].Ref != "secret://ai-defense-api-key" || !m.SecretRefs[0].Required {
		t.Fatalf("sign did not record the reference: %+v", m.SecretRefs)
	}
	a := anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
	in := f.input(t, f.bundle, a)
	in.SecretPresent = func(string) (bool, error) { return false, nil }
	if _, err := enterprisebundle.Verify(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing {
		t.Fatalf("missing credential: %v", err)
	}
	in.SecretPresent = func(string) (bool, error) { return false, os.ErrPermission }
	res, err := enterprisebundle.Verify(context.Background(), in)
	if err != nil || res.Warnings[0].Code != enterprisebundle.WarnSecretPresenceUnchecked {
		t.Fatalf("unreadable store: %+v %v", res, err)
	}
}
