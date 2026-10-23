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
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
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
		ProductVersion: "1.0.2", Digester: digester,
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

func TestBundleVerifyRejectsSignedUnknownConfigSetting(t *testing.T) {
	f := newFixture(t, bundleConfig(t), nil)
	invalid := strings.Replace(bundleConfig(t), "guardrail:\n  enabled: true\n  mode: observe\n", "guardrail:\n  enabled: true\n  mode: observe\n  rules:\n    definitions: policies/guardrail/missing\n", 1)
	if invalid == bundleConfig(t) {
		t.Fatal("test config has no guardrail mode to extend")
	}
	f.in.Bundle.Files[enterprisebundle.ConfigName] = []byte(invalid)
	m, err := enterprisebundle.DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	m.Files = enterprisebundle.FileEntries(&enterprisebundle.Bundle{Files: f.in.Bundle.Files})
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b := f.signed(t, raw)
	a := anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
	_, err = enterprisebundle.Verify(context.Background(), f.input(t, b, a))
	if enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(err.Error(), "guardrail.rules.definitions") {
		t.Fatalf("verify accepted a signed unknown setting: %v", err)
	}
}

func flip(data []byte, i int) []byte {
	out := append([]byte(nil), data...)
	out[i] ^= 0x01
	return out
}

func TestAnchorMinVersionIsExclusiveFloor(t *testing.T) {
	m := &enterprisebundle.Manifest{Version: 1, BundleID: "b-01JA0000000000000000000032"}
	_, floor, err := enterprisebundle.CheckFloor(m, strings.Repeat("a", 64), enterprisebundle.Confirmed{}, 1)
	if floor != 1 || enterprisebundle.CodeOf(err) != enterprisebundle.CodeVersionNotNewer ||
		!strings.Contains(err.Error(), "version 1 is not above the floor 1 (set by trust anchor min_version)") {
		t.Fatalf("floor = %d, refusal = %v", floor, err)
	}
}

func TestFloorSourceNamesEffectiveAuthority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		confirmed uint64
		anchor    uint64
		source    string
		message   string
	}{
		{"anchor", 1, 2, "trust_anchor_min_version", "trust anchor min_version"},
		{"confirmed", 2, 1, "last_confirmed_bundle", "the last confirmed bundle"},
		{"both", 2, 2, "both", "trust anchor min_version and the last confirmed bundle"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			confirmed := enterprisebundle.Confirmed{Version: tc.confirmed}
			if got := enterprisebundle.FloorSource(confirmed, tc.anchor); got != tc.source {
				t.Fatalf("floor source = %q", got)
			}
			_, _, err := enterprisebundle.CheckFloor(&enterprisebundle.Manifest{Version: 1}, "", confirmed, tc.anchor)
			if err == nil || !strings.Contains(err.Error(), "set by "+tc.message) {
				t.Fatalf("floor refusal = %v", err)
			}
		})
	}
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

// GAP-0113: a signer that ran this product version computes the device's
// digest on any OS, so every signer and device platform pair compares the
// signed digest. An equal digest verifies; a device that computes another
// digest refuses the validly signed bundle with digest_mismatch and names the
// signed component that differs, the compiled-in builtin component too. Only
// another signer product version leaves the digest unverifiable.
func TestVerifyComparesSignedDigestOnEverySignerPlatform(t *testing.T) {
	const signed = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const device = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	reporting := func(digest string, components map[string]string) enterprisebundle.PolicyDigester {
		return func(ctx context.Context, _ *config.Config, _ []byte, _, _ string) (string, error) {
			enterprisebundle.ReportPolicyComponents(ctx, components)
			return digest, nil
		}
	}
	for _, signer := range enterprisebundle.Platforms {
		for _, target := range enterprisebundle.Platforms {
			t.Run(signer+"-signs-"+target, func(t *testing.T) {
				f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) {
					in.Platforms = []string{target}
					in.HostPlatform = signer
					in.Digester = reporting(signed, map[string]string{"builtin": signed, "config": signed})
				})
				in := f.input(t, f.bundle, anchors(t, "acme", []string{"eng"}, 0, activeKey("k1", f.key.Public())))
				in.Platform = target
				in.Digester = reporting(signed, map[string]string{"builtin": signed, "config": signed})
				if res, err := enterprisebundle.Verify(context.Background(), in); err != nil || !res.DigestVerified || res.DigestUnverifiable {
					t.Fatalf("equal digest = %+v, %v", res, err)
				}
				for component, local := range map[string]map[string]string{
					"config":  {"builtin": signed, "config": device},
					"builtin": {"builtin": device, "config": signed},
				} {
					in.Digester = reporting(device, local)
					res, err := enterprisebundle.Verify(context.Background(), in)
					if enterprisebundle.CodeOf(err) != enterprisebundle.CodeDigestMismatch || res.DigestVerified || res.DigestUnverifiable ||
						!strings.Contains(err.Error(), "component "+component+" differs") ||
						!strings.Contains(err.Error(), "the signer computed the digest on "+signer) {
						t.Fatalf("%s differs: %+v, %v", component, res, err)
					}
					if (component == "builtin") != strings.Contains(err.Error(), "sign with the build the devices run") {
						t.Fatalf("%s differs: builtin hint in %v", component, err)
					}
				}
				in.ProductVersion = "1.0.3"
				res, err := enterprisebundle.Verify(context.Background(), in)
				if err != nil || res.DigestVerified || !res.DigestUnverifiable || len(res.Warnings) == 0 ||
					res.Warnings[0].Code != enterprisebundle.WarnDigestUnverifiable || !strings.Contains(res.Warnings[0].Message, "product version 1.0.2") {
					t.Fatalf("other product version = %+v, %v", res, err)
				}
			})
		}
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
		{name: "data_dir and policy_dir omitted", defaultDataDir: true, defaultPolicyDir: true},
		{name: "data_dir explicit", prefix: "data_dir: /var/lib/defenseclaw\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := tc.prefix + base
			if !tc.defaultPolicyDir {
				_, file, _, _ := runtime.Caller(0)
				source += fmt.Sprintf("policy_dir: %q\n", filepath.Join(filepath.Dir(file), "..", "..", "policies"))
			}
			if tc.defaultPolicyDir {
				start, end := strings.Index(source, "guardrail:\n"), strings.Index(source, "asset_policy:\n")
				// The installed Unix default pack lives under the vendor tree,
				// which an offline test host need not have. This path-default
				// check uses a digester over loaded paths below.
				source = source[:start] + source[end:]
			}
			f := newFixture(t, source, func(in *enterprisebundle.ComposeInput) {
				in.Digester = func(_ context.Context, cfg *config.Config, raw []byte, _, root string) (string, error) {
					canonical := strings.ReplaceAll(string(raw), root, "${bundle_root}")
					sum := sha256.Sum256([]byte(fmt.Sprint(cfg.DataDir, cfg.PolicyDir, cfg.Guardrail.RulePackDir, cfg.QuarantineDir, canonical)))
					return "sha256:" + hex.EncodeToString(sum[:]), nil
				}
				if !tc.defaultDataDir {
					in.Platforms = []string{"linux"}
				}
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
					{"gateway.device_key_file", cfg.Gateway.DeviceKeyFile, "device.key"},
				} {
					if want := path.Join(root, field.suffix); field.got != want {
						t.Errorf("%s = %q, want %q", field.name, field.got, want)
					}
				}
				// On a standalone deployment an omitted openshell.pack_dir is
				// <policy_dir>/sandbox, not a folder in data_dir
				// (rel-1-0-2:GAP-0099).
				if want := path.Join(cfg.PolicyDir, config.DefaultOpenShellPackDirName); cfg.OpenShell.PackDir != want {
					t.Errorf("openshell.pack_dir = %q, want <policy_dir>/sandbox %q", cfg.OpenShell.PackDir, want)
				}
				// This check loads a Linux target even on a Windows signer;
				// its omitted policy_dir must use the Unix vendor tree.
				if tc.defaultPolicyDir && cfg.PolicyDir != "/opt/defenseclaw/share/policies" {
					t.Errorf("policy_dir = %q, want Unix vendor default", cfg.PolicyDir)
				}
			}
			cfg, raw, err := enterprisebundle.LoadConfigForPlatform(f.in.Bundle, f.in.Root, "linux")
			if err != nil {
				t.Fatal(err)
			}
			layout, err := enterprisebundle.StandardDeviceLayout("linux")
			if err != nil {
				t.Fatal(err)
			}
			checkDefaultPaths(cfg, layout.DataDir)
			signedDigest, err := f.in.Digester(context.Background(), cfg, raw, "linux", f.in.Root)
			if err != nil {
				t.Fatal(err)
			}
			in := f.input(t, f.bundle, a)
			in.Digester = func(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
				checkDefaultPaths(cfg, layout.DataDir)
				got, err := f.in.Digester(ctx, cfg, raw, goos, root)
				if got != signedDigest {
					t.Errorf("signed %s, verified %s", signedDigest, got)
				}
				return got, err
			}
			res, err := enterprisebundle.Verify(context.Background(), in)
			if err != nil || !res.DigestVerified {
				t.Fatalf("signed bundle did not verify after staging elsewhere: digest=%s expected=%s: %v", res.EffectivePolicyDigest, res.ExpectedDigest, err)
			}
		})
	}
	t.Run("Windows policy_dir omitted", func(t *testing.T) {
		// Windows Setup ships no Rego bundle under the writable data_dir.
		// An omitted policy_dir therefore uses the built-in policy.
		start, end := strings.Index(base, "guardrail:\n"), strings.Index(base, "asset_policy:\n")
		root, bundle := writeBundle(t, base[:start]+base[end:])
		cfg, _, err := enterprisebundle.LoadConfigForPlatform(bundle, root, "windows")
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PolicyDir != "" {
			t.Fatalf("Windows policy_dir = %q, want built-in policy", cfg.PolicyDir)
		}
	})
}

// These settings pass the runtime loader used by the signer, but standalone
// ensure refuses them as config_invalid before installing a bundle.
func TestBundleManagedConfigRefusals(t *testing.T) {
	base := bundleConfig(t)
	for _, tc := range []struct {
		name, platform, config, key, allowed string
	}{
		{"empty policy_dir", "linux", strings.Replace(base, "policy_dir: ", "policy_dir: \"\" # ", 1), "policy_dir", ""},
		{"wrong Linux data_dir", "linux", base + "data_dir: /var/lib/defenseclaw-enterprise\n", "data_dir", "/var/lib/defenseclaw"},
		{"wrong macOS data_dir", "darwin", base + "data_dir: /var/lib/defenseclaw-enterprise\n", "data_dir", "/opt/cisco/defenseclaw/runtime"},
		{"explicit Windows data_dir", "windows", base + "data_dir: D:/Other/runtime\n", "data_dir", "standard managed runtime"},
		{"nonloopback api_bind", "linux", base + "gateway:\n  api_bind: 0.0.0.0\n", "gateway.api_bind", ""},
		{"wrong api_port", "linux", base + "gateway:\n  api_port: 18971\n", "gateway.api_port", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, b := writeBundle(t, tc.config)
			const pack = "policies/guardrail/default/rules/local-patterns.yaml"
			packData := []byte("version: 1\ninjection: []\n")
			b.Files[pack] = packData
			packPath := filepath.Join(root, filepath.FromSlash(pack))
			if err := os.MkdirAll(filepath.Dir(packPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(packPath, packData, 0o644); err != nil {
				t.Fatal(err)
			}
			in := enterprisebundle.ComposeInput{
				Bundle: b, Root: root, BundleID: tamperBundleID, TenantID: "acme", DeviceGroup: "eng", Version: 5,
				Platforms: []string{tc.platform}, CreatedAt: signedAt, CreatedBy: "operator:alice",
				ProductVersion: "1.0.2", HostPlatform: runtime.GOOS, Digester: digester,
			}
			if _, _, err := enterprisebundle.Compose(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), tc.allowed) {
				t.Fatalf("sign: got %v, want config_invalid naming %s and allowed value %s", err, tc.key, tc.allowed)
			}

			// Sign a manifest with matching file hashes to exercise verify's
			// config validation rather than its signature or file checks.
			valid := newFixture(t, base, func(in *enterprisebundle.ComposeInput) {
				in.Bundle.Files[pack] = packData
				full := filepath.Join(in.Root, filepath.FromSlash(pack))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, packData, 0o644); err != nil {
					t.Fatal(err)
				}
			})
			modified := valid.signed(t, valid.raw)
			modified.Files[enterprisebundle.ConfigName] = []byte(tc.config)
			m, err := enterprisebundle.DecodeManifest(valid.raw)
			if err != nil {
				t.Fatal(err)
			}
			for i := range m.Files {
				if m.Files[i].Path == enterprisebundle.ConfigName {
					sum := sha256.Sum256(modified.Files[enterprisebundle.ConfigName])
					m.Files[i].SHA256 = hex.EncodeToString(sum[:])
					m.Files[i].Size = int64(len(modified.Files[enterprisebundle.ConfigName]))
				}
			}
			manifest, err := m.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			modified = valid.signed(t, manifest)
			modified.Files[enterprisebundle.ConfigName] = []byte(tc.config)
			a := anchors(t, "acme", nil, 0, activeKey("k1", valid.key.Public()))
			verify := valid.input(t, modified, a)
			verify.Platform = tc.platform
			if _, err := enterprisebundle.Verify(context.Background(), verify); enterprisebundle.CodeOf(err) != enterprisebundle.CodeConfigInvalid || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), tc.allowed) {
				t.Fatalf("verify: got %v, want config_invalid naming %s and allowed value %s", err, tc.key, tc.allowed)
			}
		})
	}
}

// A required credential the device lacks keeps the bundle out
// (secret_ref_missing); an unreadable store only warns.
func TestVerifySecretPresence(t *testing.T) {
	cfg := strings.Replace(bundleConfig(t), "  profile: standalone\n", "  profile: standalone\n  inspection:\n    ai_defense:\n      credential: ai-defense-api-key\n", 1)
	f := newFixture(t, cfg, bindValues("ai-defense-api-key"))
	m, _ := enterprisebundle.DecodeManifest(f.raw)
	if len(m.SecretRefs) != 1 || m.SecretRefs[0].Ref != "secret://ai-defense-api-key" || !m.SecretRefs[0].Required ||
		m.SecretRefs[0].ValueSHA256 != enterprisebundle.CredentialValueSHA256("acme", "ai-defense-api-key", testSecretValue("ai-defense-api-key")) {
		t.Fatalf("sign did not record the bound reference: %+v", m.SecretRefs)
	}
	a := anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public()))
	in := f.input(t, f.bundle, a)
	in.SecretValue = func(string) ([]byte, error) { return nil, nil }
	if _, err := enterprisebundle.Verify(context.Background(), in); enterprisebundle.CodeOf(err) != enterprisebundle.CodeSecretRefMissing {
		t.Fatalf("missing credential: %v", err)
	}
	in.SecretValue = func(string) ([]byte, error) { return nil, os.ErrPermission }
	res, err := enterprisebundle.Verify(context.Background(), in)
	if err != nil || res.Warnings[0].Code != enterprisebundle.WarnSecretPresenceUnchecked {
		t.Fatalf("unreadable store: %+v %v", res, err)
	}
}
