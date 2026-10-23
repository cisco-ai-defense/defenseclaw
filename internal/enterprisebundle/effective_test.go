// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A signer and an installed device must hash a bundled custom rule pack the
// same way, despite their distinct staging and version directory paths.
func TestBundleCustomGuardrailPackSignedDigestMatchesAppliedDigest(t *testing.T) {
	for _, platform := range []string{enterprisebundle.PlatformLinux, enterprisebundle.PlatformDarwin} {
		t.Run(platform, func(t *testing.T) {
			testBundleCustomGuardrailPackSignedDigestMatchesAppliedDigest(t, platform)
		})
	}
}

func testBundleCustomGuardrailPackSignedDigestMatchesAppliedDigest(t *testing.T, platform string) {
	layout, err := managed.StandaloneLayoutFor(platform)
	if err != nil {
		t.Fatal(err)
	}
	const pack = "policies/guardrail/custom/rules/local-patterns.yaml"
	const rules = "version: 1\ninjection: []\n"
	packRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(packRoot, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "rules/local-patterns.yaml"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	packDigest, err := guardrail.RulePackDigest(packRoot)
	if err != nil {
		t.Fatal(err)
	}
	configYAML := strings.Replace(bundleConfigBase+fmt.Sprintf("data_dir: %q\npolicy_dir: %q\n", layout.DataDir, filepath.Join(t.TempDir(), "absent-policies")), "guardrail:\n", "guardrail:\n  rule_pack: custom\n  custom_packs:\n    custom:\n      path: policies/guardrail/custom\n      digest: sha256:"+packDigest+"\n", 1)
	f := newFixture(t, configYAML, func(in *enterprisebundle.ComposeInput) {
		in.HostPlatform = platform
		in.Platforms = []string{platform}
		in.Bundle.Files[pack] = []byte(rules)
		full := filepath.Join(in.Root, filepath.FromSlash(pack))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(rules), 0o644); err != nil {
			t.Fatal(err)
		}
	})
	spki, err := x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal(err)
	}
	anchorsRaw, err := json.Marshal(enterprisebundle.Anchors{SchemaVersion: 1, TenantID: "acme", DeviceGroups: []string{"eng"}, Keys: []enterprisebundle.AnchorKey{{
		KeyID: "k1", Alg: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(spki), Status: enterprisebundle.KeyActive,
		NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	anchorsPath := filepath.Join(root, "trust", enterprisebundle.AnchorsName)
	if err := os.MkdirAll(filepath.Dir(anchorsPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorsPath, anchorsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	store := enterprisebundle.NewStore(filepath.Join(root, "bundles"), filepath.Join(root, "lifecycle"))
	t.Cleanup(func() {
		_ = filepath.WalkDir(store.BundlesDir, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	driver := &enterprisebundle.Driver{Store: store, ConfigPath: filepath.Join(root, "config.yaml"), AnchorsPath: anchorsPath, Platform: platform, ProductVersion: "1.0.2", Digester: digester, Now: func() time.Time { return verifyAt }}
	prepared, err := driver.Prepare(context.Background(), f.bundle, nil)
	if err != nil {
		t.Fatal(err)
	}
	versionRoot := store.VersionDir(prepared.Receipt.Dir)
	installedBundle, err := enterprisebundle.ReadDir(versionRoot)
	if err != nil {
		t.Fatal(err)
	}
	installedRaw, err := enterprisebundle.RenderConfig(installedBundle, versionRoot)
	if err != nil {
		t.Fatal(err)
	}
	// Model the target layout even when this test runs on another OS.
	t.Setenv(managed.ConfigPathEnv, layout.ConfigPath)
	t.Setenv("DEFENSECLAW_HOME", layout.DataDir)
	installedConfig, err := config.LoadRuntimeV8InspectionCandidateForLayout(layout.ConfigPath, installedRaw, layout.DataDir, platform)
	if err != nil {
		t.Fatal(err)
	}
	deviceDigest, err := digester(context.Background(), installedConfig, installedRaw, platform, versionRoot)
	if err != nil {
		t.Fatal(err)
	}
	policy := installPreparedBundle(t, driver, prepared)
	policy.EffectiveDigest, policy.Digest = deviceDigest, deviceDigest
	if _, err := driver.Finish(prepared, prepared.ConfigSHA256, nil, policy, false, nil); err != nil {
		t.Fatal(err)
	}
	if rc := prepared.Receipt; rc.State != enterprisebundle.StateConfirmed || rc.ExpectedDigest != deviceDigest || rc.EffectivePolicyDigest != deviceDigest {
		t.Fatalf("signed expected %s, device computed %s, receipt %+v", rc.ExpectedDigest, deviceDigest, rc)
	}
}

const bundleConfigBase = `config_version: 9
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
  tetragon:
    mode: observe
guardrail:
  enabled: true
  mode: observe
ai_discovery:
  enabled: true
  signature_packs:
    - discovery/signature-packs/team.json
  confidence_policy_path: discovery/confidence.yaml
  runtime:
    enabled: true
    enable_host_plane: true
`

// bundleConfig is the test bundle config with policy_dir at this checkout's
// built-in packs (a device has them in its install; the bundle does not
// carry them).
func bundleConfig(t *testing.T) string {
	t.Helper()
	// The test runs in its package folder; a source path compiled into a
	// cross-built test binary does not exist on the host that runs it.
	dir, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "guardrail", "default")); err != nil {
		t.Skipf("policies not found: %v", err)
	}
	return bundleConfigBase + fmt.Sprintf("policy_dir: %q\n", dir)
}

// writeBundle writes the test bundle under a new directory and reads it.
func writeBundle(t *testing.T, configYAML string) (string, *enterprisebundle.Bundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "bundle")
	for name, body := range map[string]string{
		"config.yaml":                         configYAML,
		"discovery/signature-packs/team.json": `{"version":1}`,
		"discovery/confidence.yaml":           "version: 1\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := enterprisebundle.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	return root, b
}

func digester(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
	policy, err := gateway.ComputeEffectivePolicyFor(ctx, cfg, gateway.EffectivePolicyOptions{GOOS: goos, BundleRoot: root, Raw: raw})
	return policy.Digest, err
}

// The same bundle digests the same wherever it is unpacked: the signer's
// working copy and the versioned directory a device installs it to give one
// digest per platform, and the platforms differ where their policy does (the
// kernel control set is Linux only).
func TestEffectivePolicyDigestsIgnoreTheBundleRoot(t *testing.T) {
	ctx := context.Background()
	signerRoot, signer := writeBundle(t, bundleConfig(t))
	deviceRoot, device := writeBundle(t, bundleConfig(t))
	if signerRoot == deviceRoot {
		t.Fatal("test needs two roots")
	}
	platforms := enterprisebundle.Platforms
	signed, err := enterprisebundle.EffectivePolicyDigests(ctx, signer, signerRoot, platforms, digester)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := enterprisebundle.EffectivePolicyDigests(ctx, device, deviceRoot, platforms, digester)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range platforms {
		if signed[platform] == "" || signed[platform] != installed[platform] {
			t.Fatalf("%s: signer %s, device %s", platform, signed[platform], installed[platform])
		}
	}
	if signed["linux"] == signed["darwin"] {
		t.Fatalf("platform digests %v: want linux to differ (kernel policy)", signed)
	}

	// An edited policy file moves the digest of every platform.
	if err := os.WriteFile(filepath.Join(deviceRoot, "discovery", "signature-packs", "team.json"), []byte(`{"version":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	edited, err := enterprisebundle.ReadDir(deviceRoot)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := enterprisebundle.EffectivePolicyDigests(ctx, edited, deviceRoot, platforms, digester)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range platforms {
		if moved[platform] == signed[platform] {
			t.Fatalf("%s: an edited signature pack kept the digest", platform)
		}
	}
}

func TestLinuxBundleDigestIgnoresWindowsStyleStageRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a Windows-style relative path is simulated on a Unix host")
	}
	posixRoot, bundle := writeBundle(t, bundleConfigBase)
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(workingDir) })
	windowsRoot := `C:\Users\x\AppData\Local\Temp\bundle-stage`
	for name, body := range bundle.Files {
		file := path.Join(windowsRoot, name)
		if err := os.MkdirAll(path.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	compute := func(root string) string {
		t.Helper()
		got, err := enterprisebundle.EffectivePolicyDigests(context.Background(), bundle, root, []string{"linux"}, digester)
		if err != nil {
			t.Fatal(err)
		}
		return got["linux"]
	}
	if posix, windows := compute(posixRoot), compute(windowsRoot); posix != windows {
		t.Fatalf("Linux target digest changed with stage root: POSIX %s, Windows-style %s", posix, windows)
	}
}

func TestBundleDigestIgnoresSignerHomeEnvironmentAndWorkingDirectory(t *testing.T) {
	root, bundle := writeBundle(t, bundleConfig(t))
	compute := func() string {
		t.Helper()
		got, err := enterprisebundle.EffectivePolicyDigests(context.Background(), bundle, root, []string{"linux"}, digester)
		if err != nil {
			t.Fatal(err)
		}
		return got["linux"]
	}
	baseline := compute()
	before, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(before) })
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	t.Setenv("DEFENSECLAW_LLM_MODEL", "host-only-model")
	t.Setenv(managed.ConfigPathEnv, "/tmp/host-only-config.yaml")
	t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")
	t.Setenv(managed.EnterpriseProfileEnv, "standalone")
	if got := compute(); got != baseline {
		t.Fatalf("host environment or cwd changed bundle digest: %s != %s", got, baseline)
	}
}

func TestOfflineSignerUsesEmbeddedVendorPackWithoutInstall(t *testing.T) {
	root, bundle := writeBundle(t, bundleConfigBase)
	compute := func() string {
		t.Helper()
		got, err := enterprisebundle.EffectivePolicyDigests(context.Background(), bundle, root, []string{"linux"}, digester)
		if err != nil {
			t.Fatal(err)
		}
		return got["linux"]
	}
	first := compute()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	if second := compute(); first != second {
		t.Fatalf("vendor pack digest changed with host: %s != %s", first, second)
	}
}

func TestSignedComponentsNameTheDeviceMismatch(t *testing.T) {
	const signed = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const device = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	f := newFixture(t, bundleConfig(t), func(in *enterprisebundle.ComposeInput) {
		in.Platforms = []string{"linux"}
		in.Digester = func(ctx context.Context, _ *config.Config, _ []byte, _, _ string) (string, error) {
			enterprisebundle.ReportPolicyComponents(ctx, map[string]string{"config": signed, "kernel_policy": "sha256:0123456789ab"})
			return signed, nil
		}
	})
	m, err := enterprisebundle.DecodeManifest(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.EffectivePolicy.Components["linux"]; len(got) != 2 || got[0].Name != "config" || got[0].Digest != signed {
		t.Fatalf("signed components = %+v", got)
	}
	in := f.input(t, f.bundle, anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public())))
	in.Digester = func(ctx context.Context, _ *config.Config, _ []byte, _, _ string) (string, error) {
		enterprisebundle.ReportPolicyComponents(ctx, map[string]string{"config": device, "kernel_policy": "sha256:0123456789ab"})
		return device, nil
	}
	_, err = enterprisebundle.Verify(context.Background(), in)
	if err == nil || !strings.Contains(err.Error(), "component config differs") {
		t.Fatalf("device mismatch = %v, want config component", err)
	}
}

// Signing and device verification must load path defaults from the same
// installed layout while bundle assets live under independent temporary roots.
func TestBundleDeviceLayoutDigestParity(t *testing.T) {
	const pack = "policies/guardrail/custom/rules/local-patterns.yaml"
	const rules = "version: 1\ninjection: []\n"
	packRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(packRoot, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packRoot, "rules/local-patterns.yaml"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	pin, err := guardrail.RulePackDigest(packRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range enterprisebundle.Platforms {
		layout, err := enterprisebundle.StandardDeviceLayout(platform)
		if err != nil {
			t.Fatal(err)
		}
		for _, shape := range []struct {
			name, policyDir, dataDir string
		}{
			{"explicit policy_dir", layout.PolicyDir, layout.DataDir},
			{"omitted policy_dir", "", layout.DataDir},
			{"omitted data_dir", layout.PolicyDir, ""},
			{"both omitted", "", ""},
		} {
			t.Run(platform+"/"+shape.name, func(t *testing.T) {
				configYAML := strings.Replace(bundleConfigBase, "guardrail:\n", "guardrail:\n  rule_pack: custom\n  custom_packs:\n    custom:\n      path: policies/guardrail/custom\n      digest: sha256:"+pin+"\n", 1)
				if shape.policyDir != "" {
					configYAML += fmt.Sprintf("policy_dir: %q\n", shape.policyDir)
				}
				if shape.dataDir != "" {
					configYAML += fmt.Sprintf("data_dir: %q\n", shape.dataDir)
				}
				f := newFixture(t, configYAML, func(in *enterprisebundle.ComposeInput) {
					in.Platforms = []string{platform}
					in.Bundle.Files[pack] = []byte(rules)
					full := filepath.Join(in.Root, filepath.FromSlash(pack))
					if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(full, []byte(rules), 0o644); err != nil {
						t.Fatal(err)
					}
				})
				in := f.input(t, f.bundle, anchors(t, "acme", nil, 0, activeKey("k1", f.key.Public())))
				in.Platform, in.DeviceLayout = platform, &layout
				res, err := enterprisebundle.Verify(context.Background(), in)
				if err != nil || !res.DigestVerified || res.ExpectedDigest != res.EffectivePolicyDigest {
					t.Fatalf("signed %s, device %s, verified %v: %v", res.ExpectedDigest, res.EffectivePolicyDigest, res.DigestVerified, err)
				}
				if platform == enterprisebundle.PlatformWindows && shape.name == "omitted data_dir" {
					forward := enterprisebundle.DeviceLayout{
						ConfigPath: strings.ReplaceAll(layout.ConfigPath, `\`, "/"),
						DataDir:    strings.ReplaceAll(layout.DataDir, `\`, "/"),
						PolicyDir:  strings.ReplaceAll(layout.PolicyDir, `\`, "/"),
					}
					in.DeviceLayout = &forward
					separators, err := enterprisebundle.Verify(context.Background(), in)
					if err != nil || !separators.DigestVerified || separators.EffectivePolicyDigest != res.ExpectedDigest {
						t.Fatalf("Windows drive path separators: %+v, %v", separators, err)
					}
					other := enterprisebundle.DeviceLayout{
						ConfigPath: strings.Replace(layout.ConfigPath, `C:\`, `D:\`, 1),
						DataDir:    strings.Replace(layout.DataDir, `C:\`, `D:\`, 1),
						PolicyDir:  strings.Replace(layout.PolicyDir, `C:\`, `D:\`, 1),
					}
					in.DeviceLayout = &other
					equal, err := enterprisebundle.Verify(context.Background(), in)
					if err != nil || !equal.DigestVerified || equal.DigestUnverifiable || equal.EffectivePolicyDigest != equal.ExpectedDigest {
						t.Fatalf("matching digest on non-standard ProgramData layout: %+v, %v", equal, err)
					}
					// A digest the D: layout changes, whose standard-layout
					// digest is the signed one: layout-unverifiable.
					layoutSensitive := in
					layoutSensitive.Digester = onDriveD(gatewayDigest)
					unverifiable, err := enterprisebundle.Verify(context.Background(), layoutSensitive)
					if err != nil || unverifiable.DigestVerified || unverifiable.DigestUnverifiable || !unverifiable.DigestLayoutUnverifiable {
						t.Fatalf("different digest on non-standard ProgramData layout: %+v, %v", unverifiable, err)
					}
					found := false
					for _, warning := range unverifiable.Warnings {
						found = found || warning.Code == enterprisebundle.WarnDigestLayoutUnverifiable
					}
					if !found {
						t.Fatalf("non-standard layout warnings: %+v", unverifiable.Warnings)
					}
				}
				// A config byte that changes the effective policy must change
				// the digest even when the bundle assets are unchanged.
				edited := &enterprisebundle.Bundle{Files: map[string][]byte{}}
				for name, body := range f.in.Bundle.Files {
					edited.Files[name] = body
				}
				edited.Files[enterprisebundle.ConfigName] = []byte(strings.Replace(configYAML, "  mode: observe\nai_discovery:", "  mode: action\nai_discovery:", 1))
				changed, err := enterprisebundle.EffectivePolicyDigests(context.Background(), edited, f.in.Root, []string{platform}, digester)
				if err != nil || changed[platform] == res.ExpectedDigest {
					t.Fatalf("changed config digest %v, original %s: %v", changed, res.ExpectedDigest, err)
				}
			})
		}
	}
}

// onDriveD is a digester whose result on a ProgramData relocated to D: is
// layoutDigest; on every other layout it is the real digest.
func onDriveD(layoutDigest string) enterprisebundle.PolicyDigester {
	return func(ctx context.Context, cfg *config.Config, raw []byte, goos, root string) (string, error) {
		if strings.HasPrefix(strings.ToUpper(cfg.DataDir), `D:\`) {
			return layoutDigest, nil
		}
		return digester(ctx, cfg, raw, goos, root)
	}
}

// GAP-0113 verifier finding 1: a Windows device whose ProgramData is on D:
// must still refuse a signed digest it disproves, for every signer OS. The
// device recomputes the digest for the standard layout the signer models;
// only when that digest equals the signed one does the layout difference
// downgrade to digest_layout_unverifiable.
func TestVerifyNonStandardLayoutRefusesDisprovedDigest(t *testing.T) {
	standard, err := enterprisebundle.StandardDeviceLayout(enterprisebundle.PlatformWindows)
	if err != nil {
		t.Fatal(err)
	}
	driveD := enterprisebundle.DeviceLayout{
		ConfigPath: strings.Replace(standard.ConfigPath, `C:\`, `D:\`, 1),
		DataDir:    strings.Replace(standard.DataDir, `C:\`, `D:\`, 1),
		PolicyDir:  strings.Replace(standard.PolicyDir, `C:\`, `D:\`, 1),
	}
	if driveD.IsStandard(enterprisebundle.PlatformWindows) {
		t.Fatal("D: layout treated as standard")
	}
	// An explicit standard data_dir is signable, but the D: layout still
	// supplies the defaults of the other runtime paths, so it changes the
	// real device digest (follow-up probe layout-probe.log).
	explicitDataDir := bundleConfigBase + fmt.Sprintf("data_dir: %q\n", standard.DataDir)
	for _, signer := range enterprisebundle.Platforms {
		t.Run(signer, func(t *testing.T) {
			// sign returns the consistent bundle, one re-signed with a
			// wrong windows digest, and the true digest.
			sign := func(configYAML string) (*fixture, *enterprisebundle.Bundle, *enterprisebundle.Bundle, string) {
				f := newFixture(t, configYAML, func(in *enterprisebundle.ComposeInput) {
					in.Platforms = []string{enterprisebundle.PlatformWindows}
					in.HostPlatform = signer
				})
				m, err := enterprisebundle.DecodeManifest(f.raw)
				if err != nil {
					t.Fatal(err)
				}
				actual := m.EffectivePolicy.Digests[enterprisebundle.PlatformWindows]
				flip := "0"
				if actual[7] == '0' {
					flip = "1"
				}
				m.EffectivePolicy.Digests[enterprisebundle.PlatformWindows] = actual[:7] + flip + actual[8:]
				wrong, err := m.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				return f, f.bundle, f.signed(t, wrong), actual
			}
			f, good, bad, actual := sign(bundleConfig(t))
			fd, goodD, badD, actualD := sign(explicitDataDir)
			for _, tc := range []struct {
				name     string
				f        *fixture
				bundle   *enterprisebundle.Bundle
				digester enterprisebundle.PolicyDigester
				want     string // "verified", "layout" or a refusal detail
			}{
				{"consistent", f, good, digester, "verified"},
				{"disproved", f, bad, digester, "this host computes " + actual + " for windows; the signer computed the digest on " + signer},
				{"layout changed the digest", f, good, onDriveD(gatewayDigest), "layout"},
				{"layout changed the digest, standard digest disproves", f, bad, onDriveD(gatewayDigest),
					"this host computes " + gatewayDigest + " for windows (" + actual + " for the standard managed layout)"},
				{"explicit standard data_dir", fd, goodD, digester, "layout"},
				{"explicit standard data_dir, disproved", fd, badD, digester, "(" + actualD + " for the standard managed layout); the signer computed the digest on " + signer},
			} {
				t.Run(tc.name, func(t *testing.T) {
					in := tc.f.input(t, tc.bundle, anchors(t, "acme", []string{"eng"}, 0, activeKey("k1", tc.f.key.Public())))
					in.Platform, in.DeviceLayout, in.Digester = enterprisebundle.PlatformWindows, &driveD, tc.digester
					res, err := enterprisebundle.Verify(context.Background(), in)
					switch tc.want {
					case "verified":
						if err != nil || !res.DigestVerified || res.DigestLayoutUnverifiable || res.EffectivePolicyDigest != actual {
							t.Fatalf("consistent bundle on D: = %+v, %v", res, err)
						}
					case "layout":
						if err != nil || res.DigestVerified || res.DigestUnverifiable || !res.DigestLayoutUnverifiable || res.EffectivePolicyDigest == res.ExpectedDigest {
							t.Fatalf("layout-dependent digest on D: = %+v, %v", res, err)
						}
					default:
						if enterprisebundle.CodeOf(err) != enterprisebundle.CodeDigestMismatch || res.DigestVerified || res.DigestLayoutUnverifiable ||
							!strings.Contains(err.Error(), tc.want) {
							t.Fatalf("disproved digest on D: = %+v, %v; want digest_mismatch with %q", res, err, tc.want)
						}
					}
				})
			}
		})
	}
}

// A signer computes each target platform's digest with that platform's
// defaults, never its own host's. notifications.enabled defaulted from the
// signing host: a Linux signer digested every Windows bundle with false while
// the Windows device resolves true, so no Windows receipt ever verified its
// signed digest (GAP-0107). An omitted default digests like the target's
// explicit default, and the opposite explicit value is another policy.
func TestBundleDigestUsesTargetPlatformDefaults(t *testing.T) {
	targetDefault := map[string]bool{"linux": false, "darwin": true, "windows": true}
	for _, platform := range enterprisebundle.Platforms {
		t.Run(platform, func(t *testing.T) {
			digest := func(extra string) string {
				t.Helper()
				root, bundle := writeBundle(t, bundleConfigBase+extra)
				got, err := enterprisebundle.EffectivePolicyDigests(context.Background(), bundle, root, []string{platform}, digester)
				if err != nil {
					t.Fatal(err)
				}
				return got[platform]
			}
			want := targetDefault[platform]
			omitted := digest("")
			if same := digest(fmt.Sprintf("notifications:\n  enabled: %t\n", want)); omitted != same {
				t.Fatalf("omitted notifications.enabled digests %s, the %s default (%t) digests %s", omitted, platform, want, same)
			}
			if other := digest(fmt.Sprintf("notifications:\n  enabled: %t\n", !want)); omitted == other {
				t.Fatalf("notifications.enabled %t digests like the %s default", !want, platform)
			}
		})
	}
}

func TestWindowsDeviceLayoutPathSeparators(t *testing.T) {
	standard, err := enterprisebundle.StandardDeviceLayout(enterprisebundle.PlatformWindows)
	if err != nil {
		t.Fatal(err)
	}
	forward := enterprisebundle.DeviceLayout{
		ConfigPath: strings.ReplaceAll(standard.ConfigPath, `\`, "/"),
		DataDir:    strings.ReplaceAll(standard.DataDir, `\`, "/"),
		PolicyDir:  strings.ReplaceAll(standard.PolicyDir, `\`, "/"),
	}
	if !forward.IsStandard(enterprisebundle.PlatformWindows) {
		t.Fatalf("Windows drive path with forward slashes is not standard: %+v", forward)
	}
	forward.DataDir = `D:\Other\runtime`
	if forward.IsStandard(enterprisebundle.PlatformWindows) {
		t.Fatal("different ProgramData drive treated as standard")
	}
}

// Golden: the bundle-root canonicalisation of a digest component. The
// signature pack component is sha256 over "<canonical path>=<file digest>",
// and the canonical path starts with ${bundle_root}, so this value is the
// same on every host, in every directory.
func TestEffectivePolicyComponentGolden(t *testing.T) {
	root, b := writeBundle(t, bundleConfig(t))
	cfg, raw, err := enterprisebundle.LoadConfig(b, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), filepath.Join(root, "discovery", "confidence.yaml")) {
		t.Fatalf("rendered config does not point into the bundle:\n%s", raw)
	}
	policy, err := gateway.ComputeEffectivePolicyFor(context.Background(), cfg, gateway.EffectivePolicyOptions{GOOS: "linux", BundleRoot: root, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	const key = "signature_pack:${bundle_root}/discovery/signature-packs/team.json"
	const golden = "sha256:9c216b6317e8cc15f1d63e88c6ff51c5cdeaf9bacec02391f91fc84a0a00dded"
	if got := policy.Components[key]; got != golden {
		t.Fatalf("component %s = %q, want %s (components %v)", key, got, golden, policy.Components)
	}
	if _, ok := policy.Components["kernel_policy"]; !ok {
		t.Fatalf("linux digest has no kernel_policy component: %v", policy.Components)
	}
	darwin, err := gateway.ComputeEffectivePolicyFor(context.Background(), cfg, gateway.EffectivePolicyOptions{GOOS: "darwin", BundleRoot: root, Raw: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := darwin.Components["kernel_policy"]; ok {
		t.Fatal("darwin digest has a kernel_policy component")
	}
	for key := range policy.Components {
		if strings.Contains(key, root) {
			t.Fatalf("component key %s holds the bundle root", key)
		}
	}
}

func TestRenderConfig(t *testing.T) {
	root, b := writeBundle(t, bundleConfig(t))
	b.Files["config.yaml"] = []byte(bundleConfig(t) + "x:\n  glob: discovery/signature-packs/*.json\n  other: policies-not-a-bundle-path\n")
	raw, err := enterprisebundle.RenderConfig(b, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		filepath.Join(root, "discovery", "signature-packs", "team.json"),
		filepath.Join(root, "discovery", "signature-packs", "*.json"),
		"policies-not-a-bundle-path",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("rendered config lacks %s:\n%s", want, raw)
		}
	}
	for name, extra := range map[string]string{
		"missing file":   "x: policies/guardrail/absent\n",
		"traversal":      "x: discovery/../../etc/passwd\n",
		"pattern in dir": "x: discovery/*/team.json\n",
	} {
		t.Run(name, func(t *testing.T) {
			b.Files["config.yaml"] = []byte(bundleConfig(t) + extra)
			_, err := enterprisebundle.RenderConfig(b, root)
			if code := enterprisebundle.CodeOf(err); code != enterprisebundle.CodeFileMissing && code != enterprisebundle.CodeConfigInvalid {
				t.Fatalf("got %v, want file_missing or config_invalid", err)
			}
		})
	}
}

// A standard user on a managed device cannot open the service data_dir (0700,
// owned by the service account). Offline sign and verify run as any account,
// so they check the target's audit.db path by name there, as they do on a
// computer without that folder; the gateway's own load still refuses a path
// it cannot inspect (sidecar F02).
func TestOfflineBundleLoadToleratesUnreadableDataDir(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a POSIX account that a mode 0 folder denies")
	}
	base := t.TempDir()
	dataDir := filepath.Join(base, "runtime")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "audit.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })
	root, b := writeBundle(t, bundleConfig(t))
	layout := enterprisebundle.DeviceLayout{ConfigPath: filepath.Join(base, "etc", "config.yaml"), DataDir: dataDir, PolicyDir: filepath.Join(base, "policies")}
	if _, _, err := enterprisebundle.LoadConfigForDeviceLayout(b, root, runtime.GOOS, layout); err != nil {
		t.Fatalf("offline load as a standard user: %v", err)
	}
	_, err := config.ParseCompileObservabilityV8(layout.ConfigPath, b.Files[enterprisebundle.ConfigName], config.ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the gateway compile must still refuse an uninspectable audit.db: %v", err)
	}
}
