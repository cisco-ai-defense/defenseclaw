// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/spf13/cobra"
)

var updateBundleGoldens = flag.Bool("update-bundle-goldens", false, "rewrite testdata/enterprise_bundle/*.golden.json")

const bundleTestConfig = `config_version: 9
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
guardrail:
  enabled: true
  mode: observe
ai_discovery:
  enabled: true
  signature_packs:
    - discovery/signature-packs/team.json
  confidence_policy_path: discovery/confidence.yaml
`

type bundleCLIEnv struct {
	dir, in, anchors string
	edKey            ed25519.PrivateKey
	secretFiles      []string
}

func newBundleCLIEnv(t *testing.T) *bundleCLIEnv {
	t.Helper()
	// The test runs in its package folder; a source path compiled into a
	// cross-built test binary does not exist on the host that runs it.
	policies, err := filepath.Abs(filepath.Join("..", "..", "policies"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(policies, "guardrail", "default")); err != nil {
		t.Skipf("policies not found: %v", err)
	}
	savedNow, savedEntropy, savedDevice, savedSC, savedVersion, savedPrivilege := bundleNow, bundleIDEntropy, bundleManagedDevice, bundleSecureClient, appVersion, bundlePrivilege
	t.Cleanup(func() {
		bundleNow, bundleIDEntropy, bundleManagedDevice, bundleSecureClient, appVersion = savedNow, savedEntropy, savedDevice, savedSC, savedVersion
		bundlePrivilege = savedPrivilege
	})
	bundleNow = func() time.Time { return time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) }
	bundleManagedDevice = func() bool { return false }
	bundleSecureClient = func() bool { return false }
	appVersion = "1.0.2"

	dir := t.TempDir()
	env := &bundleCLIEnv{dir: dir, in: filepath.Join(dir, "policy"), anchors: filepath.Join(dir, "anchors.json")}
	for name, body := range map[string]string{
		"config.yaml":                         bundleTestConfig + fmt.Sprintf("policy_dir: %q\n", policies),
		"discovery/signature-packs/team.json": `{"version":1}`,
		"discovery/confidence.yaml":           "version: 1\n",
	} {
		full := filepath.Join(env.in, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	env.edKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	der, _ := x509.MarshalPKCS8PrivateKey(env.edKey)
	writeBundleTestFile(t, filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	return env
}

func writeBundleTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *bundleCLIEnv) writeAnchors(t *testing.T, keys map[string]any) {
	t.Helper()
	var parts []string
	for id, public := range keys {
		spki, _ := x509.MarshalPKIXPublicKey(public)
		alg, _ := enterprisebundle.KeyAlg(public)
		parts = append(parts, fmt.Sprintf(`{"key_id":%q,"alg":%q,"public_key":%q,"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","status":"active"}`,
			id, alg, base64.StdEncoding.EncodeToString(spki)))
	}
	writeBundleTestFile(t, e.anchors, []byte(`{"schema_version":1,"tenant_id":"acme","device_groups":["eng"],"min_version":0,"keys":[`+strings.Join(parts, ",")+`]}`))
}

// runBundle runs `enterprise bundle <args>` and returns stdout and the
// process exit code.
func runBundle(t *testing.T, args ...string) (string, int) {
	t.Helper()
	bundleIDEntropy = bytes.NewReader(make([]byte, 10))
	cmd := newEnterpriseBundleCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	if err == nil {
		return out.String(), 0
	}
	return out.String(), commandExitCode(err)
}

func (e *bundleCLIEnv) signArgs(extra ...string) []string {
	return append([]string{"sign", "--in", e.in, "--tenant", "acme", "--device-group", "eng", "--version", "5",
		"--created-by", "operator:alice", "--summary", "First bundle", "--json"}, extra...)
}

func TestBundleSignRejectsUnknownConfigSetting(t *testing.T) {
	e := newBundleCLIEnv(t)
	path := filepath.Join(e.in, "config.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte("  mode: observe\n"), []byte("  mode: observe\n  rules:\n    definitions: policies/guardrail/missing\n"), 1)
	writeBundleTestFile(t, path, raw)
	out, code := runBundle(t, e.signArgs("--out", filepath.Join(e.dir, "invalid.dcbundle"), "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...)
	if code == 0 || !strings.Contains(out, "config_invalid") || !strings.Contains(out, "guardrail.rules.definitions") {
		t.Fatalf("sign accepted an unknown setting: exit=%d\n%s", code, out)
	}
}

// normalizeBundleJSON drops what differs per run or per policy content:
// temp paths, digests and hashes.
func normalizeBundleJSON(t *testing.T, raw, tmp string) []byte {
	t.Helper()
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, raw)
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				switch k {
				case "manifest_sha256", "to_be_signed_sha256", "to_be_signed_sha256_base64":
					x[k] = "<hash>"
				case "computed_on":
					x[k] = "<host>"
				default:
					x[k] = walk(val)
				}
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case string:
			if strings.HasPrefix(x, "sha256:") {
				return "sha256:<digest>"
			}
			if strings.Contains(x, tmp) {
				x = filepath.ToSlash(strings.ReplaceAll(x, tmp, "<tmp>"))
			}
			if i := strings.Index(x, "this host computes sha256:"); i >= 0 {
				x = x[:i] + "this host computes sha256:<digest>"
			}
			return x
		}
		return v
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(walk(doc)); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func checkBundleGolden(t *testing.T, name, raw, tmp string) {
	t.Helper()
	got := normalizeBundleJSON(t, raw, tmp)
	path := filepath.Join("testdata", "enterprise_bundle", name+".golden.json")
	if *updateBundleGoldens {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update-bundle-goldens)", err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s differs from %s:\n%s", name, path, got)
	}
}

func TestEnterpriseBundleSignVerifyGoldens(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...)
	if code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	checkBundleGolden(t, "sign", out, e.dir)

	out, code = runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--platform", "linux", "--json")
	if code != 0 {
		t.Fatalf("verify exit %d:\n%s", code, out)
	}
	checkBundleGolden(t, "verify", out, e.dir)

	// One changed policy file: refused with its code and the failure exit
	// code, and the bundle summary still shows what was refused.
	b, err := readBundleInput(signed)
	if err != nil {
		t.Fatal(err)
	}
	b.Files["discovery/confidence.yaml"] = []byte("version: 2\n")
	tampered := filepath.Join(e.dir, "tampered.dcbundle")
	if err := writeBundleArchive(tampered, b); err != nil {
		t.Fatal(err)
	}
	out, code = runBundle(t, "verify", "--bundle", tampered, "--anchors", e.anchors, "--platform", "linux", "--json")
	if code != bundleFailureExitCode() {
		t.Fatalf("tampered verify exit %d:\n%s", code, out)
	}
	checkBundleGolden(t, "verify-refused", out, e.dir)
}

// The HSM/KMS route: emit the digest, sign it outside, attach the
// signature (DER for ECDSA, base64 text of the exact bytes for Ed25519).
func TestEnterpriseBundleEmitDigestAndAttach(t *testing.T) {
	e := newBundleCLIEnv(t)
	hsm, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e.writeAnchors(t, map[string]any{"hsm-1": &hsm.PublicKey, "k1": e.edKey.Public()})
	spki, _ := x509.MarshalPKIXPublicKey(&hsm.PublicKey)
	writeBundleTestFile(t, filepath.Join(e.dir, "hsm.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))
	edSPKI, _ := x509.MarshalPKIXPublicKey(e.edKey.Public())
	writeBundleTestFile(t, filepath.Join(e.dir, "ed.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edSPKI}))

	unsigned := filepath.Join(e.dir, "unsigned.dcbundle")
	tbs := filepath.Join(e.dir, "tbs.bin")
	out, code := runBundle(t, e.signArgs("--out", unsigned, "--emit-digest", "--tbs-out", tbs)...)
	if code != 0 {
		t.Fatalf("emit-digest exit %d:\n%s", code, out)
	}
	checkBundleGolden(t, "sign-emit-digest", out, e.dir)
	var emitted bundleSignResult
	_ = json.Unmarshal([]byte(out), &emitted)
	digest, _ := hex.DecodeString(emitted.ToBeSignedSHA256)
	message, _ := os.ReadFile(tbs)

	// An unsigned bundle never verifies.
	if out, code := runBundle(t, "verify", "--bundle", unsigned, "--anchors", e.anchors, "--json"); code == 0 || !strings.Contains(out, `"signature_invalid"`) {
		t.Fatalf("unsigned bundle verified (%d):\n%s", code, out)
	}

	der, _ := ecdsa.SignASN1(rand.Reader, hsm, digest)
	writeBundleTestFile(t, filepath.Join(e.dir, "hsm.sig"), der)
	writeBundleTestFile(t, filepath.Join(e.dir, "ed.sig"), []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(e.edKey, message))+"\n"))
	for _, tc := range []struct{ id, sig, pub string }{{"hsm-1", "hsm.sig", "hsm.pem"}, {"k1", "ed.sig", "ed.pem"}} {
		signed := filepath.Join(e.dir, tc.id+".dcbundle")
		out, code := runBundle(t, "sign", "--attach-sig", filepath.Join(e.dir, tc.sig), "--in", unsigned, "--out", signed,
			"--key-id", tc.id, "--public-key", filepath.Join(e.dir, tc.pub), "--json")
		if code != 0 || !strings.Contains(out, `"signature_attached"`) {
			t.Fatalf("attach %s exit %d:\n%s", tc.id, code, out)
		}
		if out, code := runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--platform", "linux", "--json"); code != 0 {
			t.Fatalf("verify %s exit %d:\n%s", tc.id, code, out)
		}
	}
	// A signature that does not verify with the named public key is never
	// attached.
	if out, code := runBundle(t, "sign", "--attach-sig", filepath.Join(e.dir, "hsm.sig"), "--in", unsigned, "--out", filepath.Join(e.dir, "x.dcbundle"),
		"--key-id", "k1", "--public-key", filepath.Join(e.dir, "ed.pem"), "--json"); code == 0 || !strings.Contains(out, `"signature_invalid"`) {
		t.Fatalf("mismatched signature attached (%d):\n%s", code, out)
	}
}

func TestEnterpriseBundleRefusals(t *testing.T) {
	e := newBundleCLIEnv(t)
	usage := enterprisestatus.InvalidArgsExitCode(runtime.GOOS)
	for name, args := range map[string][]string{
		"no tenant":           {"sign", "--in", e.in, "--out", filepath.Join(e.dir, "x"), "--key", "k", "--key-id", "k1", "--device-group", "eng", "--version", "1", "--created-by", "operator:a", "--json"},
		"key and emit-digest": e.signArgs("--out", filepath.Join(e.dir, "x"), "--key", "k", "--key-id", "k1", "--emit-digest"),
		"attach with tenant":  {"sign", "--attach-sig", "s", "--in", "u", "--out", "o", "--key-id", "k1", "--public-key", "p", "--tenant", "acme", "--json"},
		"verify no bundle":    {"verify", "--json"},
		"stray argument":      {"verify", "extra"},
	} {
		out, code := runBundle(t, args...)
		if code != usage {
			t.Errorf("%s: exit %d, want %d:\n%s", name, code, usage, out)
		}
	}
	// A Secure Client computer refuses every verb before reading anything.
	bundleSecureClient = func() bool { return true }
	for _, args := range [][]string{{"verify", "--bundle", "/nonexistent", "--json"}, {"apply", "--bundle", "/nonexistent", "--json"}, e.signArgs("--out", "/nonexistent/x", "--emit-digest")} {
		out, code := runBundle(t, args...)
		if code != bundleFailureExitCode() || !strings.Contains(out, `"not_supported_secure_client"`) {
			t.Errorf("%v on Secure Client: exit %d:\n%s", args[0], code, out)
		}
	}
}

// Secure Client keeps the command tree of main: the group is absent.
func TestEnterpriseBundleAbsentOnSecureClient(t *testing.T) {
	saved := secureClientHost
	t.Cleanup(func() { secureClientHost = saved })
	secureClientHost = func() bool { return true }
	root := &cobra.Command{Use: "defenseclaw-gateway"}
	enterprise := &cobra.Command{Use: "enterprise"}
	enterprise.AddCommand(newEnterpriseBundleCommand())
	root.AddCommand(enterprise)
	keepCommandTreeOfMainOnSecureClient(root)
	if len(enterprise.Commands()) != 0 {
		t.Fatalf("enterprise bundle is in the Secure Client tree")
	}
}

// GAP-0009: an account that cannot read the installed anchor file (a
// standard user on Windows) is told to run verify elevated or to pass
// --anchors, not that the anchor file is insecure; with --anchors, an
// account that cannot read the deployment record is not told that the
// device is unmanaged.
func TestEnterpriseBundleVerifyUnreadableAnchorsAndRecord(t *testing.T) {
	e := newBundleCLIEnv(t)
	e.writeAnchors(t, map[string]any{"k1": e.edKey.Public()})
	signed := filepath.Join(e.dir, "v5.dcbundle")
	if out, code := runBundle(t, e.signArgs("--out", signed, "--key", filepath.Join(e.dir, "key.pem"), "--key-id", "k1")...); code != 0 {
		t.Fatalf("sign exit %d:\n%s", code, out)
	}
	savedAnchors, savedLstat, savedUnreadable := bundleDefaultAnchors, bundleAnchorsLstat, bundleDeviceRecordUnreadable
	t.Cleanup(func() {
		bundleDefaultAnchors, bundleAnchorsLstat, bundleDeviceRecordUnreadable = savedAnchors, savedLstat, savedUnreadable
	})
	bundleDefaultAnchors = func() (string, error) { return e.anchors, nil }
	bundleAnchorsLstat = func(path string) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrPermission}
	}
	out, code := runBundle(t, "verify", "--bundle", signed, "--platform", "linux", "--json")
	if code != bundleFailureExitCode() || !strings.Contains(out, `"code": "not_admin"`) ||
		!strings.Contains(out, "--anchors") || strings.Contains(out, "anchor_insecure") {
		t.Fatalf("default anchors unreadable (exit %d):\n%s", code, out)
	}

	bundleAnchorsLstat = os.Lstat
	bundleDeviceRecordUnreadable = func() bool { return true }
	out, code = runBundle(t, "verify", "--bundle", signed, "--anchors", e.anchors, "--platform", "linux", "--json")
	if code != 0 || !strings.Contains(out, `"anchor_trust_unchecked"`) ||
		strings.Contains(out, "not a managed device") || !strings.Contains(out, "deployment record") {
		t.Fatalf("--anchors with an unreadable deployment record (exit %d):\n%s", code, out)
	}
}
