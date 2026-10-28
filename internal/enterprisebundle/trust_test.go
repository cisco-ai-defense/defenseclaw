// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Known-answer vectors computed with an independent implementation (Python
// cryptography 50): the RFC 8032 test 1 Ed25519 key and the RFC 6979 A.2.5
// P-256 key over the domain prefix and katManifest.
const (
	katManifest  = "{\"schema_version\":1}\n"
	katTBSSHA256 = "04c245c9fd895de4578dc28d37b4ea8adbafb2cfe8578c015d4878d5b91fcf93"
	katEdSeed    = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	katEdPublic  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	katEdSig     = "df2174905e07ee16795ab15437e00bc1ab3be854d5fee4410cd3031ca879fb3e1839a57d56738a3ce86d09657b09ea42914dbdf7c729bc7a4f6a9262d1e14c0b"
	katECSPKI    = "3059301306072a8648ce3d020106082a8648ce3d0301070342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
	katECSig     = "30450220385ee8fb308145f2327432d5e792d154430083b79e516fa7360afea90b2540a30221009cb001641ddbedf093b15758b47d47155da27ef3b624892ee0848a56971331c2"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignatureKnownAnswers(t *testing.T) {
	manifest := []byte(katManifest)
	if got := SignedDigest(manifest); hex.EncodeToString(got[:]) != katTBSSHA256 {
		t.Fatalf("to-be-signed digest %x", got)
	}
	edKey := ed25519.NewKeyFromSeed(unhex(t, katEdSeed))
	if hex.EncodeToString(edKey.Public().(ed25519.PublicKey)) != katEdPublic {
		t.Fatal("RFC 8032 public key")
	}
	sig, err := Sign(manifest, edKey, "kat-ed")
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(sig.Sig); hex.EncodeToString(raw) != katEdSig || sig.Alg != AlgEd25519 {
		t.Fatalf("ed25519 signature %s %s", sig.Alg, sig.Sig)
	}
	if err := VerifySignature(manifest, sig, edKey.Public()); err != nil {
		t.Fatal(err)
	}
	ecPub, alg, err := ParsePublicKey(unhex(t, katECSPKI))
	if err != nil || alg != AlgECDSAP256SHA256 {
		t.Fatalf("P-256 key: %v %s", err, alg)
	}
	ecSig, err := AttachSignature(manifest, ecPub, "kat-ec", unhex(t, katECSig))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(manifest, ecSig, ecPub); err != nil {
		t.Fatal(err)
	}
	// The signature covers the domain prefix: the same key over the bare
	// manifest, or over another prefix, never verifies.
	for _, msg := range [][]byte{manifest, append([]byte("defenseclaw-bundle-manifest-v2\x00"), manifest...)} {
		bare := &Signature{SchemaVersion: 1, KeyID: "kat-ed", Alg: AlgEd25519, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(edKey, msg))}
		wantCode(t, VerifySignature(manifest, bare, edKey.Public()), CodeSignatureInvalid)
	}
}

func TestAttachSignatureAcceptsRawECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	manifest := []byte(katManifest)
	digest := SignedDigest(manifest)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	sig, err := AttachSignature(manifest, &key.PublicKey, "hsm-1", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(manifest, sig, &key.PublicKey); err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := AttachSignature(manifest, &other.PublicKey, "hsm-1", raw); CodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("a signature of another key attached: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := Sign(manifest, p384, "p384"); err == nil {
		t.Fatal("a P-384 key signed")
	}
}

func TestDecodeSignatureRefuses(t *testing.T) {
	good := `{"schema_version":1,"key_id":"k1","alg":"ed25519","sig":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`
	if _, err := DecodeSignature([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"empty":           "",
		"unknown key":     strings.Replace(good, `"alg"`, `"extra":1,"alg"`, 1),
		"repeated key":    strings.Replace(good, `"alg"`, `"key_id":"k2","alg"`, 1),
		"upper-case key":  strings.Replace(good, `"alg"`, `"Alg"`, 1),
		"trailing data":   good + "{}",
		"schema":          strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"alg":             strings.Replace(good, `"ed25519"`, `"rsa"`, 1),
		"short ed25519":   `{"schema_version":1,"key_id":"k1","alg":"ed25519","sig":"AAAA"}`,
		"ecdsa not DER":   strings.Replace(good, `"ed25519"`, `"ecdsa-p256-sha256"`, 1),
		"bad key id":      strings.Replace(good, `"k1"`, `"../k"`, 1),
		"not base64":      strings.Replace(good, `"sig":"`, `"sig":"*`, 1),
		"byte-order mark": "\xef\xbb\xbf" + good,
	} {
		if _, err := DecodeSignature([]byte(raw)); CodeOf(err) != CodeSignatureInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A DER signature has one spelling: a trailing byte or a non-minimal
	// integer is not that signature.
	der := unhex(t, katECSig)
	for _, bad := range [][]byte{append(append([]byte{}, der...), 0), append([]byte{0x30, 0x46, 0x02, 0x21, 0x00}, der[4:]...)} {
		if validDERSignature(bad) {
			t.Errorf("accepted %x", bad)
		}
	}
}

type anchorKeyJSON struct {
	id, alg, status, notBefore, notAfter string
	public                               []byte
}

func anchorsJSON(tenant string, groups []string, minVersion uint64, keys ...anchorKeyJSON) string {
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(`{"key_id":%q,"alg":%q,"public_key":%q,"not_before":%q,"not_after":%q,"status":%q}`,
			k.id, k.alg, base64.StdEncoding.EncodeToString(k.public), k.notBefore, k.notAfter, k.status))
	}
	quoted := make([]string, len(groups))
	for i, g := range groups {
		quoted[i] = fmt.Sprintf("%q", g)
	}
	return fmt.Sprintf(`{"schema_version":1,"tenant_id":%q,"device_groups":[%s],"min_version":%d,"keys":[%s]}`,
		tenant, strings.Join(quoted, ","), minVersion, strings.Join(parts, ","))
}

func edAnchorKey(t *testing.T) anchorKeyJSON {
	spki, err := x509.MarshalPKIXPublicKey(ed25519.NewKeyFromSeed(unhex(t, katEdSeed)).Public())
	if err != nil {
		t.Fatal(err)
	}
	return anchorKeyJSON{id: "k1", alg: AlgEd25519, status: KeyActive, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", public: spki}
}

func TestDecodeAnchors(t *testing.T) {
	key := edAnchorKey(t)
	good := anchorsJSON("acme", []string{"eng"}, 3, key)
	a, err := DecodeAnchors([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	k := a.Key("k1")
	if k == nil || k.Public() == nil || !k.ValidAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) || k.ValidAt(time.Date(2027, 1, 1, 0, 0, 1, 0, time.UTC)) {
		t.Fatalf("key %+v", k)
	}
	if !a.AllowsDeviceGroup("eng") || a.AllowsDeviceGroup("ops") {
		t.Fatal("device groups")
	}
	ecSPKI := unhex(t, katECSPKI)
	mislabelled := key
	mislabelled.public = ecSPKI
	inverted := key
	inverted.notAfter = key.notBefore
	notUTC := key
	notUTC.notBefore = "2026-01-01T00:00:00+01:00"
	badStatus := key
	badStatus.status = "paused"
	for name, raw := range map[string]string{
		"no keys":        anchorsJSON("acme", nil, 0),
		"duplicate key":  anchorsJSON("acme", nil, 0, key, key),
		"duplicate grp":  anchorsJSON("acme", []string{"eng", "eng"}, 0, key),
		"alg mismatch":   anchorsJSON("acme", nil, 0, mislabelled),
		"inverted":       anchorsJSON("acme", nil, 0, inverted),
		"not UTC":        anchorsJSON("acme", nil, 0, notUTC),
		"status":         anchorsJSON("acme", nil, 0, badStatus),
		"tenant":         anchorsJSON("a/b", nil, 0, key),
		"min_version":    anchorsJSON("acme", nil, MaxVersion+1, key),
		"unknown field":  strings.Replace(good, `"min_version"`, `"floor":1,"min_version"`, 1),
		"repeated field": strings.Replace(good, `"min_version":3`, `"min_version":3,"min_version":1`, 1),
		"schema":         strings.Replace(good, `"schema_version":1`, `"schema_version":2`, 1),
		"trailing":       good + "x",
	} {
		if _, err := DecodeAnchors([]byte(raw)); CodeOf(err) != CodeAnchorInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ReadAnchorsFile returns the exact bytes it decoded, so a caller that
// installs them never reads the source a second time.
func TestReadAnchorsFileReturnsTheDecodedBytes(t *testing.T) {
	raw := anchorsJSON("acme", nil, 0, edAnchorKey(t))
	path := filepath.Join(t.TempDir(), "anchors.json")
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	a, got, err := ReadAnchorsFile(path, nil)
	if err != nil || string(got) != raw || a.Key("k1") == nil {
		t.Fatalf("ReadAnchorsFile = %v, %q, %v", a, got, err)
	}
	if _, _, err := ReadAnchorsFile(filepath.Join(t.TempDir(), "absent.json"), nil); CodeOf(err) != CodeAnchorMissing {
		t.Fatalf("absent: %v", err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, got, err := ReadAnchorsFile(path, nil); CodeOf(err) != CodeAnchorInvalid || got != nil {
		t.Fatalf("invalid: %q, %v", got, err)
	}
}

// Anchor permission cases: the file the MDM installs must not be a link,
// a folder, writable by other accounts or owned by a standard account.
// Every one is anchor_insecure through the device trust check; with the
// check skipped (an administrator workstation) the same file loads.
func TestLoadAnchorsPermissions(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(anchorsJSON("acme", nil, 0, edAnchorKey(t))), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAnchors(filepath.Join(dir, "absent.json"), TrustAnchorFile); CodeOf(err) != CodeAnchorMissing {
		t.Fatalf("absent: %v", err)
	}
	if _, err := LoadAnchors(good, nil); err != nil {
		t.Fatalf("unchecked: %v", err)
	}
	// The temp folder and the file belong to the test account (and on
	// Linux and macOS the temp root is writable by every account). Run as
	// LocalSystem, the account and its temp folder are trusted, so the file
	// rightly loads; the cases below still hold.
	if _, err := LoadAnchors(good, TrustAnchorFile); testRunsAsLocalSystem() {
		if err != nil {
			t.Fatalf("LocalSystem-owned: %v", err)
		}
	} else if CodeOf(err) != CodeAnchorInsecure {
		t.Fatalf("user-owned: %v", err)
	}
	cases := map[string]string{"folder": filepath.Join(dir, "folder")}
	if err := os.Mkdir(cases["folder"], 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		cases["symlink"] = filepath.Join(dir, "link.json")
		if err := os.Symlink(good, cases["symlink"]); err != nil {
			t.Fatal(err)
		}
		cases["group-writable"] = filepath.Join(dir, "gw.json")
		if err := os.WriteFile(cases["group-writable"], []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(cases["group-writable"], 0o664); err != nil {
			t.Fatal(err)
		}
	}
	for name, path := range cases {
		trust := TrustAnchorFile
		if name == "symlink" || name == "folder" {
			trust = nil // refused before any trust check
		}
		if _, err := LoadAnchors(path, trust); CodeOf(err) != CodeAnchorInsecure {
			t.Errorf("%s: %v", name, err)
		}
	}
	malformed := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(malformed, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAnchors(malformed, nil); CodeOf(err) != CodeAnchorInvalid {
		t.Fatalf("malformed: %v", err)
	}
}

func TestCheckFloor(t *testing.T) {
	id := "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z2A"
	sum, other := strings.Repeat("a", 64), strings.Repeat("b", 64)
	for name, tc := range map[string]struct {
		version   uint64
		confirmed Confirmed
		anchorMin uint64
		applied   bool
		floor     uint64
		code      Code
	}{
		"first bundle":            {version: 1, floor: 0},
		"above confirmed":         {version: 8, confirmed: Confirmed{Version: 7, BundleID: "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z29"}, floor: 7},
		"equal to confirmed":      {version: 7, confirmed: Confirmed{Version: 7, BundleID: "b-01J9ZK3Q4R5S6T7V8W9X0Y1Z29"}, floor: 7, code: CodeVersionNotNewer},
		"older (replay)":          {version: 3, confirmed: Confirmed{Version: 7}, floor: 7, code: CodeVersionNotNewer},
		"the confirmed bundle":    {version: 7, confirmed: Confirmed{Version: 7, BundleID: id, ManifestSHA256: sum}, applied: true, floor: 7},
		"other manifest, same id": {version: 7, confirmed: Confirmed{Version: 7, BundleID: id, ManifestSHA256: other}, floor: 7, code: CodeVersionNotNewer},
		"no confirmed hash":       {version: 7, confirmed: Confirmed{Version: 7, BundleID: id}, floor: 7, code: CodeVersionNotNewer},
		"anchor min":              {version: 4, anchorMin: 5, floor: 5, code: CodeVersionNotNewer},
		"anchor min above it":     {version: 7, confirmed: Confirmed{Version: 7, BundleID: id, ManifestSHA256: sum}, anchorMin: 9, floor: 9, code: CodeVersionNotNewer},
		"above anchor min":        {version: 6, anchorMin: 5, floor: 5},
		"same id, other version":  {version: 8, confirmed: Confirmed{Version: 7, BundleID: id}, floor: 7},
	} {
		applied, floor, err := CheckFloor(&Manifest{BundleID: id, Version: tc.version}, sum, tc.confirmed, tc.anchorMin)
		if applied != tc.applied || floor != tc.floor || CodeOf(err) != tc.code {
			t.Errorf("%s: applied=%v floor=%d err=%v", name, applied, floor, err)
		}
	}
}

func TestCheckProductVersion(t *testing.T) {
	for _, tc := range []struct {
		min, running string
		ok           bool
	}{
		{"", "dev", true}, {"1.0.2", "1.0.2", true}, {"1.0.2", "1.1.0", true}, {"1.0.2", "1.0.10", true},
		{"1.0.2", "1.0.1", false}, {"1.0.2", "1.0.2-rc.1", false}, {"1.0.2", "dev", false}, {"1.0.2", "1.0.2+build.7", true},
		{"1.0.4-01", "1.0.3", false},
	} {
		err := CheckProductVersion(tc.min, tc.running)
		if (err == nil) != tc.ok || (err != nil && CodeOf(err) != CodeProductTooOld) {
			t.Errorf("min %s running %s: %v", tc.min, tc.running, err)
		}
	}
}

func TestNewBundleID(t *testing.T) {
	// The ULID specification example time 1469918176385 encodes as
	// 01ARYZ6S41; zero entropy gives zeros.
	id, err := NewBundleID(time.UnixMilli(1469918176385), bytes.NewReader(make([]byte, 10)))
	if err != nil || id != "b-01ARYZ6S410000000000000000" || !ValidBundleID(id) {
		t.Fatalf("%s %v", id, err)
	}
	ones, err := NewBundleID(time.UnixMilli(1<<48-1), bytes.NewReader(bytes.Repeat([]byte{0xff}, 10)))
	if err != nil || ones != "b-7ZZZZZZZZZZZZZZZZZZZZZZZZZ" || !ValidBundleID(ones) {
		t.Fatalf("%s %v", ones, err)
	}
	a, _ := NewBundleID(time.Now(), nil)
	b, _ := NewBundleID(time.Now(), nil)
	if a == b || !ValidBundleID(a) {
		t.Fatalf("%s %s", a, b)
	}
}

func TestWriteArchiveRoundTrip(t *testing.T) {
	in := &Bundle{Manifest: []byte(katManifest), Signature: []byte("{}"), Files: map[string][]byte{
		ConfigName: []byte("config_version: 9\n"),
		"policies/guardrail/strict/" + strings.Repeat("r", 120) + ".yaml": []byte("rules: []\n"),
	}}
	var first, second bytes.Buffer
	if err := WriteArchive(&first, in); err != nil {
		t.Fatal(err)
	}
	if err := WriteArchive(&second, in); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("the archive is not deterministic")
	}
	out, err := ReadArchive(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Manifest, in.Manifest) || !bytes.Equal(out.Signature, in.Signature) || len(out.Files) != len(in.Files) {
		t.Fatalf("round trip %+v", out)
	}
	for name, data := range in.Files {
		if !bytes.Equal(out.Files[name], data) {
			t.Fatalf("%s differs", name)
		}
	}
}
