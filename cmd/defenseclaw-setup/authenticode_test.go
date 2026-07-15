// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unsignedTestPE() []byte {
	data := make([]byte, 512)
	binary.LittleEndian.PutUint16(data[0:2], 0x5a4d)
	binary.LittleEndian.PutUint32(data[0x3c:0x40], 0x80)
	binary.LittleEndian.PutUint32(data[0x80:0x84], 0x00004550)
	// IMAGE_FILE_HEADER.SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(data[0x80+20:0x80+22], 240)
	optional := 0x80 + 24
	binary.LittleEndian.PutUint16(data[optional:optional+2], 0x20b)
	binary.LittleEndian.PutUint32(data[optional+108:optional+112], 16)
	copy(data[400:], []byte("DefenseClaw unsigned PE fixture"))
	return data
}

func setTestPECertificateTable(data []byte, offset, size uint32) {
	optional := 0x80 + 24
	securityDirectory := optional + 112 + 32
	binary.LittleEndian.PutUint32(data[securityDirectory:securityDirectory+4], offset)
	binary.LittleEndian.PutUint32(data[securityDirectory+4:securityDirectory+8], size)
}

func TestReadEmbeddedPKCS7ReadsCertificateTable(t *testing.T) {
	data := unsignedTestPE()
	payload := []byte("pkcs7-fixture")
	const certificateOffset = 400
	recordLength := 8 + len(payload)
	recordSize := (recordLength + 7) &^ 7
	setTestPECertificateTable(data, certificateOffset, uint32(recordSize))
	binary.LittleEndian.PutUint32(data[certificateOffset:certificateOffset+4], uint32(recordLength))
	binary.LittleEndian.PutUint16(data[certificateOffset+4:certificateOffset+6], 0x0200)
	binary.LittleEndian.PutUint16(data[certificateOffset+6:certificateOffset+8], 0x0002)
	copy(data[certificateOffset+8:], payload)
	path := filepath.Join(t.TempDir(), "signed.exe")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	got, present, err := readEmbeddedPKCS7(path)
	if err != nil {
		t.Fatalf("readEmbeddedPKCS7: %v", err)
	}
	if !present || !bytes.Equal(got, payload) {
		t.Fatalf("PKCS#7 = %x, present=%t; want %x, true", got, present, payload)
	}
}

func TestReadEmbeddedPKCS7RejectsOversizedCertificateTable(t *testing.T) {
	data := unsignedTestPE()
	const certificateOffset = 512
	certificateSize := uint32(maxEmbeddedCertificateTableSize + 1)
	setTestPECertificateTable(data, certificateOffset, certificateSize)
	path := filepath.Join(t.TempDir(), "oversized.exe")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, int64(certificateOffset)+int64(certificateSize)); err != nil {
		t.Fatal(err)
	}

	if _, _, err := readEmbeddedPKCS7(path); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("readEmbeddedPKCS7 oversized table error = %v", err)
	}
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func unsignedEvidence(installedPath, sbomName, digest, policy string) authenticodeFileEvidence {
	expected := authenticodeFilePolicy{
		Policy:                   policy,
		Status:                   "NotSigned",
		PlatformIdentityRequired: policy != pinnedInputAuthenticodePolicy,
	}
	if policy != pinnedInputAuthenticodePolicy {
		expected.SignatureType = "None"
	}
	return authenticodeFileEvidence{
		SchemaVersion: authenticodeEvidenceSchemaVersion,
		InstalledPath: installedPath,
		SBOMFileName:  sbomName,
		SHA256:        digest,
		Expected:      expected,
		Observed:      json.RawMessage(`{"status":"NotSigned","embedded_signatures":null}`),
	}
}

func unsignedManifestFixture(t *testing.T) (string, payloadManifest) {
	t.Helper()
	root := t.TempDir()
	pe := unsignedTestPE()
	digest := digestBytes(pe)
	files := make(map[string]authenticodeFileEvidence)
	for _, installedPath := range requiredProductPEPaths {
		full := filepath.Join(root, filepath.FromSlash(installedPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, pe, 0o755); err != nil {
			t.Fatal(err)
		}
		files[installedPath] = unsignedEvidence(
			installedPath,
			"./fixture/"+strings.ReplaceAll(installedPath, "/", "-"),
			digest,
			productAuthenticodePolicy,
		)
	}
	for installedPath, policy := range map[string]string{
		"runtime/python/python.exe": pinnedInputAuthenticodePolicy,
		"runtime/tools/cosign.exe":  digestOnlyAuthenticodePolicy,
	} {
		full := filepath.Join(root, filepath.FromSlash(installedPath))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, pe, 0o755); err != nil {
			t.Fatal(err)
		}
		files[installedPath] = unsignedEvidence(installedPath, "./fixture/"+filepath.Base(full), digest, policy)
	}
	manifest := payloadManifest{
		SchemaVersion:      2,
		Version:            "1.2.3",
		SourceCommit:       "0123456789abcdef0123456789abcdef01234567",
		DistributionFlavor: "oss",
		PythonVersion:      "3.14.6",
		GatewayArchive:     "gateway.zip",
		Wheel:              "defenseclaw.whl",
		PythonEmbed:        "python.zip",
		YaraCompatWheel:    "yara-compat.whl",
		UpgradeManifest:    "upgrade-manifest.json",
		SitePackages:       "site-packages.zip",
		Launcher:           "launcher.exe",
		StartupLauncher:    "startup.exe",
		CosignVerifier:     "cosign.exe",
		Unsigned:           true,
		Files: map[string]string{
			"gateway.zip":           strings.Repeat("1", 64),
			"defenseclaw.whl":       strings.Repeat("2", 64),
			"python.zip":            strings.Repeat("3", 64),
			"yara-compat.whl":       strings.Repeat("4", 64),
			"upgrade-manifest.json": strings.Repeat("5", 64),
			"site-packages.zip":     strings.Repeat("6", 64),
			"launcher.exe":          digest,
			"startup.exe":           digest,
			"cosign.exe":            digest,
		},
		Authenticode: authenticodeInventory{
			SchemaVersion: authenticodeInventorySchemaVersion,
			Files:         files,
		},
	}
	return root, manifest
}

func cloneManifest(t *testing.T, manifest payloadManifest) payloadManifest {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var cloned payloadManifest
	if err := json.Unmarshal(data, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestValidateAuthenticodeManifestAcceptsExplicitUnsignedLocalPolicy(t *testing.T) {
	root, manifest := unsignedManifestFixture(t)
	if err := validateAuthenticodeManifest(manifest); err != nil {
		t.Fatalf("validate Authenticode manifest: %v", err)
	}
	if err := verifyInstalledPEInventoryWith(root, manifest, func(string) error {
		return errors.New("trust verifier must not run for unsigned files")
	}); err != nil {
		t.Fatalf("verify unsigned installed inventory: %v", err)
	}
}

func TestVerifyPayloadManifestAcceptsSchemaTwoAuthenticodeAndYaraContract(t *testing.T) {
	_, manifest := unsignedManifestFixture(t)
	root := t.TempDir()
	payloadRoot := filepath.Join(root, "payload")
	if err := os.MkdirAll(payloadRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	pe := unsignedTestPE()
	for _, name := range []string{manifest.Launcher, manifest.StartupLauncher, manifest.CosignVerifier} {
		if err := os.WriteFile(filepath.Join(payloadRoot, name), pe, 0o755); err != nil {
			t.Fatal(err)
		}
		manifest.Files[name] = digestBytes(pe)
	}
	for _, name := range []string{
		manifest.GatewayArchive, manifest.Wheel, manifest.PythonEmbed, manifest.YaraCompatWheel,
		manifest.UpgradeManifest, manifest.SitePackages,
	} {
		data := []byte("fixture:" + name)
		if err := os.WriteFile(filepath.Join(payloadRoot, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		manifest.Files[name] = digestBytes(data)
	}
	if err := verifyPayloadManifest(root, manifest); err != nil {
		t.Fatalf("verify schema-two payload manifest: %v", err)
	}
}

func TestValidateAuthenticodeManifestRejectsPolicyAndPathDowngrades(t *testing.T) {
	_, base := unsignedManifestFixture(t)
	tests := map[string]func(*payloadManifest){
		"missing product": func(manifest *payloadManifest) {
			delete(manifest.Authenticode.Files, "bin/defenseclaw-hook.exe")
		},
		"traversal": func(manifest *payloadManifest) {
			evidence := manifest.Authenticode.Files["runtime/python/python.exe"]
			delete(manifest.Authenticode.Files, evidence.InstalledPath)
			evidence.InstalledPath = "runtime/python/../escape.exe"
			manifest.Authenticode.Files[evidence.InstalledPath] = evidence
		},
		"case collision": func(manifest *payloadManifest) {
			evidence := manifest.Authenticode.Files["runtime/python/python.exe"]
			evidence.InstalledPath = "runtime/Python/python.exe"
			manifest.Authenticode.Files[evidence.InstalledPath] = evidence
		},
		"bad digest": func(manifest *payloadManifest) {
			evidence := manifest.Authenticode.Files["runtime/python/python.exe"]
			evidence.SHA256 = strings.Repeat("A", 64)
			manifest.Authenticode.Files[evidence.InstalledPath] = evidence
		},
		"unsigned signer pin": func(manifest *payloadManifest) {
			evidence := manifest.Authenticode.Files["bin/defenseclaw.exe"]
			evidence.Expected.SignerThumbprintSHA256 = strings.Repeat("a", 64)
			manifest.Authenticode.Files[evidence.InstalledPath] = evidence
		},
		"cosign policy downgrade": func(manifest *payloadManifest) {
			evidence := manifest.Authenticode.Files["runtime/tools/cosign.exe"]
			evidence.Expected.Policy = pinnedInputAuthenticodePolicy
			manifest.Authenticode.Files[evidence.InstalledPath] = evidence
		},
		"direct hash mismatch": func(manifest *payloadManifest) {
			manifest.Files[manifest.Launcher] = strings.Repeat("f", 64)
		},
		"missing python": func(manifest *payloadManifest) {
			delete(manifest.Authenticode.Files, "runtime/python/python.exe")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := cloneManifest(t, base)
			mutate(&manifest)
			if err := validateAuthenticodeManifest(manifest); err == nil {
				t.Fatal("validateAuthenticodeManifest accepted a downgraded contract")
			}
		})
	}
}

func TestVerifyInstalledPEInventoryRejectsTamperMissingAndExtraPEs(t *testing.T) {
	tests := map[string]func(*testing.T, string, *payloadManifest){
		"tampered": func(t *testing.T, root string, _ *payloadManifest) {
			path := filepath.Join(root, "bin", "defenseclaw.exe")
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte("tamper")); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		},
		"missing": func(t *testing.T, root string, _ *payloadManifest) {
			if err := os.Remove(filepath.Join(root, "bin", "defenseclaw-hook.exe")); err != nil {
				t.Fatal(err)
			}
		},
		"extra pyd": func(t *testing.T, root string, _ *payloadManifest) {
			if err := os.WriteFile(filepath.Join(root, "runtime", "python", "extra.pyd"), unsignedTestPE(), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"listed non PE": func(t *testing.T, root string, manifest *payloadManifest) {
			name := "runtime/python/python.exe"
			data := []byte("not a PE")
			if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), data, 0o755); err != nil {
				t.Fatal(err)
			}
			evidence := manifest.Authenticode.Files[name]
			evidence.SHA256 = digestBytes(data)
			manifest.Authenticode.Files[name] = evidence
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			root, manifest := unsignedManifestFixture(t)
			mutate(t, root, &manifest)
			if err := verifyInstalledPEInventoryWith(root, manifest, func(string) error { return nil }); err == nil {
				t.Fatal("verifyInstalledPEInventory accepted a mutated install tree")
			}
		})
	}
}

func TestValidPortableRelativePathRejectsWindowsAliases(t *testing.T) {
	for _, value := range []string{
		"../escape.exe", `bin\escape.exe`, "bin/tool.exe:stream", "bin/CON.exe",
		"bin/trailing. /tool.exe", "bin//tool.exe", "bin/ümlaut.exe",
	} {
		if validPortableRelativePath(value) {
			t.Fatalf("validPortableRelativePath(%q) = true", value)
		}
	}
	if !validPortableRelativePath("runtime/python/Lib/site-packages/native.pyd") {
		t.Fatal("valid portable relative path was rejected")
	}
}
