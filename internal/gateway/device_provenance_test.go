// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestLoadOrCreateIdentityCreatesBoundProvenance(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	keyFile := filepath.Join(dataDir, "device.key")

	if _, err := LoadOrCreateIdentity(keyFile); err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}

	assertBoundDeviceProvenance(t, keyFile, dataDir)
}

func TestLoadOrCreateIdentityRestartPreservesIdentityTriplet(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	keyFile := filepath.Join(dataDir, "device.key")
	first, err := LoadOrCreateIdentity(keyFile)
	if err != nil {
		t.Fatalf("first LoadOrCreateIdentity: %v", err)
	}
	before := readDeviceIdentityTriplet(t, keyFile, filepath.Dir(keyFile))

	second, err := LoadOrCreateIdentity(keyFile)
	if err != nil {
		t.Fatalf("second LoadOrCreateIdentity: %v", err)
	}
	after := readDeviceIdentityTriplet(t, keyFile, filepath.Dir(keyFile))

	if first.DeviceID != second.DeviceID {
		t.Fatalf("device ID changed across restart: %q != %q", first.DeviceID, second.DeviceID)
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("identity artifact %d changed across restart", i)
		}
	}
}

func TestLoadOrCreateIdentityDoesNotBlessExistingKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "device.key")
	writeLegacyDeviceKey(t, keyFile)

	if _, err := LoadOrCreateIdentity(keyFile); err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	for _, path := range []string{
		filepath.Join(dir, deviceProvenanceSecretName),
		keyFile + ".provenance",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("legacy key was blessed with %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityRefusesOrphanedContinuityState(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	keyFile := filepath.Join(dir, "device.key")
	secretFile := filepath.Join(dir, deviceProvenanceSecretName)
	if err := os.WriteFile(secretFile, make([]byte, 32), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadOrCreateIdentity(keyFile); err == nil {
		t.Fatal("LoadOrCreateIdentity succeeded with orphaned continuity state")
	} else if !strings.Contains(err.Error(), "continuity-aware recovery") {
		t.Fatalf("orphan refusal lacks recovery guidance: %v", err)
	}
	if _, err := os.Lstat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("key was created despite orphaned continuity state: %v", err)
	}
}

func TestLoadOrCreateIdentityNestedKeyUsesDataRootSecret(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	keyFile := filepath.Join(dataDir, "identity", "nested", "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}

	assertBoundDeviceProvenance(t, keyFile, dataDir)
	if _, err := os.Lstat(filepath.Join(filepath.Dir(keyFile), deviceProvenanceSecretName)); !os.IsNotExist(err) {
		t.Fatalf("provenance secret was written beside nested key: %v", err)
	}
}

func TestNewClientRelativeNestedKeyRetainsConfiguredDataDir(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	relativeKey := filepath.Join("identity", "nested", "device.key")
	keyFile := filepath.Join(dataDir, relativeKey)
	cfg := &config.GatewayConfig{DeviceKeyFile: relativeKey}
	client, err := NewClient(cfg, dataDir)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.dataDir != dataDir {
		t.Fatalf("client dataDir = %q, want %q", client.dataDir, dataDir)
	}
	if cfg.DeviceKeyFile != keyFile {
		t.Fatalf("canonical device key = %q, want %q", cfg.DeviceKeyFile, keyFile)
	}
	assertBoundDeviceProvenance(t, keyFile, dataDir)
}

func TestLoadOrCreateIdentityRefusesMissingKeyOutsideDataDirWithoutMutation(t *testing.T) {
	dataDir := t.TempDir()
	outsideRoot := t.TempDir()
	targetParent := filepath.Join(outsideRoot, "operator-selected")
	keyFile := filepath.Join(targetParent, "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity created a missing key outside data_dir")
	}
	if _, err := os.Lstat(targetParent); !os.IsNotExist(err) {
		t.Fatalf("outside parent was mutated: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, deviceProvenanceSecretName)); !os.IsNotExist(err) {
		t.Fatalf("provenance secret was created after containment refusal: %v", err)
	}
}

func TestLoadOrCreateIdentityLoadsExistingOutsideDataDirWithoutBlessing(t *testing.T) {
	dataDir := t.TempDir()
	outsideRoot := t.TempDir()
	keyFile := filepath.Join(outsideRoot, "device.key")
	writeLegacyDeviceKey(t, keyFile)

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	for _, path := range []string{
		filepath.Join(dataDir, deviceProvenanceSecretName),
		filepath.Join(outsideRoot, deviceProvenanceSecretName),
		keyFile + ".provenance",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("existing outside key was blessed with %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityResolvesRelativeMissingKeyUnderDataDir(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	dataDir := testenv.PrivateTempDir(t)
	relativeKey := filepath.Join("identity", "nested", "device.key")
	keyFile := filepath.Join(dataDir, relativeKey)

	if _, err := LoadOrCreateIdentity(relativeKey, dataDir); err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	assertBoundDeviceProvenance(t, keyFile, dataDir)
	if _, err := os.Lstat(filepath.Join(workingDir, "identity")); !os.IsNotExist(err) {
		t.Fatalf("relative key path mutated the process working directory: %v", err)
	}
}

func TestLoadOrCreateIdentityLoadsRelativeExistingKeyWithoutBlessing(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	dataDir := testenv.PrivateTempDir(t)
	relativeKey := filepath.Join("identity", "device.key")
	keyFile := filepath.Join(dataDir, relativeKey)
	if err := safefile.ProtectDirectory(filepath.Dir(keyFile)); err != nil {
		t.Fatalf("ProtectDirectory: %v", err)
	}
	writeLegacyDeviceKey(t, keyFile)
	want, err := LoadOrCreateIdentity(keyFile, dataDir)
	if err != nil {
		t.Fatalf("load absolute key: %v", err)
	}

	got, err := LoadOrCreateIdentity(relativeKey, dataDir)
	if err != nil {
		t.Fatalf("load relative key: %v", err)
	}
	if got.DeviceID != want.DeviceID {
		t.Fatalf("relative key device ID = %q, want %q", got.DeviceID, want.DeviceID)
	}
	for _, path := range []string{
		filepath.Join(dataDir, deviceProvenanceSecretName),
		keyFile + ".provenance",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("relative legacy key was blessed with %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityRefusesRelativeExistingKeyBeforeRead(t *testing.T) {
	workingDir := t.TempDir()
	t.Chdir(workingDir)
	relativeKey := filepath.Join("relative-parent", "device.key")
	absoluteKey := filepath.Join(workingDir, relativeKey)
	if err := os.Mkdir(filepath.Dir(absoluteKey), 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	writeLegacyDeviceKey(t, absoluteKey)

	if _, err := LoadOrCreateIdentity(relativeKey); err == nil {
		t.Fatal("LoadOrCreateIdentity read an existing relative key")
	}
	if _, err := os.Lstat(absoluteKey + ".provenance"); !os.IsNotExist(err) {
		t.Fatalf("relative existing key was blessed: %v", err)
	}
}

func TestLoadOrCreateIdentityRefusesRelativeDataDirBeforeExistingRead(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "device.key")
	writeLegacyDeviceKey(t, keyFile)

	if _, err := LoadOrCreateIdentity(keyFile, "relative-data-dir"); err == nil {
		t.Fatal("LoadOrCreateIdentity accepted a relative data directory")
	}
	if _, err := os.Lstat(keyFile + ".provenance"); !os.IsNotExist(err) {
		t.Fatalf("key was blessed through a relative data directory: %v", err)
	}
}

func TestLoadOrCreateIdentityRefusesRelativeTraversalBeforeRead(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	outsideKey := filepath.Join(filepath.Dir(dataDir), "outside-device.key")
	writeLegacyDeviceKey(t, outsideKey)

	if _, err := LoadOrCreateIdentity(filepath.Join("..", filepath.Base(outsideKey)), dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity read a relative key outside data_dir")
	}
	if _, err := os.Lstat(outsideKey + ".provenance"); !os.IsNotExist(err) {
		t.Fatalf("outside key was blessed through relative traversal: %v", err)
	}
}

func TestPrepareFreshIdentityDirectoriesSyncsEachCreatedParent(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	parent := filepath.Join(dataDir, "identity", "nested")
	var synced []string

	err := prepareFreshIdentityDirectoriesWith(
		dataDir,
		parent,
		safefile.ProtectDirectory,
		func(path string) error {
			synced = append(synced, path)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("prepareFreshIdentityDirectoriesWith: %v", err)
	}
	want := []string{dataDir, filepath.Join(dataDir, "identity")}
	if !slices.Equal(synced, want) {
		t.Fatalf("synced parents = %#v, want %#v", synced, want)
	}
}

func TestPrepareFreshIdentityDirectoriesStopsAfterParentSyncFailure(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	first := filepath.Join(dataDir, "identity")
	second := filepath.Join(first, "nested")
	syncFailure := errors.New("injected directory sync failure")

	err := prepareFreshIdentityDirectoriesWith(
		dataDir,
		second,
		safefile.ProtectDirectory,
		func(string) error { return syncFailure },
	)
	if !errors.Is(err, syncFailure) {
		t.Fatalf("prepareFreshIdentityDirectoriesWith error = %v, want %v", err, syncFailure)
	}
	if info, statErr := os.Lstat(first); statErr != nil || !info.IsDir() {
		t.Fatalf("first validated directory was not retained: info=%v err=%v", info, statErr)
	}
	if _, statErr := os.Lstat(second); !os.IsNotExist(statErr) {
		t.Fatalf("deeper directory was created after sync failure: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(dataDir, deviceProvenanceSecretName)); !os.IsNotExist(statErr) {
		t.Fatalf("identity artifact was created after sync failure: %v", statErr)
	}
}

func TestPrepareFreshIdentityDirectoriesRetryResyncsExistingEntries(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	first := filepath.Join(dataDir, "identity")
	second := filepath.Join(first, "nested")
	syncFailure := errors.New("injected intermediate sync failure")
	syncCalls := 0

	err := prepareFreshIdentityDirectoriesWith(
		dataDir,
		second,
		safefile.ProtectDirectory,
		func(string) error {
			syncCalls++
			if syncCalls == 2 {
				return syncFailure
			}
			return nil
		},
	)
	if !errors.Is(err, syncFailure) {
		t.Fatalf("first preparation error = %v, want %v", err, syncFailure)
	}
	for _, path := range []string{first, second} {
		if info, statErr := os.Lstat(path); statErr != nil || !info.IsDir() {
			t.Fatalf("interrupted directory %s missing: info=%v err=%v", path, info, statErr)
		}
	}

	var retried []string
	if err := prepareFreshIdentityDirectoriesWith(
		dataDir,
		second,
		safefile.ProtectDirectory,
		func(path string) error {
			retried = append(retried, path)
			return nil
		},
	); err != nil {
		t.Fatalf("retry preparation: %v", err)
	}
	want := []string{dataDir, first}
	if !slices.Equal(retried, want) {
		t.Fatalf("retry synced parents = %#v, want %#v", retried, want)
	}
}

func TestLoadOrCreateIdentityRefusesMissingDataDirWithoutCreatingIt(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "missing-data")
	keyFile := filepath.Join(dataDir, "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity created a missing configured data directory")
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("missing data directory was created: %v", err)
	}
}

func TestLoadOrCreateIdentityRefusesNestedSymlinkWithoutOutsideMutation(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	outside := t.TempDir()
	jump := filepath.Join(dataDir, "jump")
	if err := os.Symlink(outside, jump); err != nil {
		t.Skipf("directory symlink unavailable: %v", err)
	}
	keyFile := filepath.Join(jump, "deeper", "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity followed a nested symlink")
	}
	for _, path := range []string{
		filepath.Join(outside, "deeper"),
		filepath.Join(dataDir, deviceProvenanceSecretName),
		keyFile + ".provenance",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("artifact escaped through nested symlink: %s: %v", path, err)
		}
	}
}

func TestLoadOrCreateIdentityRefusesNestedNonDirectory(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	blocked := filepath.Join(dataDir, "blocked")
	if err := os.WriteFile(blocked, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	keyFile := filepath.Join(blocked, "deeper", "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity traversed a non-directory component")
	}
	if _, err := os.Lstat(filepath.Join(dataDir, deviceProvenanceSecretName)); !os.IsNotExist(err) {
		t.Fatalf("provenance secret was created after non-directory refusal: %v", err)
	}
}

func TestLoadOrCreateIdentityRefusesReservedArtifactAliasesWithoutMutation(t *testing.T) {
	for _, relativeKey := range []string{
		deviceProvenanceSecretName,
		filepath.Join(deviceProvenanceSecretName, "nested", "device.key"),
	} {
		t.Run(relativeKey, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "missing-data")
			keyFile := filepath.Join(dataDir, relativeKey)
			if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
				t.Fatal("LoadOrCreateIdentity accepted a reserved artifact alias")
			}
			if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
				t.Fatalf("data directory was created after alias refusal: %v", err)
			}
		})
	}
}

func TestLoadOrCreateIdentityRefusesCaseVariantsOfReservedSecret(t *testing.T) {
	for _, relativeKey := range []string{
		strings.ToUpper(deviceProvenanceSecretName),
		filepath.Join(strings.ToUpper(deviceProvenanceSecretName), "nested", "device.key"),
	} {
		t.Run(relativeKey, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "missing-data")
			keyFile := filepath.Join(dataDir, relativeKey)
			if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
				t.Fatal("LoadOrCreateIdentity accepted a case variant of the reserved secret")
			}
			if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
				t.Fatalf("data directory was created after case-folded alias refusal: %v", err)
			}
		})
	}
}

func TestLoadOrCreateIdentityDoesNotTightenBroadExistingDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode-preservation regression")
	}
	dataDir := t.TempDir()
	if err := os.Chmod(dataDir, 0o755); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	keyFile := filepath.Join(dataDir, "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err == nil {
		t.Fatal("LoadOrCreateIdentity accepted a broad existing data directory")
	}
	info, err := os.Lstat(dataDir)
	if err != nil {
		t.Fatalf("Lstat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("data directory mode was mutated to %04o", got)
	}
}

func TestLoadOrCreateIdentityRefusesMultipleDataDirsWithoutMutation(t *testing.T) {
	dataDir := t.TempDir()
	keyFile := filepath.Join(dataDir, "device.key")

	if _, err := LoadOrCreateIdentity(keyFile, dataDir, t.TempDir()); err == nil {
		t.Fatal("LoadOrCreateIdentity accepted multiple data directories")
	}
	for _, path := range []string{
		keyFile,
		filepath.Join(dataDir, deviceProvenanceSecretName),
		keyFile + ".provenance",
	} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("identity artifact was created after argument refusal: %s: %v", path, err)
		}
	}
}

func assertBoundDeviceProvenance(t *testing.T, keyFile, dataDir string) {
	t.Helper()
	triplet := readDeviceIdentityTriplet(t, keyFile, dataDir)
	keyData, secret, provenance := triplet[0], triplet[1], triplet[2]
	if len(secret) != 32 {
		t.Fatalf("provenance secret length = %d, want 32", len(secret))
	}
	mac := hmac.New(sha256.New, secret)
	if _, err := mac.Write(keyData); err != nil {
		t.Fatalf("hash key: %v", err)
	}
	want := []byte(deviceProvenancePrefix + hex.EncodeToString(mac.Sum(nil)) + "\n")
	if !hmac.Equal(provenance, want) {
		t.Fatalf("provenance is not bound to the exact key bytes")
	}
	for _, path := range []string{
		keyFile,
		filepath.Join(dataDir, deviceProvenanceSecretName),
		keyFile + ".provenance",
	} {
		testenv.AssertPrivateFile(t, path)
	}
}

func readDeviceIdentityTriplet(t *testing.T, keyFile, dataDir string) [3][]byte {
	t.Helper()
	paths := [3]string{
		keyFile,
		filepath.Join(dataDir, deviceProvenanceSecretName),
		keyFile + ".provenance",
	}
	var values [3][]byte
	for i, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", path, err)
		}
		values[i] = data
	}
	return values
}

func writeLegacyDeviceKey(t *testing.T, keyFile string) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyData := pem.EncodeToMemory(&pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privateKey.Seed(),
	})
	if err := os.WriteFile(keyFile, keyData, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}
