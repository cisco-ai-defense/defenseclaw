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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

type testSGWChildProcess struct {
	killed bool
	waited bool
	err    error
}

func (process *testSGWChildProcess) Kill() error {
	process.killed = true
	return nil
}

func (process *testSGWChildProcess) Wait() error {
	process.waited = true
	return process.err
}

type testSGWWriteCloser struct {
	closed bool
}

func (*testSGWWriteCloser) Write(value []byte) (int, error) {
	return len(value), nil
}

func (writer *testSGWWriteCloser) Close() error {
	writer.closed = true
	return nil
}

type sgwRuntimeFixture struct {
	dataDir      string
	receiptPath  string
	packageRoot  string
	publicKeyPEM []byte
	fingerprint  string
}

func TestSGWRuntimeIdentityMatchesReleaseManifest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "release", "s-gw-module.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		PackageName      string `json:"package_name"`
		PackageVersion   string `json:"package_version"`
		UpstreamRevision string `json:"upstream_revision"`
		UpstreamTree     string `json:"upstream_tree"`
		BuildToolchain   struct {
			Node string `json:"node"`
			NPM  string `json:"npm"`
		} `json:"build_toolchain"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	checks := map[string][2]string{
		"package name":      {manifest.PackageName, sgwModulePackageName},
		"package version":   {manifest.PackageVersion, sgwModulePackageVersion},
		"upstream revision": {manifest.UpstreamRevision, sgwModuleUpstreamRevision},
		"upstream tree":     {manifest.UpstreamTree, sgwModuleUpstreamTree},
		"Node toolchain":    {manifest.BuildToolchain.Node, sgwModuleBuildNodeVersion},
		"npm toolchain":     {manifest.BuildToolchain.NPM, sgwModuleBuildNPMVersion},
	}
	for name, values := range checks {
		if values[0] != values[1] {
			t.Fatalf("s-gw %s mismatch: release manifest has %q, gateway expects %q", name, values[0], values[1])
		}
	}
}

func (fixture sgwRuntimeFixture) load() (*sgwModuleReceipt, error) {
	return loadSGWModuleReceiptWithKey(fixture.dataDir, fixture.publicKeyPEM, fixture.fingerprint)
}

func TestLoadSGWModuleReceiptVerifiesEveryInstalledFile(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	receipt, err := fixture.load()
	if err != nil {
		t.Fatalf("load receipt: %v", err)
	}
	wantRoot, err := filepath.EvalSymlinks(fixture.packageRoot)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PackageRoot != wantRoot || receipt.Target != sgwRuntimeTarget() {
		t.Fatalf("receipt = %#v", receipt)
	}

	entrypoint := filepath.Join(fixture.packageRoot, filepath.FromSlash(sgwMCPEntrypoint))
	if err := os.WriteFile(entrypoint, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("tampered module was accepted")
	}
}

func TestLoadSGWModuleReceiptFailsClosedWithoutReleaseAnchor(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	if _, err := loadSGWModuleReceipt(fixture.dataDir); err == nil {
		t.Fatal("runtime accepted a module without the compiled release trust anchor")
	}
}

func TestLoadSGWModuleReceiptRejectsSymlinkedReceipt(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	raw, err := os.ReadFile(fixture.receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	realReceipt := fixture.receiptPath + ".real"
	if err := os.WriteFile(realReceipt, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.receiptPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realReceipt, fixture.receiptPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("symlinked receipt was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsPublicPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not available on Windows")
	}
	fixture := writeSGWRuntimeFixture(t)
	if err := os.Chmod(fixture.receiptPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("public receipt permissions were accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsPublicModuleParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not available on Windows")
	}
	fixture := writeSGWRuntimeFixture(t)
	if err := os.Chmod(filepath.Join(fixture.dataDir, "modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("public module parent permissions were accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsSymlinkedModuleParent(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	modulesRoot := filepath.Join(fixture.dataDir, "modules")
	outside := filepath.Join(t.TempDir(), "moved-modules")
	if err := os.Rename(modulesRoot, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, modulesRoot); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("symlinked module parent was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsUntrackedDependency(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	path := filepath.Join(fixture.packageRoot, "node_modules", "dependency", "index.js")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("untracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("untracked dependency was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsMissingProductionComponent(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	receipt := readSGWFixtureReceipt(t, fixture.receiptPath)
	delete(receipt.Components, "credential_helper")
	writeSGWFixtureReceipt(t, fixture.receiptPath, receipt)
	if _, err := fixture.load(); err == nil {
		t.Fatal("incomplete production component receipt was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsMissingLicenseBundle(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	receipt := readSGWFixtureReceipt(t, fixture.receiptPath)
	delete(receipt.Components, "license_bundle")
	writeSGWFixtureReceipt(t, fixture.receiptPath, receipt)
	if _, err := fixture.load(); err == nil {
		t.Fatal("production receipt without its signed license bundle was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsDuplicateIdentityField(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	raw, err := os.ReadFile(fixture.receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(
		string(raw),
		`"schema_version":1`,
		`"schema_version":1,"schema_version":1`,
		1,
	))
	if err := os.WriteFile(fixture.receiptPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.load(); err == nil {
		t.Fatal("receipt with duplicate identity field was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsUnsignedInventoryRewrite(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	path := filepath.Join(fixture.packageRoot, "package.json")
	if err := os.WriteFile(path, []byte(`{"name":"@s-gw/s-gw","version":"0.2.0","tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := readSGWFixtureReceipt(t, fixture.receiptPath)
	receipt.Files["package.json"] = mustSHA256File(t, path)
	moduleFiles := copySGWDigestsExceptMetadata(receipt.Files)
	receipt.ModuleInstalledSHA256 = mustSGWInventory(t, moduleFiles, sgwModuleInventoryDomain)
	writeSGWFixtureReceipt(t, fixture.receiptPath, receipt)
	if _, err := fixture.load(); err == nil {
		t.Fatal("rewritten inventory without a new module signature was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsUnsignedContractRewrite(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	receipt := readSGWFixtureReceipt(t, fixture.receiptPath)
	receipt.RunnerContract.ApprovalMutations = "agent-callable"
	digest, err := sgwRunnerContractSHA256(receipt.RunnerContract)
	if err != nil {
		t.Fatal(err)
	}
	receipt.RunnerContractSHA256 = digest
	writeSGWFixtureReceipt(t, fixture.receiptPath, receipt)
	if _, err := fixture.load(); err == nil {
		t.Fatal("rewritten runner contract was accepted")
	}
}

func TestLoadSGWModuleReceiptRejectsUnsignedLaunchAdmissionRewrite(t *testing.T) {
	fixture := writeSGWRuntimeFixture(t)
	receipt := readSGWFixtureReceipt(t, fixture.receiptPath)
	var admission map[string]any
	if err := json.Unmarshal(receipt.RunnerLaunchAdmission, &admission); err != nil {
		t.Fatal(err)
	}
	admission["dependency_policy"] = "ambient-search-path"
	receipt.RunnerLaunchAdmission = mustSGWJSON(t, admission)
	writeSGWFixtureReceipt(t, fixture.receiptPath, receipt)
	if _, err := fixture.load(); err == nil {
		t.Fatal("rewritten runner launch admission was accepted")
	}
}

func TestSGWRunnerContractDigestMatchesReleaseSchema(t *testing.T) {
	digest, err := sgwRunnerContractSHA256(expectedSGWRunnerContract())
	if err != nil {
		t.Fatal(err)
	}
	const want = "54c066815848c543013510569925ca47bbe261282ed562f00df6d736881c0ad4"
	if digest != want {
		t.Fatalf("runner contract digest = %s, want %s", digest, want)
	}
}

func TestWaitForSGWConsoleAcceptsOnlyCanonicalStatus(t *testing.T) {
	process := &testSGWChildProcess{}
	stdin := &testSGWWriteCloser{}
	status, err := waitForSGWConsole(&sgwAdmittedCommand{
		process: process,
		stdin:   stdin,
		stdout:  bytes.NewBufferString(`{"schema_version":1,"status":"already_open"}`),
		stderr:  bytes.NewReader(nil),
	})
	if err != nil {
		t.Fatalf("wait for console: %v", err)
	}
	if status.Status != "already_open" || !stdin.closed || !process.waited || process.killed {
		t.Fatalf("status/process = %#v, closed=%t, waited=%t, killed=%t", status, stdin.closed, process.waited, process.killed)
	}
}

func TestWaitForSGWConsoleRejectsAuthorityMaterial(t *testing.T) {
	process := &testSGWChildProcess{}
	_, err := waitForSGWConsole(&sgwAdmittedCommand{
		process: process,
		stdin:   &testSGWWriteCloser{},
		stdout:  bytes.NewBufferString(`{"schema_version":1,"status":"opened","token":"forbidden"}`),
		stderr:  bytes.NewReader(nil),
	})
	if err == nil {
		t.Fatal("console status containing authority material was accepted")
	}
}

func TestWaitForSGWConsoleBoundsOutput(t *testing.T) {
	process := &testSGWChildProcess{}
	_, err := waitForSGWConsole(&sgwAdmittedCommand{
		process: process,
		stdin:   &testSGWWriteCloser{},
		stdout:  bytes.NewReader(bytes.Repeat([]byte("x"), int(sgwConsoleOutputLimit+1))),
		stderr:  bytes.NewReader(nil),
	})
	if err == nil || !process.killed {
		t.Fatalf("oversized console output: err=%v killed=%t", err, process.killed)
	}
}

func TestSGWComponentSignaturePayloadMatchesReleaseSchema(t *testing.T) {
	component := sgwReceiptComponent{
		ArtifactSHA256:  strings.Repeat("a", 64),
		InstalledSHA256: strings.Repeat("b", 64),
		Destination:     "dist/native/linux-x64/s-gw-core",
	}
	want := "defenseclaw.s-gw.component-signature.v1\n" +
		"schema_version=1\n" +
		"target=linux-x64\n" +
		"component=runner\n" +
		"destination=dist/native/linux-x64/s-gw-core\n" +
		"artifact_sha256=" + strings.Repeat("a", 64) + "\n" +
		"installed_sha256=" + strings.Repeat("b", 64) + "\n"
	if got := string(sgwComponentSignaturePayload("linux-x64", "runner", component)); got != want {
		t.Fatalf("component signature payload:\n%s\nwant:\n%s", got, want)
	}
}

func TestSGWBrokerEnvironmentIsAllowlisted(t *testing.T) {
	t.Setenv("SYNTHETIC_PARENT_CREDENTIAL", "must-not-be-inherited")
	t.Setenv("PATH", filepath.Join(t.TempDir(), "untrusted-bin"))
	t.Setenv("SystemRoot", filepath.Join(t.TempDir(), "untrusted-windows"))
	t.Setenv("WINDIR", filepath.Join(t.TempDir(), "untrusted-windir"))
	env, err := sgwBrokerEnvironment(os.Args[0])
	if err != nil {
		t.Fatalf("broker environment: %v", err)
	}
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "SYNTHETIC_PARENT_CREDENTIAL") || strings.Contains(joined, "must-not-be-inherited") {
		t.Fatal("unapproved parent environment was inherited")
	}
	if strings.Contains(joined, "untrusted-bin") || strings.Contains(joined, "untrusted-windows") ||
		strings.Contains(joined, "untrusted-windir") {
		t.Fatal("untrusted command lookup environment was inherited")
	}
	for _, required := range []string{
		"SGW_AGENT_NAME=DefenseClaw",
		"SGW_DISABLE_UPDATE_CHECK=1",
		"SGW_EXECUTION_ENGINE=rust",
		"SGW_HOME=",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("environment lacks %q: %v", required, env)
		}
	}
	if runtime.GOOS == "windows" && !strings.Contains(joined, "SGW_TRUSTED_POWERSHELL=") {
		t.Fatalf("Windows environment lacks trusted PowerShell path: %v", env)
	}
}

func writeSGWRuntimeFixture(t *testing.T) sgwRuntimeFixture {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "defenseclaw")
	moduleRoot := filepath.Join(dataDir, "modules", "s-gw")
	packageRoot := filepath.Join(moduleRoot, "fixture", "package")
	if err := os.MkdirAll(packageRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	runnerPath := "dist/native/" + sgwRuntimeTarget() + "/s-gw-core"
	if runtime.GOOS == "windows" {
		runnerPath += ".exe"
	}
	helperPath := "dist/native/" + sgwRuntimeTarget() + "/s-gw-credential-helper"
	uiRoot := "dist/console-ui"
	files := map[string][]byte{
		"package.json":            []byte(`{"name":"@s-gw/s-gw","version":"0.2.0"}`),
		sgwMCPEntrypoint:          []byte("console.log('fixture');\n"),
		sgwModuleMetadataFile:     []byte("{}\n"),
		sgwThirdPartyLicensesFile: []byte("fixture third-party licenses\n"),
		runnerPath:                []byte("fixture native runner\n"),
		helperPath:                []byte("fixture credential helper\n"),
		uiRoot + "/index.html":    []byte("<html></html>\n"),
		uiRoot + "/assets/app.js": []byte("console.log('ui');\n"),
	}
	digests := make(map[string]string, len(files))
	for relative, content := range files {
		path := filepath.Join(packageRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o600)
		if relative == runnerPath || relative == helperPath {
			mode = 0o700
		}
		if err := os.WriteFile(path, content, mode); err != nil {
			t.Fatal(err)
		}
		digests[relative] = mustSHA256File(t, path)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	keyHash := sha256.Sum256(publicKeyPEM)
	fingerprint := hex.EncodeToString(keyHash[:])

	components := map[string]sgwReceiptComponent{
		"runner": {
			ArtifactSHA256: strings.Repeat("1", 64),
			Destination:    runnerPath,
			Files:          []string{runnerPath},
		},
		"credential_helper": {
			ArtifactSHA256: strings.Repeat("2", 64),
			Destination:    helperPath,
			Files:          []string{helperPath},
		},
		"approval_ui": {
			ArtifactSHA256: strings.Repeat("3", 64),
			Destination:    uiRoot,
			Files:          []string{uiRoot + "/assets/app.js", uiRoot + "/index.html"},
		},
		"license_bundle": {
			ArtifactSHA256: strings.Repeat("4", 64),
			Destination:    sgwThirdPartyLicensesFile,
			Files:          []string{sgwThirdPartyLicensesFile},
		},
	}
	for name, component := range components {
		componentFiles := make(map[string]string, len(component.Files))
		for _, relative := range component.Files {
			componentFiles[relative] = digests[relative]
		}
		component.InstalledSHA256 = mustSGWInventory(t, componentFiles, sgwComponentInventoryDomain)
		component.Signature = signSGWFixture(privateKey, sgwComponentSignaturePayload(sgwRuntimeTarget(), name, component))
		components[name] = component
	}

	contract := expectedSGWRunnerContract()
	contractDigest, err := sgwRunnerContractSHA256(contract)
	if err != nil {
		t.Fatal(err)
	}
	admission := fixtureSGWLaunchAdmission()
	admissionRaw := mustSGWJSON(t, fixtureSGWLaunchAdmissionJSON(admission))
	moduleInstalled := mustSGWInventory(t, copySGWDigestsExceptMetadata(digests), sgwModuleInventoryDomain)
	receipt := sgwModuleReceipt{
		SchemaVersion:               1,
		PackageName:                 sgwModulePackageName,
		PackageVersion:              sgwModulePackageVersion,
		UpstreamRevision:            sgwModuleUpstreamRevision,
		UpstreamTree:                sgwModuleUpstreamTree,
		Target:                      sgwRuntimeTarget(),
		ArchiveSHA256:               strings.Repeat("0", 64),
		PackageRoot:                 packageRoot,
		NodePath:                    filepath.Join(moduleRoot, "unused-node"),
		NodeVersion:                 sgwModuleBuildNodeVersion,
		BuildToolchain:              sgwBuildToolchain{Node: sgwModuleBuildNodeVersion, NPM: sgwModuleBuildNPMVersion},
		SignaturePolicy:             sgwSignaturePolicy{Algorithm: sgwReleaseSignatureAlgorithm, PublicKeySHA256: fingerprint},
		RunnerContract:              contract,
		RunnerContractSHA256:        contractDigest,
		RunnerLaunchAdmission:       admissionRaw,
		RunnerLaunchAdmissionSHA256: sgwRunnerLaunchAdmissionSHA256(sgwRuntimeTarget(), admission),
		ModuleInstalledSHA256:       moduleInstalled,
		Components:                  components,
		Runner:                      sgwReceiptRunner{Path: runnerPath, SHA256: digests[runnerPath]},
		Files:                       digests,
		InstalledAt:                 "2030-01-01T00:00:00Z",
	}
	receipt.ModuleSignature = signSGWFixture(privateKey, sgwModuleSignaturePayload(&receipt, moduleInstalled))
	receiptPath := filepath.Join(moduleRoot, "receipt.json")
	writeSGWFixtureReceipt(t, receiptPath, receipt)

	if err := filepath.WalkDir(dataDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return safefile.ProtectDirectory(path)
		}
		return safefile.ProtectFile(path)
	}); err != nil {
		t.Fatalf("protect s-gw fixture: %v", err)
	}
	for _, path := range []string{
		filepath.Join(packageRoot, filepath.FromSlash(runnerPath)),
		filepath.Join(packageRoot, filepath.FromSlash(helperPath)),
	} {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return sgwRuntimeFixture{
		dataDir: dataDir, receiptPath: receiptPath, packageRoot: packageRoot,
		publicKeyPEM: publicKeyPEM, fingerprint: fingerprint,
	}
}

func fixtureSGWLaunchAdmission() sgwRunnerLaunchAdmission {
	admission := sgwRunnerLaunchAdmission{
		SchemaVersion: 1, SignatureScope: "installed-runner-bytes", DependencyPolicy: "system-only-v1",
	}
	switch runtime.GOOS {
	case "windows":
		admission.Mode = "windows-locked-image-v1"
		admission.PEMachine = "arm64"
		if runtime.GOARCH == "amd64" {
			admission.PEMachine = "x86_64"
		}
		admission.RequiredMitigations = []string{
			"block-non-microsoft-binaries", "image-load-no-remote", "image-load-no-low-label",
		}
	case "darwin":
		admission.Mode = "darwin-running-code-v1"
		admission.TeamID = "ABCDEFGHIJ"
		admission.SigningID = "com.cisco.s-gw-core"
		admission.CDHash = strings.Repeat("a", 40)
		admission.RequiredCSFlags = []string{"valid", "hard", "kill", "runtime"}
	default:
		admission.Mode = "linux-sealed-memfd-v1"
	}
	return admission
}

func fixtureSGWLaunchAdmissionJSON(admission sgwRunnerLaunchAdmission) map[string]any {
	value := map[string]any{
		"schema_version": admission.SchemaVersion, "mode": admission.Mode,
		"signature_scope": admission.SignatureScope, "dependency_policy": admission.DependencyPolicy,
	}
	if runtime.GOOS == "windows" {
		value["pe_machine"] = admission.PEMachine
		value["required_mitigations"] = admission.RequiredMitigations
	}
	if runtime.GOOS == "darwin" {
		value["team_id"] = admission.TeamID
		value["signing_id"] = admission.SigningID
		value["cdhash"] = admission.CDHash
		value["required_cs_flags"] = admission.RequiredCSFlags
	}
	return value
}

func readSGWFixtureReceipt(t *testing.T, path string) sgwModuleReceipt {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var receipt sgwModuleReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func writeSGWFixtureReceipt(t *testing.T, path string, receipt sgwModuleReceipt) {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustSGWInventory(t *testing.T, files map[string]string, domain []byte) string {
	t.Helper()
	digest, err := sgwInventorySHA256(files, domain)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func copySGWDigestsExceptMetadata(files map[string]string) map[string]string {
	result := make(map[string]string, len(files)-1)
	for relative, digest := range files {
		if relative != sgwModuleMetadataFile {
			result[relative] = digest
		}
	}
	return result
}

func mustSHA256File(t *testing.T, path string) string {
	t.Helper()
	digest, err := sha256File(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func signSGWFixture(privateKey ed25519.PrivateKey, payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
}

func mustSGWJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
