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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	sgwModulePackageName      = "@s-gw/s-gw"
	sgwModulePackageVersion   = "0.2.0"
	sgwModuleUpstreamRevision = "652b042ef61da6170cb26aa8e4d8e446dc1c9b22"
	sgwModuleUpstreamTree     = "0451e84cbfa65c5050df309c1b045344b75dae10"
	sgwModuleBuildNodeVersion = "24.18.1"
	sgwModuleBuildNPMVersion  = "11.16.0"
	sgwModuleReceiptLimit     = 1024 * 1024
	sgwModuleFileLimit        = 100_000
	sgwModuleTotalBytes       = int64(1024 * 1024 * 1024)
	sgwMCPEntrypoint          = "dist/mcp-server.js"
	sgwConsoleOutputLimit     = int64(4 * 1024)
	sgwConsoleStderrLimit     = int64(64 * 1024)
	sgwConsoleTimeout         = 15 * time.Second
)

type sgwModuleReceipt struct {
	SchemaVersion               int                            `json:"schema_version"`
	PackageName                 string                         `json:"package_name"`
	PackageVersion              string                         `json:"package_version"`
	UpstreamRevision            string                         `json:"upstream_revision"`
	UpstreamTree                string                         `json:"upstream_tree"`
	Target                      string                         `json:"target"`
	ArchiveSHA256               string                         `json:"archive_sha256"`
	PackageRoot                 string                         `json:"package_root"`
	NodePath                    string                         `json:"node_path"`
	NodeVersion                 string                         `json:"node_version"`
	BuildToolchain              sgwBuildToolchain              `json:"build_toolchain"`
	SignaturePolicy             sgwSignaturePolicy             `json:"signature_policy"`
	RunnerContract              sgwRunnerContract              `json:"runner_contract"`
	RunnerContractSHA256        string                         `json:"runner_contract_sha256"`
	RunnerLaunchAdmission       json.RawMessage                `json:"runner_launch_admission"`
	RunnerLaunchAdmissionSHA256 string                         `json:"runner_launch_admission_sha256"`
	ModuleInstalledSHA256       string                         `json:"module_installed_sha256"`
	ModuleSignature             string                         `json:"module_signature"`
	Components                  map[string]sgwReceiptComponent `json:"components"`
	Runner                      sgwReceiptRunner               `json:"runner"`
	Files                       map[string]string              `json:"files"`
	InstalledAt                 string                         `json:"installed_at"`
	runnerLaunch                sgwRunnerLaunchAdmission       `json:"-"`
	managedRoot                 string                         `json:"-"`
}

type sgwBuildToolchain struct {
	Node string `json:"node"`
	NPM  string `json:"npm"`
}

type sgwReceiptComponent struct {
	ArtifactSHA256  string   `json:"artifact_sha256"`
	InstalledSHA256 string   `json:"installed_sha256"`
	Signature       string   `json:"signature"`
	Destination     string   `json:"destination"`
	Files           []string `json:"files"`
}

type sgwReceiptRunner struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type sgwPackageIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type SGWConsoleStatus struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
}

func newInstalledSGWCredentialTokenizer(dataDir string) (*sgwCredentialTokenizer, error) {
	receipt, err := loadSGWModuleReceipt(dataDir)
	if err != nil {
		return nil, err
	}
	runnerPath := filepath.Join(receipt.PackageRoot, filepath.FromSlash(receipt.Runner.Path))
	env, err := sgwBrokerEnvironment(runnerPath)
	if err != nil {
		return nil, err
	}
	client, err := startVerifiedSGWRunner(receipt, runnerPath, env)
	if err != nil {
		return nil, err
	}
	tokenizer, err := newSGWCredentialTokenizer(client)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return tokenizer, nil
}

func startVerifiedSGWRunner(
	receipt *sgwModuleReceipt,
	runnerPath string,
	env []string,
) (*sgwMCPProcess, error) {
	command, err := startAdmittedSGWRunner(
		receipt,
		runnerPath,
		env,
		receipt.RunnerContract.MCPArguments,
	)
	if err != nil {
		return nil, err
	}
	return initializeSGWMCPProcess(command.process, command.stdin, command.stdout, command.stderr)
}

func OpenInstalledSGWConsole(dataDir string) (SGWConsoleStatus, error) {
	receipt, err := loadSGWModuleReceipt(dataDir)
	if err != nil {
		return SGWConsoleStatus{}, err
	}
	runnerPath := filepath.Join(receipt.PackageRoot, filepath.FromSlash(receipt.Runner.Path))
	env, err := sgwBrokerEnvironment(runnerPath)
	if err != nil {
		return SGWConsoleStatus{}, err
	}
	command, err := startAdmittedSGWRunner(
		receipt,
		runnerPath,
		env,
		receipt.RunnerContract.ConsoleArguments,
	)
	if err != nil {
		return SGWConsoleStatus{}, err
	}
	return waitForSGWConsole(command)
}

type sgwConsoleReadResult struct {
	stream string
	value  []byte
	err    error
	large  bool
}

func waitForSGWConsole(command *sgwAdmittedCommand) (SGWConsoleStatus, error) {
	if command == nil || command.process == nil || command.stdin == nil ||
		command.stdout == nil || command.stderr == nil {
		return SGWConsoleStatus{}, errors.New("s-gw approval console process is invalid")
	}
	if err := command.stdin.Close(); err != nil {
		_ = command.process.Kill()
		_ = command.process.Wait()
		return SGWConsoleStatus{}, errors.New("close s-gw approval console input")
	}

	results := make(chan sgwConsoleReadResult, 3)
	read := func(stream string, source io.Reader, limit int64) {
		value, err := io.ReadAll(io.LimitReader(source, limit+1))
		results <- sgwConsoleReadResult{
			stream: stream,
			value:  value,
			err:    err,
			large:  int64(len(value)) > limit,
		}
	}
	go read("stdout", command.stdout, sgwConsoleOutputLimit)
	go read("stderr", command.stderr, sgwConsoleStderrLimit)
	go func() {
		results <- sgwConsoleReadResult{stream: "wait", err: command.process.Wait()}
	}()

	timer := time.NewTimer(sgwConsoleTimeout)
	defer timer.Stop()
	var stdout []byte
	var failed bool
	var timedOut bool
	for pending := 3; pending > 0; {
		select {
		case result := <-results:
			pending--
			if result.stream == "stdout" {
				stdout = result.value
			}
			if result.err != nil || result.large {
				failed = true
				_ = command.process.Kill()
			}
		case <-timer.C:
			timedOut = true
			failed = true
			_ = command.process.Kill()
		}
	}
	if timedOut {
		return SGWConsoleStatus{}, errors.New("s-gw approval console timed out")
	}
	if failed {
		return SGWConsoleStatus{}, errors.New("s-gw approval console failed")
	}

	var status SGWConsoleStatus
	if decodeSGWJSON(stdout, &status, true) != nil || status.SchemaVersion != 1 ||
		(status.Status != "opened" && status.Status != "already_open") {
		return SGWConsoleStatus{}, errors.New("s-gw approval console returned an invalid status")
	}
	return status, nil
}

func loadSGWModuleReceipt(dataDir string) (*sgwModuleReceipt, error) {
	return loadSGWModuleReceiptWithKey(
		dataDir,
		[]byte(sgwReleasePublicKeyPEM),
		sgwReleasePublicKeySHA256,
	)
}

func loadSGWModuleReceiptWithKey(
	dataDir string,
	publicKeyPEM []byte,
	publicKeySHA256 string,
) (*sgwModuleReceipt, error) {
	managedRoot, err := privateManagedModuleRoot(dataDir)
	if err != nil {
		return nil, err
	}
	receiptPath := filepath.Join(managedRoot, "receipt.json")
	if err := requirePrivateRegularFile(receiptPath); err != nil {
		return nil, errors.New("s-gw module receipt is unavailable")
	}
	raw, err := readBoundedFile(receiptPath, sgwModuleReceiptLimit)
	if err != nil {
		return nil, errors.New("s-gw module receipt is invalid")
	}
	if rejectDuplicateJSONKeys(raw) != nil {
		return nil, errors.New("s-gw module receipt is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt sgwModuleReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return nil, errors.New("s-gw module receipt is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("s-gw module receipt is invalid")
	}
	if err := validateSGWReceipt(&receipt, managedRoot); err != nil {
		return nil, err
	}
	if err := validateSGWReleaseProof(&receipt, publicKeyPEM, publicKeySHA256); err != nil {
		return nil, err
	}
	receipt.managedRoot = managedRoot
	return &receipt, nil
}

func privateManagedModuleRoot(dataDir string) (string, error) {
	if !filepath.IsAbs(dataDir) {
		return "", errors.New("DefenseClaw data directory must be absolute")
	}
	dataRoot, err := filepath.EvalSymlinks(filepath.Clean(dataDir))
	if err != nil {
		return "", errors.New("DefenseClaw data directory is unavailable")
	}
	if err := requirePrivateDirectory(dataRoot); err != nil {
		return "", errors.New("DefenseClaw data directory is not private")
	}
	modulesRoot := filepath.Join(dataRoot, "modules")
	if err := requirePrivateDirectory(modulesRoot); err != nil {
		return "", errors.New("DefenseClaw module directory is not private")
	}
	root := filepath.Join(modulesRoot, "s-gw")
	if err := requirePrivateDirectory(root); err != nil {
		return "", errors.New("s-gw module directory is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("s-gw module directory is not trusted")
	}
	return resolved, nil
}

func validateSGWReceipt(receipt *sgwModuleReceipt, managedRoot string) error {
	if receipt == nil || receipt.SchemaVersion != 1 ||
		receipt.PackageName != sgwModulePackageName ||
		receipt.PackageVersion != sgwModulePackageVersion ||
		receipt.UpstreamRevision != sgwModuleUpstreamRevision ||
		receipt.UpstreamTree != sgwModuleUpstreamTree ||
		receipt.BuildToolchain.Node != sgwModuleBuildNodeVersion ||
		receipt.BuildToolchain.NPM != sgwModuleBuildNPMVersion ||
		receipt.Target != sgwRuntimeTarget() ||
		!validSHA256(receipt.ArchiveSHA256) ||
		!validSHA256(receipt.RunnerContractSHA256) ||
		!validSHA256(receipt.RunnerLaunchAdmissionSHA256) ||
		!validSHA256(receipt.ModuleInstalledSHA256) ||
		!validSHA256(receipt.Runner.SHA256) ||
		receipt.ModuleSignature == "" ||
		receipt.InstalledAt == "" {
		return errors.New("s-gw module receipt identity is invalid")
	}
	if err := validateSGWReceiptComponents(receipt); err != nil {
		return err
	}

	packageRoot, err := confinedExistingPath(receipt.PackageRoot, managedRoot)
	if err != nil {
		return errors.New("s-gw module package path is invalid")
	}
	info, err := os.Lstat(packageRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("s-gw module package path is invalid")
	}
	if err := requirePrivatePath(packageRoot, info); err != nil {
		return errors.New("s-gw module package path is not private")
	}
	receipt.PackageRoot = packageRoot

	if len(receipt.Files) == 0 || len(receipt.Files) > sgwModuleFileLimit {
		return errors.New("s-gw module file inventory is invalid")
	}
	required := map[string]string{
		"package.json":            "",
		sgwMCPEntrypoint:          "",
		sgwModuleMetadataFile:     "",
		sgwThirdPartyLicensesFile: "",
		receipt.Runner.Path:       receipt.Runner.SHA256,
	}
	for path, digest := range required {
		if !safeModuleRelativePath(path) || receipt.Files[path] == "" {
			return errors.New("s-gw module file inventory is incomplete")
		}
		if digest != "" && receipt.Files[path] != digest {
			return errors.New("s-gw module runner identity is invalid")
		}
	}

	paths := make([]string, 0, len(receipt.Files))
	for relative := range receipt.Files {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	var total int64
	for _, relative := range paths {
		digest := receipt.Files[relative]
		if !safeModuleRelativePath(relative) || !validSHA256(digest) {
			return errors.New("s-gw module file inventory is invalid")
		}
		path := filepath.Join(packageRoot, filepath.FromSlash(relative))
		resolved, err := confinedExistingPath(path, packageRoot)
		if err != nil || resolved != path {
			return errors.New("s-gw module file path is invalid")
		}
		itemInfo, err := os.Lstat(path)
		if err != nil || !itemInfo.Mode().IsRegular() || itemInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("s-gw module file is invalid")
		}
		if err := requirePrivatePath(path, itemInfo); err != nil {
			return errors.New("s-gw module file is not private")
		}
		if relative == sgwThirdPartyLicensesFile && itemInfo.Size() == 0 {
			return errors.New("s-gw third-party license bundle is empty")
		}
		total += itemInfo.Size()
		if total > sgwModuleTotalBytes {
			return errors.New("s-gw module file inventory is too large")
		}
		actual, err := sha256File(path)
		if err != nil || actual != digest {
			return errors.New("s-gw module file integrity check failed")
		}
	}
	runnerPath := filepath.Join(packageRoot, filepath.FromSlash(receipt.Runner.Path))
	runnerInfo, err := os.Lstat(runnerPath)
	if err != nil || !runnerInfo.Mode().IsRegular() || runnerInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("s-gw module runner is invalid")
	}
	if runtime.GOOS != "windows" && runnerInfo.Mode().Perm()&0o111 == 0 {
		return errors.New("s-gw module runner is not executable")
	}
	if err := requireExactSGWFileInventory(packageRoot, receipt.Files); err != nil {
		return err
	}

	packageRaw, err := readBoundedFile(filepath.Join(packageRoot, "package.json"), sgwModuleReceiptLimit)
	if err != nil {
		return errors.New("s-gw module package metadata is invalid")
	}
	if rejectDuplicateJSONKeys(packageRaw) != nil {
		return errors.New("s-gw module package metadata is invalid")
	}
	var identity sgwPackageIdentity
	if json.Unmarshal(packageRaw, &identity) != nil ||
		identity.Name != sgwModulePackageName || identity.Version != sgwModulePackageVersion {
		return errors.New("s-gw module package metadata is invalid")
	}
	return nil
}

func validateSGWReceiptComponents(receipt *sgwModuleReceipt) error {
	required := []string{"runner", "credential_helper", "approval_ui", "license_bundle"}
	if len(receipt.Components) != len(required) {
		return errors.New("s-gw module component receipt is incomplete")
	}
	for _, name := range required {
		component, ok := receipt.Components[name]
		if !ok || !validSHA256(component.ArtifactSHA256) ||
			!validSHA256(component.InstalledSHA256) || component.Signature == "" ||
			!safeModuleRelativePath(component.Destination) || len(component.Files) == 0 ||
			!sort.StringsAreSorted(component.Files) {
			return errors.New("s-gw module component receipt is invalid")
		}
		seen := make(map[string]struct{}, len(component.Files))
		for _, relative := range component.Files {
			if !safeModuleRelativePath(relative) || receipt.Files[relative] == "" {
				return errors.New("s-gw module component inventory is invalid")
			}
			if _, duplicate := seen[relative]; duplicate {
				return errors.New("s-gw module component inventory is invalid")
			}
			seen[relative] = struct{}{}
		}
		if name != "approval_ui" {
			if len(component.Files) != 1 || component.Files[0] != component.Destination {
				return errors.New("s-gw module file component inventory is invalid")
			}
			if name == "license_bundle" && component.Destination != sgwThirdPartyLicensesFile {
				return errors.New("s-gw third-party license bundle destination is invalid")
			}
			continue
		}
		prefix := strings.TrimSuffix(component.Destination, "/") + "/"
		hasIndex := false
		hasAsset := false
		for _, relative := range component.Files {
			if !strings.HasPrefix(relative, prefix) {
				return errors.New("s-gw approval UI inventory is invalid")
			}
			hasIndex = hasIndex || relative == prefix+"index.html"
			hasAsset = hasAsset || strings.HasPrefix(relative, prefix+"assets/")
		}
		if !hasIndex || !hasAsset {
			return errors.New("s-gw approval UI inventory is incomplete")
		}
	}
	runner := receipt.Components["runner"]
	if len(runner.Files) != 1 || receipt.Runner.Path != runner.Files[0] ||
		receipt.Runner.SHA256 != receipt.Files[runner.Files[0]] {
		return errors.New("s-gw module runner identity is invalid")
	}
	return nil
}

func requireExactSGWFileInventory(packageRoot string, expected map[string]string) error {
	found := make(map[string]struct{}, len(expected))
	err := filepath.WalkDir(packageRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == packageRoot {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("s-gw module contains a symbolic link")
		}
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			return requirePrivatePath(path, info)
		}
		if !entry.Type().IsRegular() {
			return errors.New("s-gw module contains a non-regular file")
		}
		relative, err := filepath.Rel(packageRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if expected[relative] == "" {
			return errors.New("s-gw module contains an untracked file")
		}
		found[relative] = struct{}{}
		return nil
	})
	if err != nil || len(found) != len(expected) {
		return errors.New("s-gw module file inventory does not match the installation")
	}
	return nil
}

func sgwRuntimeTarget() string {
	osName := runtime.GOOS
	if osName == "windows" {
		osName = "win32"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return osName + "-" + arch
}

func confinedExistingPath(path, root string) (string, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(root) {
		return "", errors.New("path must be absolute")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes managed root")
	}
	return resolved, nil
}

func safeModuleRelativePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00") || filepath.IsAbs(path) {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	return clean == path && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func requirePrivateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("not a regular file")
	}
	return requirePrivatePath(path, info)
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("not a directory")
	}
	return requirePrivatePath(path, info)
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return raw, nil
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func sgwBrokerEnvironment(runnerPath string) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil, errors.New("resolve s-gw user home")
	}
	values := map[string]string{
		"SGW_AGENT_NAME":           "DefenseClaw",
		"SGW_DISABLE_UPDATE_CHECK": "1",
		"SGW_EXECUTION_ENGINE":     "rust",
		"SGW_HOME":                 filepath.Join(home, ".s-gw"),
	}
	if runtime.GOOS == "windows" {
		copySafeEnvironment(values, "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP")
		trusted, err := sgwWindowsExecutionEnvironment(runnerPath)
		if err != nil {
			return nil, err
		}
		for key, value := range trusted {
			values[key] = value
		}
	} else {
		values["HOME"] = home
		values["PATH"] = strings.Join([]string{
			"/usr/local/bin",
			"/usr/bin",
			"/bin",
			"/usr/sbin",
			"/sbin",
		}, string(os.PathListSeparator))
		copySafeEnvironment(values, "USER", "LOGNAME", "TMPDIR", "TMP", "TEMP")
		if runtime.GOOS == "linux" {
			copySafeEnvironment(values,
				"DBUS_SESSION_BUS_ADDRESS",
				"DISPLAY",
				"WAYLAND_DISPLAY",
				"XDG_RUNTIME_DIR",
				"XDG_SESSION_TYPE",
			)
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env, nil
}

func copySafeEnvironment(destination map[string]string, names ...string) {
	for _, name := range names {
		value := os.Getenv(name)
		if value == "" || strings.ContainsRune(value, '\x00') {
			continue
		}
		destination[name] = value
	}
}
