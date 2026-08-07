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
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const (
	sgwReleaseSignatureAlgorithm = "ed25519-sha256-v1"
	sgwComponentSignatureDomain  = "defenseclaw.s-gw.component-signature.v1"
	sgwModuleSignatureDomain     = "defenseclaw.s-gw.module-signature.v1"
	sgwRunnerContractDomain      = "defenseclaw.s-gw.runner-contract.v1"
	sgwRunnerLaunchDomain        = "defenseclaw.s-gw.runner-launch-admission.v1"
	sgwModuleMetadataFile        = "defenseclaw-module.json"
	sgwThirdPartyLicensesFile    = "THIRD_PARTY_LICENSES.txt"
)

var (
	sgwComponentInventoryDomain = []byte("DefenseClaw s-gw component inventory\x00v1\x00")
	sgwModuleInventoryDomain    = []byte("DefenseClaw s-gw module inventory\x00v1\x00")
)

type sgwSignaturePolicy struct {
	Algorithm       string `json:"algorithm"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

type sgwRunnerContract struct {
	SchemaVersion         int                    `json:"schema_version"`
	RuntimeContract       string                 `json:"runtime_contract"`
	Protocol              string                 `json:"protocol"`
	MCPArguments          []string               `json:"mcp_arguments"`
	ServerInfo            sgwRunnerServerInfo    `json:"server_info"`
	Tools                 []string               `json:"tools"`
	ConsoleArguments      []string               `json:"console_arguments"`
	ConsoleStatus         sgwRunnerConsoleStatus `json:"console_status"`
	ConsoleUIBinding      string                 `json:"console_ui_binding"`
	ConsoleBrowserHandoff string                 `json:"console_browser_handoff"`
	ApprovalMutations     string                 `json:"approval_mutations"`
	Capabilities          []string               `json:"capabilities"`
}

type sgwRunnerServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type sgwRunnerConsoleStatus struct {
	Schema   string   `json:"schema"`
	Fields   []string `json:"fields"`
	Statuses []string `json:"statuses"`
}

type sgwRunnerLaunchAdmission struct {
	SchemaVersion       int
	Mode                string
	SignatureScope      string
	DependencyPolicy    string
	PEMachine           string
	RequiredMitigations []string
	TeamID              string
	SigningID           string
	CDHash              string
	RequiredCSFlags     []string
}

func expectedSGWRunnerContract() sgwRunnerContract {
	return sgwRunnerContract{
		SchemaVersion:   1,
		RuntimeContract: "defenseclaw.s-gw.native-runtime.v1",
		Protocol:        "mcp-stdio-jsonrpc-2.0",
		MCPArguments:    []string{"mcp", "--profile", "defenseclaw-tokenizer", "--protocol-version", "1"},
		ServerInfo:      sgwRunnerServerInfo{Name: sgwRunnerServerName, Version: sgwRunnerVersion},
		Tools:           []string{sgwTokenizerToolName},
		ConsoleArguments: []string{
			"console", "open", "--protocol-version", "1",
		},
		ConsoleStatus: sgwRunnerConsoleStatus{
			Schema:   "defenseclaw.s-gw.console-status.v1",
			Fields:   []string{"schema_version", "status"},
			Statuses: []string{"opened", "already_open"},
		},
		ConsoleUIBinding:      "runner-verified-signed-inventory-snapshot-v1",
		ConsoleBrowserHandoff: "native-os-api-or-absolute-system-launcher-v1",
		ApprovalMutations:     "native-authenticated-user-presence-only",
		Capabilities: []string{
			"defenseclaw.native-tokenizer-mcp.v1",
			"defenseclaw.approval-console-session.v1",
			"defenseclaw.pending-enrollment.v1",
		},
	}
}

func validateSGWReleaseProof(receipt *sgwModuleReceipt, publicKeyPEM []byte, expectedFingerprint string) error {
	publicKey, fingerprint, err := parseSGWReleasePublicKey(publicKeyPEM)
	if err != nil || !validSHA256(expectedFingerprint) || fingerprint != expectedFingerprint {
		return errors.New("s-gw release trust anchor is unavailable")
	}
	if receipt.SignaturePolicy.Algorithm != sgwReleaseSignatureAlgorithm ||
		receipt.SignaturePolicy.PublicKeySHA256 != fingerprint {
		return errors.New("s-gw release signing policy is invalid")
	}
	if !reflect.DeepEqual(receipt.RunnerContract, expectedSGWRunnerContract()) {
		return errors.New("s-gw native runner contract is invalid")
	}
	contractDigest, err := sgwRunnerContractSHA256(receipt.RunnerContract)
	if err != nil || contractDigest != receipt.RunnerContractSHA256 {
		return errors.New("s-gw native runner contract digest is invalid")
	}
	launchAdmission, err := parseSGWRunnerLaunchAdmission(receipt.Target, receipt.RunnerLaunchAdmission)
	if err != nil {
		return errors.New("s-gw native runner launch admission is invalid")
	}
	launchDigest := sgwRunnerLaunchAdmissionSHA256(receipt.Target, launchAdmission)
	if launchDigest != receipt.RunnerLaunchAdmissionSHA256 {
		return errors.New("s-gw native runner launch admission digest is invalid")
	}
	receipt.runnerLaunch = launchAdmission

	moduleFiles := make(map[string]string, len(receipt.Files)-1)
	for relative, digest := range receipt.Files {
		if relative != sgwModuleMetadataFile {
			moduleFiles[relative] = digest
		}
	}
	installed, err := sgwInventorySHA256(moduleFiles, sgwModuleInventoryDomain)
	if err != nil || installed != receipt.ModuleInstalledSHA256 {
		return errors.New("s-gw signed module inventory is invalid")
	}
	payload := sgwModuleSignaturePayload(receipt, installed)
	if verifySGWEd25519(publicKey, receipt.ModuleSignature, payload) != nil {
		return errors.New("s-gw module signature is invalid")
	}

	for _, name := range []string{"runner", "credential_helper", "approval_ui", "license_bundle"} {
		component, ok := receipt.Components[name]
		if !ok {
			return errors.New("s-gw module component receipt is incomplete")
		}
		files := make(map[string]string, len(component.Files))
		for _, relative := range component.Files {
			files[relative] = receipt.Files[relative]
		}
		componentDigest, digestErr := sgwInventorySHA256(files, sgwComponentInventoryDomain)
		if digestErr != nil || componentDigest != component.InstalledSHA256 {
			return errors.New("s-gw component signed inventory is invalid")
		}
		componentPayload := sgwComponentSignaturePayload(receipt.Target, name, component)
		if verifySGWEd25519(publicKey, component.Signature, componentPayload) != nil {
			return errors.New("s-gw component signature is invalid")
		}
	}
	return nil
}

func parseSGWReleasePublicKey(value []byte) (ed25519.PublicKey, string, error) {
	if len(value) == 0 || len(value) > 1024 {
		return nil, "", errors.New("invalid release key")
	}
	block, rest := pem.Decode(value)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, "", errors.New("invalid release key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, "", errors.New("release key is not Ed25519")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, "", err
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if !bytes.Equal(value, canonical) {
		return nil, "", errors.New("release key is not canonical")
	}
	fingerprint := sha256.Sum256(canonical)
	return publicKey, hex.EncodeToString(fingerprint[:]), nil
}

func sgwInventorySHA256(files map[string]string, domain []byte) (string, error) {
	if len(files) == 0 || len(files) > sgwModuleFileLimit {
		return "", errors.New("invalid inventory")
	}
	paths := make([]string, 0, len(files))
	for relative := range files {
		paths = append(paths, relative)
	}
	sort.Strings(paths)
	digest := sha256.New()
	_, _ = digest.Write(domain)
	if err := writeSGWInventoryUint32(digest, len(paths)); err != nil {
		return "", err
	}
	for _, relative := range paths {
		fileDigest := files[relative]
		if !safeModuleRelativePath(relative) || !validSHA256(fileDigest) {
			return "", errors.New("invalid inventory entry")
		}
		encoded := []byte(relative)
		if err := writeSGWInventoryUint32(digest, len(encoded)); err != nil {
			return "", err
		}
		_, _ = digest.Write(encoded)
		raw, err := hex.DecodeString(fileDigest)
		if err != nil {
			return "", err
		}
		_, _ = digest.Write(raw)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func writeSGWInventoryUint32(destination hash.Hash, value int) error {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return errors.New("inventory value is too large")
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(value))
	_, err := destination.Write(raw[:])
	return err
}

func sgwComponentSignaturePayload(target, name string, component sgwReceiptComponent) []byte {
	return []byte(fmt.Sprintf(
		"%s\nschema_version=1\ntarget=%s\ncomponent=%s\ndestination=%s\nartifact_sha256=%s\ninstalled_sha256=%s\n",
		sgwComponentSignatureDomain,
		target,
		name,
		component.Destination,
		component.ArtifactSHA256,
		component.InstalledSHA256,
	))
}

func sgwModuleSignaturePayload(receipt *sgwModuleReceipt, installed string) []byte {
	return []byte(fmt.Sprintf(
		"%s\nschema_version=1\ntarget=%s\npackage_name=%s\npackage_version=%s\nupstream_revision=%s\nupstream_tree=%s\nrunner_contract_sha256=%s\nrunner_launch_admission_sha256=%s\ninstalled_sha256=%s\n",
		sgwModuleSignatureDomain,
		receipt.Target,
		receipt.PackageName,
		receipt.PackageVersion,
		receipt.UpstreamRevision,
		receipt.UpstreamTree,
		receipt.RunnerContractSHA256,
		receipt.RunnerLaunchAdmissionSHA256,
		installed,
	))
}

func sgwRunnerContractSHA256(contract sgwRunnerContract) (string, error) {
	value := map[string]any{
		"approval_mutations":      contract.ApprovalMutations,
		"capabilities":            contract.Capabilities,
		"console_arguments":       contract.ConsoleArguments,
		"console_browser_handoff": contract.ConsoleBrowserHandoff,
		"console_status": map[string]any{
			"fields":   contract.ConsoleStatus.Fields,
			"schema":   contract.ConsoleStatus.Schema,
			"statuses": contract.ConsoleStatus.Statuses,
		},
		"console_ui_binding": contract.ConsoleUIBinding,
		"mcp_arguments":      contract.MCPArguments,
		"protocol":           contract.Protocol,
		"runtime_contract":   contract.RuntimeContract,
		"schema_version":     contract.SchemaVersion,
		"server_info": map[string]any{
			"name":    contract.ServerInfo.Name,
			"version": contract.ServerInfo.Version,
		},
		"tools": contract.Tools,
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	payload := append([]byte(sgwRunnerContractDomain+"\n"), canonical...)
	payload = append(payload, '\n')
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

func parseSGWRunnerLaunchAdmission(target string, raw json.RawMessage) (sgwRunnerLaunchAdmission, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || rejectDuplicateJSONKeys(raw) != nil {
		return sgwRunnerLaunchAdmission{}, errors.New("runner launch admission is missing")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return sgwRunnerLaunchAdmission{}, errors.New("runner launch admission is invalid")
	}
	common := []string{"dependency_policy", "mode", "schema_version", "signature_scope"}
	expected := append([]string(nil), common...)
	if strings.HasPrefix(target, "win32-") {
		expected = append(expected, "pe_machine", "required_mitigations")
	} else if strings.HasPrefix(target, "darwin-") {
		expected = append(expected, "cdhash", "required_cs_flags", "signing_id", "team_id")
	} else if !strings.HasPrefix(target, "linux-") {
		return sgwRunnerLaunchAdmission{}, errors.New("runner launch target is invalid")
	}
	sort.Strings(expected)
	actual := make([]string, 0, len(fields))
	for name := range fields {
		actual = append(actual, name)
	}
	sort.Strings(actual)
	if !reflect.DeepEqual(actual, expected) {
		return sgwRunnerLaunchAdmission{}, errors.New("runner launch fields are invalid")
	}

	var decoded struct {
		SchemaVersion       int      `json:"schema_version"`
		Mode                string   `json:"mode"`
		SignatureScope      string   `json:"signature_scope"`
		DependencyPolicy    string   `json:"dependency_policy"`
		PEMachine           string   `json:"pe_machine"`
		RequiredMitigations []string `json:"required_mitigations"`
		TeamID              string   `json:"team_id"`
		SigningID           string   `json:"signing_id"`
		CDHash              string   `json:"cdhash"`
		RequiredCSFlags     []string `json:"required_cs_flags"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || decoded.SchemaVersion != 1 ||
		decoded.SignatureScope != "installed-runner-bytes" || decoded.DependencyPolicy != "system-only-v1" {
		return sgwRunnerLaunchAdmission{}, errors.New("runner launch common fields are invalid")
	}
	admission := sgwRunnerLaunchAdmission{
		SchemaVersion: decoded.SchemaVersion, Mode: decoded.Mode,
		SignatureScope: decoded.SignatureScope, DependencyPolicy: decoded.DependencyPolicy,
		PEMachine: decoded.PEMachine, RequiredMitigations: decoded.RequiredMitigations,
		TeamID: decoded.TeamID, SigningID: decoded.SigningID, CDHash: decoded.CDHash,
		RequiredCSFlags: decoded.RequiredCSFlags,
	}
	switch {
	case strings.HasPrefix(target, "linux-"):
		if admission.Mode != "linux-sealed-memfd-v1" {
			return sgwRunnerLaunchAdmission{}, errors.New("Linux runner launch mode is invalid")
		}
	case strings.HasPrefix(target, "win32-"):
		machine := "arm64"
		if strings.HasSuffix(target, "-x64") {
			machine = "x86_64"
		}
		mitigations := []string{
			"block-non-microsoft-binaries",
			"image-load-no-remote",
			"image-load-no-low-label",
		}
		if admission.Mode != "windows-locked-image-v1" || admission.PEMachine != machine ||
			!reflect.DeepEqual(admission.RequiredMitigations, mitigations) {
			return sgwRunnerLaunchAdmission{}, errors.New("Windows runner launch policy is invalid")
		}
	case strings.HasPrefix(target, "darwin-"):
		teamPattern := regexp.MustCompile(`^[A-Z0-9]{10}$`)
		signingPattern := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
		cdhashPattern := regexp.MustCompile(`^[0-9a-f]{40}$`)
		if admission.Mode != "darwin-running-code-v1" || !teamPattern.MatchString(admission.TeamID) ||
			!signingPattern.MatchString(admission.SigningID) || !cdhashPattern.MatchString(admission.CDHash) ||
			!reflect.DeepEqual(admission.RequiredCSFlags, []string{"valid", "hard", "kill", "runtime"}) {
			return sgwRunnerLaunchAdmission{}, errors.New("macOS runner launch identity is invalid")
		}
	}
	return admission, nil
}

func sgwRunnerLaunchAdmissionSHA256(target string, admission sgwRunnerLaunchAdmission) string {
	payload := fmt.Sprintf(
		"%s\nschema_version=1\ntarget=%s\nmode=%s\nsignature_scope=%s\ndependency_policy=%s\npe_machine=%s\nrequired_mitigations=%s\nteam_id=%s\nsigning_id=%s\ncdhash=%s\nrequired_cs_flags=%s\n",
		sgwRunnerLaunchDomain,
		target,
		admission.Mode,
		admission.SignatureScope,
		admission.DependencyPolicy,
		admission.PEMachine,
		strings.Join(admission.RequiredMitigations, ","),
		admission.TeamID,
		admission.SigningID,
		admission.CDHash,
		strings.Join(admission.RequiredCSFlags, ","),
	)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

func verifySGWEd25519(publicKey ed25519.PublicKey, encoded string, payload []byte) error {
	if encoded == "" {
		return errors.New("signature is empty")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(raw) != encoded {
		return errors.New("signature encoding is invalid")
	}
	if !ed25519.Verify(publicKey, payload, raw) {
		return errors.New("signature verification failed")
	}
	return nil
}
