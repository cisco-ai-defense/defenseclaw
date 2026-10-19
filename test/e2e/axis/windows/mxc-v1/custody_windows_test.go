// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func syntheticReceipt(t *testing.T) (string, receipt) {
	t.Helper()
	root := t.TempDir()
	artifact := filepath.Join(root, "artifact")
	binary := filepath.Join(artifact, filepath.FromSlash(binaryName))
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("synthetic bytes; never executed")
	if err := os.WriteFile(binary, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifact, filepath.FromSlash(loaderName)), content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	no := false
	value := receipt{Verified: true, ExecutionPerformed: &no, ProductionCertification: &no,
		Scope: diagnosticScope, Variant: diagnosticVariant, Axis: "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c",
		MXC: "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2", BuildCommit: strings.Repeat("a", 40),
		BuildRun: 123, ArtifactID: 456, Archive: strings.Repeat("b", 64), Provenance: strings.Repeat("c", 64),
		Lock: combinedLock, Artifact: artifact, Binary: binaryName, BinarySHA: hex.EncodeToString(digest[:]), BinarySize: int64(len(content))}
	value.Binaries = []component{{Path: binaryName, SHA256: value.BinarySHA, Size: value.BinarySize}, {Path: loaderName, SHA256: value.BinarySHA, Size: value.BinarySize}}
	return filepath.Join(root, "receipt.json"), value
}

func writeReceipt(t *testing.T, path string, value receipt, extra []byte) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, extra...)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func syntheticBoundaryReceipt(t *testing.T) (string, receipt) {
	t.Helper()
	path, value := syntheticReceipt(t)
	content, err := os.ReadFile(filepath.Join(value.Artifact, filepath.FromSlash(binaryName)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(boundaryName)), content, 0600); err != nil {
		t.Fatal(err)
	}
	value.Scope, value.Variant = boundaryScope, boundaryVariant
	value.Binaries = append(value.Binaries, component{Path: boundaryName, SHA256: value.BinarySHA, Size: value.BinarySize})
	return path, value
}

func TestNativeIdentityReceiptMatchesVerifierAuthority(t *testing.T) {
	// Read the actual peer-language constants, rather than deriving the fixture
	// from Go's constants alone: that missed the native-identity scope change.
	source, err := os.ReadFile("verify_live_artifact.py")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"BOUNDARY_VARIANT": "standalone_std_boundary_native_identity_environment",
		"BOUNDARY_SCOPE":   "fixed_windows_native_psec_boundary_native_identity_environment",
	}
	for name, expected := range want {
		matches := regexp.MustCompile(`(?m)^`+name+` = "([^"\r\n]+)"\r?$`).FindAllSubmatch(source, -1)
		if len(matches) != 1 || string(matches[0][1]) != expected {
			t.Fatalf("verifier %s differs from the exact native-identity contract", name)
		}
	}
	if boundaryVariant != want["BOUNDARY_VARIANT"] || boundaryScope != want["BOUNDARY_SCOPE"] {
		t.Fatal("custody and verifier native-identity authority differ")
	}
	path, value := syntheticBoundaryReceipt(t)
	// Use the independent exact values above in the serialized receipt.
	value.Variant, value.Scope = want["BOUNDARY_VARIANT"], want["BOUNDARY_SCOPE"]
	pin := writeReceipt(t, path, value, nil)
	_, images, err := checkedReceipt(path, pin, "standalone-boundary")
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 3 {
		images.Close()
		t.Fatal("native-identity receipt did not pin all three synthetic images")
	}
	if err := images.Close(); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range [][2]string{
		{"standalone_std_boundary_literal_argv", value.Scope},
		{value.Variant, "fixed_windows_native_psec_boundary_literal_argv"},
		{"standalone_std_boundary_literal_argv", "fixed_windows_native_psec_boundary_literal_argv"},
	} {
		changed := value
		changed.Variant, changed.Scope = legacy[0], legacy[1]
		pin = writeReceipt(t, path, changed, nil)
		if _, images, err := checkedReceipt(path, pin, "standalone-boundary"); err == nil {
			images.Close()
			t.Fatal("a historical literal-only receipt selected native-identity custody")
		}
	}
}

func TestModesRequireExactlyOneExplicitChoice(t *testing.T) {
	for mask := 0; mask < 32; mask++ {
		var flags [5]bool
		count := 0
		for bit := range flags {
			flags[bit] = mask&(1<<bit) != 0
			if flags[bit] {
				count++
			}
		}
		got, err := selectedMode(flags[0], flags[1], flags[2], flags[3], flags[4])
		if (err == nil) != (count == 1) {
			t.Fatalf("mode selection mask %d: %q %v", mask, got, err)
		}
		if count == 1 {
			for index, name := range []string{"loader-only", "standalone-boundary", "dll-startup-only", "claude-version-only", "claude-create-control-only"} {
				if flags[index] && got != name {
					t.Fatalf("mode %d differs: %q", index, got)
				}
			}
		}
	}
}

func TestDLLReceiptMatchesVerifierAndRequiresAllFourImages(t *testing.T) {
	source, err := os.ReadFile("verify_live_artifact.py")
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]string{"DLL_VARIANT": dllVariant, "DLL_SCOPE": dllScope, "DLL_BINARY": dllName} {
		matches := regexp.MustCompile(`(?m)^`+name+` = "([^"\r\n]+)"\r?$`).FindAllSubmatch(source, -1)
		if len(matches) != 1 || string(matches[0][1]) != expected {
			t.Fatalf("verifier and custody DLL %s differ", name)
		}
	}
	path, value := syntheticBoundaryReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "dll-startup-only"); err == nil {
		images.Close()
		t.Fatal("three-image identity receipt admitted as DLL diagnostic")
	}
	value.Scope, value.Variant = dllScope, dllVariant
	pin = writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "dll-startup-only"); err == nil {
		images.Close()
		t.Fatal("DLL receipt without its fourth image admitted")
	}
	content := []byte("synthetic bytes; never executed")
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(dllName)), content, 0600); err != nil {
		t.Fatal(err)
	}
	value.Binaries = append(value.Binaries, component{Path: dllName, SHA256: value.BinarySHA, Size: value.BinarySize})
	pin = writeReceipt(t, path, value, nil)
	_, images, err := checkedReceipt(path, pin, "dll-startup-only")
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 4 {
		images.Close()
		t.Fatal("DLL receipt did not hold all four images")
	}
	if file, err := os.OpenFile(filepath.Join(value.Artifact, filepath.FromSlash(dllName)), os.O_WRONLY, 0); err == nil {
		file.Close()
		images.Close()
		t.Fatal("fourth image permits writes while pinned")
	}
	if err := images.Close(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"loader-only", "standalone-boundary"} {
		if _, images, err := checkedReceipt(path, pin, mode); err == nil {
			images.Close()
			t.Fatal("DLL receipt admitted under a historical mode")
		}
	}
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(dllName)), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, images, err := checkedReceipt(path, pin, "dll-startup-only"); err == nil {
		images.Close()
		t.Fatal("tampered fourth image admitted")
	}
}

func TestBoundaryReceiptRequiresItsOwnModeAndAllThreeImages(t *testing.T) {
	path, value := syntheticBoundaryReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		images.Close()
		t.Fatal("boundary accepted as loader")
	}
	_, images, err := checkedReceipt(path, pin, "standalone-boundary")
	if err != nil {
		t.Fatal(err)
	}
	defer images.Close()
	if len(images) != 3 {
		t.Fatal("complete boundary bundle is not held")
	}
	if file, err := os.OpenFile(filepath.Join(value.Artifact, filepath.FromSlash(boundaryName)), os.O_WRONLY, 0); err == nil {
		file.Close()
		t.Fatal("third image can be overwritten while pinned")
	}
}

func TestBoundaryRejectsMissingOrTamperedThirdImage(t *testing.T) {
	path, value := syntheticBoundaryReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(boundaryName)), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, images, err := checkedReceipt(path, pin, "standalone-boundary"); err == nil {
		images.Close()
		t.Fatal("changed third image accepted")
	}
	value.Binaries = value.Binaries[:2]
	pin = writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "standalone-boundary"); err == nil {
		images.Close()
		t.Fatal("missing third image accepted")
	}
}

func TestReceiptMustBeIndependentlyPinned(t *testing.T) {
	path, value := syntheticReceipt(t)
	writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, strings.Repeat("0", 64), "loader-only"); err == nil {
		image.Close()
		t.Fatal("changed receipt accepted")
	}
}

func TestMissingExplicitNonExecutionEvidenceRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.ExecutionPerformed = nil
	pin := writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("missing false execution evidence accepted")
	}
}

func TestDifferentCombinedLockRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Lock = strings.Repeat("d", 64)
	pin := writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("unreviewed lock accepted")
	}
}

func TestTrailingJSONRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, []byte("\n{}"))
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("trailing JSON accepted")
	}
}

func TestChangedBinaryRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(binaryName)), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("changed binary accepted")
	}
}

func TestBothDiagnosticImagesAreRequired(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Binaries = value.Binaries[:1]
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		images.Close()
		t.Fatal("missing loader image accepted")
	}
}

func TestHeadlessReceiptCannotBecomeLoaderDiagnostic(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Scope = "fixed_windows_native_psec_only_headless"
	value.Variant = ""
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		images.Close()
		t.Fatal("historical headless variant accepted as loader diagnostic")
	}
}

func TestVerifiedImageRemainsPinnedAgainstWrites(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	_, image, err := checkedReceipt(path, pin, "loader-only")
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	binary := filepath.Join(value.Artifact, filepath.FromSlash(binaryName))
	if err := os.WriteFile(binary, []byte("must not replace reviewed image"), 0600); err == nil {
		t.Fatal("verified image allowed writes while pinned")
	}
}

func TestClaudeReceiptHasSeparateAuthorityAndKeepsCIBinaryBounds(t *testing.T) {
	source, err := os.ReadFile("verify_live_artifact.py")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"CLAUDE_VARIANT": claudeArtifactVariant, "CLAUDE_SCOPE": claudeArtifactScope} {
		m := regexp.MustCompile(`(?m)^`+name+` = "([^"\r\n]+)"\r?$`).FindAllSubmatch(source, -1)
		if len(m) != 1 || string(m[0][1]) != want {
			t.Fatalf("fixed Claude %s authority differs", name)
		}
	}
	path, value := syntheticBoundaryReceipt(t)
	data := []byte("synthetic bytes; never executed")
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(dllName)), data, 0600); err != nil {
		t.Fatal(err)
	}
	value.Binaries = append(value.Binaries, component{Path: dllName, SHA256: value.BinarySHA, Size: value.BinarySize})
	value.Variant, value.Scope = claudeArtifactVariant, claudeArtifactScope
	pin := writeReceipt(t, path, value, nil)
	_, held, err := checkedReceipt(path, pin, "claude-version-only")
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 4 {
		t.Fatal("fixed Claude receipt did not retain all four CI images")
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"loader-only", "standalone-boundary", "dll-startup-only"} {
		if _, held, err := checkedReceipt(path, pin, mode); err == nil {
			held.Close()
			t.Fatal("Claude receipt admitted as another slice")
		}
	}
	for _, identity := range [][2]string{{dllVariant, dllScope}, {boundaryVariant, boundaryScope}} {
		changed := value
		changed.Variant, changed.Scope = identity[0], identity[1]
		pin := writeReceipt(t, path, changed, nil)
		if _, held, err := checkedReceipt(path, pin, "claude-version-only"); err == nil {
			held.Close()
			t.Fatal("historical artifact admitted as Claude slice")
		}
	}
	changed := value
	changed.Binaries = append([]component(nil), value.Binaries...)
	changed.Binaries[0].Size = claudeImageSize
	pin = writeReceipt(t, path, changed, nil)
	if _, held, err := checkedReceipt(path, pin, "claude-version-only"); err == nil {
		held.Close()
		t.Fatal("local large-image exception widened the CI artifact bound")
	}
}

func TestUncontainedCreateControlReceiptNeverCrossAdmitsPSEC(t *testing.T) {
	source, err := os.ReadFile("verify_live_artifact.py")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"CONTROL_VARIANT": claudeControlVariant, "CONTROL_SCOPE": claudeControlScope} {
		m := regexp.MustCompile(`(?m)^`+name+` = "([^"\r\n]+)"\r?$`).FindAllSubmatch(source, -1)
		if len(m) != 1 || string(m[0][1]) != want {
			t.Fatalf("control %s differs", name)
		}
	}
	path, value := syntheticBoundaryReceipt(t)
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(dllName)), []byte("synthetic bytes; never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	value.Binaries = append(value.Binaries, component{Path: dllName, SHA256: value.BinarySHA, Size: value.BinarySize})
	value.Variant, value.Scope = claudeControlVariant, claudeControlScope
	value.ProbeCargoFeatures = []string{"fixed-claude-create-control"}
	pin := writeReceipt(t, path, value, nil)
	_, held, err := checkedReceipt(path, pin, "claude-create-control-only")
	if err != nil {
		t.Fatal(err)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	for _, features := range [][]string{nil, {}, {"unreviewed"}, {"fixed-claude-create-control", "fixed-claude-create-control"}} {
		changed := value
		changed.ProbeCargoFeatures = features
		changedPin := writeReceipt(t, path, changed, nil)
		if _, images, err := checkedReceipt(path, changedPin, "claude-create-control-only"); err == nil {
			images.Close()
			t.Fatal("control without exact feature evidence admitted")
		}
	}
	pin = writeReceipt(t, path, value, nil)
	for _, mode := range []string{"loader-only", "standalone-boundary", "dll-startup-only", "claude-version-only"} {
		if _, held, err := checkedReceipt(path, pin, mode); err == nil {
			held.Close()
			t.Fatalf("control admitted as %s", mode)
		}
	}
	for _, identity := range [][2]string{{claudeArtifactVariant, claudeArtifactScope}, {claudeControlVariant, claudeArtifactScope}, {claudeArtifactVariant, claudeControlScope}} {
		changed := value
		changed.Variant, changed.Scope = identity[0], identity[1]
		pin := writeReceipt(t, path, changed, nil)
		if _, held, err := checkedReceipt(path, pin, "claude-create-control-only"); err == nil {
			held.Close()
			t.Fatal("PSEC or mixed identity admitted as control")
		}
	}
}
