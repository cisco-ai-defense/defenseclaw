// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/windowsresources"
)

func TestResourceToolCrossArchitectureContract(t *testing.T) {
	repositoryRoot := resourceToolRepositoryRoot(t)
	temporaryRoot := t.TempDir()
	toolName := "windowsresources"
	if runtime.GOOS == "windows" {
		toolName += ".exe"
	}
	resourceTool := filepath.Join(temporaryRoot, toolName)
	buildGoCommand(t, repositoryRoot, nil, resourceTool, "./internal/tools/windowsresources")
	icon := filepath.Join(repositoryRoot, filepath.FromSlash(windowsresources.IconSource))

	type architectureCase struct {
		target  windowsresources.Target
		goarch  string
		machine uint16
		path    string
	}
	cases := []architectureCase{
		{
			target:  windowsresources.TargetWindowsAMD64,
			goarch:  "amd64",
			machine: pe.IMAGE_FILE_MACHINE_AMD64,
		},
		{
			target:  windowsresources.TargetWindowsARM64,
			goarch:  "arm64",
			machine: pe.IMAGE_FILE_MACHINE_ARM64,
		},
	}

	for index := range cases {
		current := &cases[index]
		current.path = filepath.Join(temporaryRoot, "defenseclaw-"+current.goarch+".exe")
		buildGoCommand(
			t,
			repositoryRoot,
			[]string{"GOOS=windows", "GOARCH=" + current.goarch, "CGO_ENABLED=0"},
			current.path,
			"./cmd/defenseclaw",
		)
		assertPEMachine(t, current.path, current.machine)
	}

	for index := range cases {
		current := cases[index]
		wrong := cases[(index+1)%len(cases)]
		t.Run("mismatch_"+current.goarch+"_as_"+wrong.goarch, func(t *testing.T) {
			before := fileSHA256(t, current.path)
			output, err := runResourceTool(
				repositoryRoot,
				resourceTool,
				wrong.target,
				current.path,
				icon,
				false,
			)
			if err == nil {
				t.Fatalf("resource application accepted %s PE as %s:\n%s", current.goarch, wrong.target, output)
			}
			if !bytes.Contains(output, []byte("PE machine is")) ||
				!bytes.Contains(output, []byte("requested target "+string(wrong.target))) {
				t.Fatalf("resource application mismatch error is not explicit:\n%s", output)
			}
			if after := fileSHA256(t, current.path); after != before {
				t.Fatal("architecture-mismatch application changed the executable")
			}
			assertNoResourceTemporaryFiles(t, current.path)

			output, err = runResourceTool(
				repositoryRoot,
				resourceTool,
				wrong.target,
				current.path,
				icon,
				true,
			)
			if err == nil {
				t.Fatalf("resource verification accepted %s PE as %s:\n%s", current.goarch, wrong.target, output)
			}
			if !bytes.Contains(output, []byte("PE machine is")) ||
				!bytes.Contains(output, []byte("requested target "+string(wrong.target))) {
				t.Fatalf("resource verification mismatch error is not explicit:\n%s", output)
			}
			if after := fileSHA256(t, current.path); after != before {
				t.Fatal("architecture-mismatch verification changed the executable")
			}
		})
	}

	for _, current := range cases {
		current := current
		t.Run("apply_and_verify_"+current.goarch, func(t *testing.T) {
			metadataBefore := goVersionMetadata(t, current.path)
			if !bytes.Contains(metadataBefore, []byte("github.com/defenseclaw/defenseclaw")) {
				t.Fatalf("gateway omitted Go module metadata:\n%s", metadataBefore)
			}
			if output, err := runResourceTool(
				repositoryRoot,
				resourceTool,
				current.target,
				current.path,
				icon,
				false,
			); err != nil {
				t.Fatalf("apply %s resources: %v\n%s", current.target, err, output)
			}
			if output, err := runResourceTool(
				repositoryRoot,
				resourceTool,
				current.target,
				current.path,
				icon,
				true,
			); err != nil {
				t.Fatalf("verify %s resources: %v\n%s", current.target, err, output)
			}
			assertPEMachine(t, current.path, current.machine)
			if metadataAfter := goVersionMetadata(t, current.path); !bytes.Equal(metadataAfter, metadataBefore) {
				t.Fatalf(
					"%s resource mutation changed go version -m metadata\nbefore:\n%s\nafter:\n%s",
					current.target,
					metadataBefore,
					metadataAfter,
				)
			}
		})
	}

	t.Run("signed_executable_refusal", func(t *testing.T) {
		signedPath := filepath.Join(temporaryRoot, "defenseclaw-amd64-signed-indicator.exe")
		copyFile(t, cases[0].path, signedPath)
		markAuthenticodeDirectory(t, signedPath)
		before := fileSHA256(t, signedPath)
		output, err := runResourceTool(
			repositoryRoot,
			resourceTool,
			windowsresources.TargetWindowsAMD64,
			signedPath,
			icon,
			false,
		)
		if err == nil {
			t.Fatalf("resource application accepted an Authenticode directory:\n%s", output)
		}
		if !bytes.Contains(output, []byte("refusing to modify resources after Authenticode signing")) {
			t.Fatalf("signed executable refusal is not explicit:\n%s", output)
		}
		if after := fileSHA256(t, signedPath); after != before {
			t.Fatal("signed executable refusal changed the executable")
		}
		assertNoResourceTemporaryFiles(t, signedPath)
	})
}

func resourceToolRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve resource integration test path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
}

func buildGoCommand(t *testing.T, root string, overrides []string, output, packagePath string) {
	t.Helper()
	arguments := []string{
		"build",
		"-trimpath",
		"-buildvcs=false",
		"-ldflags=-s -w -buildid=windows-resource-integration",
		"-o",
		output,
		packagePath,
	}
	command := exec.Command("go", arguments...)
	command.Dir = root
	if len(overrides) > 0 {
		command.Env = environmentWithOverrides(os.Environ(), overrides)
	}
	if combined, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", packagePath, err, combined)
	}
}

func environmentWithOverrides(environment, overrides []string) []string {
	overridden := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		key, _, _ := strings.Cut(override, "=")
		overridden[strings.ToUpper(key)] = struct{}{}
	}
	result := make([]string, 0, len(environment)+len(overrides))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if _, ok := overridden[strings.ToUpper(key)]; !ok {
			result = append(result, entry)
		}
	}
	return append(result, overrides...)
}

func runResourceTool(
	root, tool string,
	target windowsresources.Target,
	executable, icon string,
	verifyOnly bool,
) ([]byte, error) {
	arguments := []string{
		"-target", string(target),
		"-executable", executable,
		"-component", "gateway",
		"-version", "1.2.3",
		"-icon", icon,
	}
	if verifyOnly {
		arguments = append(arguments, "-verify-only")
	}
	command := exec.Command(tool, arguments...)
	command.Dir = root
	return command.CombinedOutput()
}

func assertPEMachine(t *testing.T, executable string, want uint16) {
	t.Helper()
	parsed, err := pe.Open(executable)
	if err != nil {
		t.Fatalf("parse %s: %v", executable, err)
	}
	machine := parsed.Machine
	if err := parsed.Close(); err != nil {
		t.Fatalf("close %s: %v", executable, err)
	}
	if machine != want {
		t.Fatalf("PE machine for %s = %#x, want %#x", executable, machine, want)
	}
}

func goVersionMetadata(t *testing.T, executable string) []byte {
	t.Helper()
	command := exec.Command("go", "version", "-m", executable)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("read Go build metadata from %s: %v\n%s", executable, err, output)
	}
	return output
}

func fileSHA256(t *testing.T, path string) [sha256.Size]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if copyErr != nil {
		t.Fatal(copyErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func assertNoResourceTemporaryFiles(t *testing.T, executable string) {
	t.Helper()
	pattern := filepath.Join(filepath.Dir(executable), "."+filepath.Base(executable)+".resources-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("resource refusal left temporary outputs: %v", matches)
	}
}

func copyFile(t *testing.T, source, destination string) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, contents, info.Mode()); err != nil {
		t.Fatal(err)
	}
}

func markAuthenticodeDirectory(t *testing.T, executable string) {
	t.Helper()
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) < 0x40 {
		t.Fatal("PE is too short for a DOS header")
	}
	peOffset := int(binary.LittleEndian.Uint32(contents[0x3c:0x40]))
	optionalHeaderOffset := peOffset + 4 + 20
	if optionalHeaderOffset+2 > len(contents) {
		t.Fatal("PE is too short for an optional header")
	}
	var dataDirectoryOffset int
	switch magic := binary.LittleEndian.Uint16(contents[optionalHeaderOffset : optionalHeaderOffset+2]); magic {
	case 0x10b:
		dataDirectoryOffset = optionalHeaderOffset + 96
	case 0x20b:
		dataDirectoryOffset = optionalHeaderOffset + 112
	default:
		t.Fatalf("unsupported PE optional-header magic %#x", magic)
	}
	securityDirectoryOffset := dataDirectoryOffset + pe.IMAGE_DIRECTORY_ENTRY_SECURITY*8
	if securityDirectoryOffset+8 > len(contents) {
		t.Fatal("PE is too short for an Authenticode directory entry")
	}
	if uint64(len(contents)) > uint64(^uint32(0)) {
		t.Fatal("PE is too large for a 32-bit Authenticode file offset")
	}
	binary.LittleEndian.PutUint32(contents[securityDirectoryOffset:], uint32(len(contents)))
	binary.LittleEndian.PutUint32(contents[securityDirectoryOffset+4:], 8)
	info, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, contents, info.Mode()); err != nil {
		t.Fatal(err)
	}
}

func TestEnvironmentWithOverridesReplacesArchitectureKeys(t *testing.T) {
	actual := environmentWithOverrides(
		[]string{"Path=example", "GOOS=linux", "goarch=386", "CGO_ENABLED=1"},
		[]string{"GOOS=windows", "GOARCH=arm64", "CGO_ENABLED=0"},
	)
	want := []string{"Path=example", "GOOS=windows", "GOARCH=arm64", "CGO_ENABLED=0"}
	if fmt.Sprint(actual) != fmt.Sprint(want) {
		t.Fatalf("environment = %v, want %v", actual, want)
	}
}
