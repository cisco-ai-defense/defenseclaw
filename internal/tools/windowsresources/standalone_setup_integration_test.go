// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
	"github.com/defenseclaw/defenseclaw/internal/windowsresources"
)

// rel-1-0-6:GAP-0296: the standalone enterprise Setup shipped with no
// VERSIONINFO, so MDM file-version detection and the management sidecar
// could not tell which release it was. build-setup.sh now stamps the outer
// Setup before it appends the payload trailer and reads it back after. This
// test runs those two tool calls on a real cross-built Setup with a trailer
// appended, and reads the version strings Windows Explorer and
// (Get-Item <exe>).VersionInfo show.
func TestStandaloneSetupVersionInfoSurvivesThePayloadTrailer(t *testing.T) {
	repositoryRoot := resourceToolRepositoryRoot(t)
	temporaryRoot := t.TempDir()
	toolName := "windowsresources"
	if runtime.GOOS == "windows" {
		toolName += ".exe"
	}
	resourceTool := filepath.Join(temporaryRoot, toolName)
	buildGoCommand(t, repositoryRoot, nil, resourceTool, "./internal/tools/windowsresources")
	icon := filepath.Join(repositoryRoot, filepath.FromSlash(windowsresources.IconSource))
	setup := filepath.Join(temporaryRoot, "DefenseClawSetup-Enterprise-Standalone-x64.exe")
	buildGoCommand(t, repositoryRoot,
		[]string{"GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0"},
		setup, "./cmd/defenseclaw-enterprise-setup")

	const releaseVersion = "1.0.7"
	run := func(extra ...string) ([]byte, error) {
		arguments := append([]string{
			"-target", "windows_amd64",
			"-executable", setup,
			"-component", "enterprise-setup-standalone",
			"-version", releaseVersion,
			"-icon", icon,
		}, extra...)
		command := exec.Command(resourceTool, arguments...)
		command.Dir = repositoryRoot
		return command.CombinedOutput()
	}

	// The 1.0.5 and 1.0.6 Setup: no resources, so the release check fails.
	if output, err := run("-verify-only"); err == nil {
		t.Fatalf("an unstamped Setup passed the version check:\n%s", output)
	}
	if output, err := run(); err != nil {
		t.Fatalf("stamp the Setup: %v\n%s", err, output)
	}
	// The assembler appends the real [archive][manifest][footer] trailer
	// after the stamped PE image; the Setup must still find its payload.
	entries := []setuppayload.Entry{{Name: "defenseclaw.exe", Contents: bytes.Repeat([]byte("payload"), 4096)}}
	trailerManifest := []byte(`{"version":"` + releaseVersion + `"}`)
	file, err := os.OpenFile(setup, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := setuppayload.WriteTrailer(file, entries, trailerManifest); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	read, err := setuppayload.ReadFile(setup)
	if err != nil {
		t.Fatalf("read the payload trailer of the stamped Setup: %v", err)
	}
	if !bytes.Equal(read.Manifest, trailerManifest) || len(read.Entries) != 1 ||
		read.Entries[0].Name != entries[0].Name || !bytes.Equal(read.Entries[0].Contents, entries[0].Contents) {
		t.Fatalf("payload trailer did not round-trip on the stamped Setup: manifest %q, %d entries", read.Manifest, len(read.Entries))
	}
	if output, err := run("-verify-only"); err != nil {
		t.Fatalf("the stamped Setup with its trailer failed the version check: %v\n%s", err, output)
	}
	// The release signs the outer Setup after the trailer; the read-back
	// runs on the signed file.
	markAuthenticodeDirectory(t, setup)
	if output, err := run("-verify-only"); err != nil {
		t.Fatalf("the signed Setup failed the version check: %v\n%s", err, output)
	}
	if output, err := run("-verify-only", "-component", "enterprise-setup"); err == nil {
		t.Fatalf("the standalone Setup passed as the Secure Client Setup:\n%s", output)
	}

	info := readVersionInfo(t, setup)
	if got, want := info.FileVersion, [4]uint16{1, 0, 7, 0}; got != want {
		t.Errorf("fixed FileVersion = %v, want %v", got, want)
	}
	if got, want := info.ProductVersion, [4]uint16{1, 0, 7, 0}; got != want {
		t.Errorf("fixed ProductVersion = %v, want %v", got, want)
	}
	values := versionStrings(t, info)
	for key, want := range map[string]string{
		version.ProductVersion:   releaseVersion,
		version.FileVersion:      releaseVersion,
		version.ProductName:      "Cisco DefenseClaw",
		version.CompanyName:      "Cisco Systems, Inc.",
		version.FileDescription:  "DefenseClaw Enterprise Setup",
		version.OriginalFilename: "DefenseClawSetup-Enterprise-Standalone-x64.exe",
	} {
		if got := values[key]; got != want {
			t.Errorf("VERSIONINFO %s = %q, want %q", key, got, want)
		}
	}
}

func readVersionInfo(t *testing.T, executable string) *version.Info {
	t.Helper()
	file, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	resources, err := winres.LoadFromEXESingleType(file, winres.RT_VERSION)
	if err != nil {
		t.Fatalf("load VERSIONINFO: %v", err)
	}
	var data []byte
	resources.Walk(func(_, _ winres.Identifier, _ uint16, value []byte) bool {
		data = value
		return false
	})
	if data == nil {
		t.Fatal("the Setup has no VERSIONINFO resource")
	}
	info, err := version.FromBytes(data)
	if err != nil {
		t.Fatalf("parse VERSIONINFO: %v", err)
	}
	return info
}

func versionStrings(t *testing.T, info *version.Info) map[string]string {
	t.Helper()
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Info map[string]map[string]string `json:"info"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	table, ok := decoded.Info["0409"]
	if !ok {
		t.Fatalf("VERSIONINFO has no en-US string table: %s", encoded)
	}
	return table
}
