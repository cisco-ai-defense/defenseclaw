// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestLoadOrCreateIdentityRejectsUnsafeDarwinDirectoryACLBeforePublication(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		entry string
		want  string
	}{
		{
			name:  "write",
			entry: "everyone allow add_file,add_subdirectory,delete_child",
			want:  "write-capable macOS ACL",
		},
		{
			name:  "confidentiality",
			entry: "everyone allow read,readattr,readextattr,file_inherit,directory_inherit",
			want:  "confidentiality-breaking macOS ACL",
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			addFreshIdentityDarwinACL(t, dataDir, fixture.entry)
			keyFile := filepath.Join(dataDir, "device.key")

			_, err := LoadOrCreateIdentity(keyFile, dataDir)
			if err == nil || !strings.Contains(err.Error(), fixture.want) {
				t.Fatalf("LoadOrCreateIdentity error = %v, want %q", err, fixture.want)
			}
			for _, path := range []string{
				keyFile,
				keyFile + ".provenance",
				filepath.Join(dataDir, deviceProvenanceSecretName),
			} {
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Fatalf("unsafe ACL allowed identity publication at %s: %v", path, statErr)
				}
			}
		})
	}
}

func TestFreshIdentityDarwinACLValidationAcceptsCleanDirectoryAndFile(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	file := filepath.Join(dataDir, "artifact")
	if err := os.WriteFile(file, []byte("private"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := validateFreshIdentityDirectoryPlatform(dataDir, mustLstat(t, dataDir)); err != nil {
		t.Fatalf("clean directory ACL rejected: %v", err)
	}
	if err := validateFreshIdentityFilePlatform(file); err != nil {
		t.Fatalf("clean file ACL rejected: %v", err)
	}
}

func TestFreshIdentityDarwinACLValidationRejectsUnsafeFinalFile(t *testing.T) {
	for _, fixture := range []struct {
		name  string
		entry string
	}{
		{name: "write", entry: "everyone allow write,append"},
		{name: "confidentiality", entry: "everyone allow read,readattr,readextattr"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			file := filepath.Join(testenv.PrivateTempDir(t), "artifact")
			if err := os.WriteFile(file, []byte("private"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			addFreshIdentityDarwinACL(t, file, fixture.entry)
			if err := validateFreshIdentityFilePlatform(file); err == nil {
				t.Fatal("unsafe final artifact ACL was accepted")
			}
		})
	}
}

func TestFreshIdentityDarwinACLParserFailsClosedOnUninterpretableACL(t *testing.T) {
	output := []byte("-rw-------+ 1 owner group 7 Jan 1 00:00 artifact\nnot-an-acl-record\n")
	if err := validateFreshIdentityACLOutput("artifact", output); err == nil ||
		!strings.Contains(err.Error(), "could not be interpreted") {
		t.Fatalf("validateFreshIdentityACLOutput error = %v", err)
	}
}

func TestFreshIdentityDarwinACLParserAllowsDenyOnlyACL(t *testing.T) {
	output := []byte("-rw-------+ 1 owner group 7 Jan 1 00:00 artifact\n 0: group:everyone deny read,write\n")
	if err := validateFreshIdentityACLOutput("artifact", output); err != nil {
		t.Fatalf("deny-only ACL rejected: %v", err)
	}
}

func addFreshIdentityDarwinACL(t *testing.T, path, entry string) {
	t.Helper()
	if _, err := os.Stat("/bin/chmod"); err != nil {
		t.Skipf("macOS ACL fixture command unavailable: %v", err)
	}
	cmd := exec.Command("/bin/chmod", "+a", entry, path)
	if output, err := cmd.CombinedOutput(); err != nil {
		message := strings.ToLower(string(output))
		if strings.Contains(message, "not supported") || strings.Contains(message, "invalid argument") {
			t.Skipf("macOS ACL fixture unavailable: %v: %s", err, output)
		}
		t.Fatalf("add macOS ACL: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
}

func mustLstat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
