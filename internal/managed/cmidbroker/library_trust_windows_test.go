// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func acceptLibraryPath(string) error { return nil }

func acceptLibrarySigner(LibrarySigner) error { return nil }

// signedForeignLibrary returns an embedded-Authenticode-signed DLL from a
// publisher other than Cisco. PowerShell 7 ships Microsoft-signed DLLs.
func signedForeignLibrary(t *testing.T) string {
	t.Helper()
	programFiles := os.Getenv("ProgramW6432")
	if programFiles == "" {
		programFiles = os.Getenv("ProgramFiles")
	}
	for _, name := range []string{"hostfxr.dll", "pwsh.dll"} {
		candidate := filepath.Join(programFiles, "PowerShell", "7", name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	t.Skip("no embedded-Authenticode-signed PowerShell 7 library is available")
	return ""
}

func copyLibrary(t *testing.T, source string) string {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), filepath.Base(source))
	if err := os.WriteFile(destination, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return destination
}

func TestOpenTrustedLibraryRejectsValidlySignedForeignLibrary(t *testing.T) {
	library := signedForeignLibrary(t)
	lease, err := OpenTrustedLibrary(library, acceptLibraryPath)
	if lease != nil {
		_ = lease.Close()
	}
	if !errors.Is(err, ErrLibrarySigner) || errors.Is(err, ErrLibrarySignature) {
		t.Fatalf("OpenTrustedLibrary(%s) error = %v, want ErrLibrarySigner", library, err)
	}
}

func TestOpenTrustedLibraryRejectsUnsignedAndTamperedLibraries(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unsigned := copyLibrary(t, executable)

	tampered := copyLibrary(t, signedForeignLibrary(t))
	data, err := os.ReadFile(tampered)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(tampered, data, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, path := range map[string]string{"unsigned": unsigned, "tampered": tampered} {
		t.Run(name, func(t *testing.T) {
			// A permissive signer policy proves the signature itself is checked.
			lease, err := openTrustedLibrary(path, acceptLibraryPath, acceptLibrarySigner)
			if lease != nil {
				_ = lease.Close()
			}
			if !errors.Is(err, ErrLibrarySignature) {
				t.Fatalf("openTrustedLibrary(%s) error = %v, want ErrLibrarySignature", path, err)
			}
		})
	}
}

func TestOpenTrustedLibraryReportsTheVerifiedSigner(t *testing.T) {
	var observed LibrarySigner
	lease, err := openTrustedLibrary(signedForeignLibrary(t), acceptLibraryPath, func(signer LibrarySigner) error {
		observed = signer
		return nil
	})
	if err != nil {
		t.Fatalf("openTrustedLibrary: %v", err)
	}
	defer lease.Close()
	if observed != lease.Signer() || observed.SimpleName == "" || observed.SimpleName == CMIDLibraryPublisher {
		t.Fatalf("signer = %#v, lease signer = %#v", observed, lease.Signer())
	}
	if digest, err := hex.DecodeString(observed.CertificateSHA256); err != nil || len(digest) != 32 {
		t.Fatalf("signer certificate SHA-256 = %q", observed.CertificateSHA256)
	}
}

func TestLibraryLeaseDeniesReplacementAndAdmitsLoadLibrary(t *testing.T) {
	library := copyLibrary(t, signedForeignLibrary(t))
	lease, err := openTrustedLibrary(library, acceptLibraryPath, acceptLibrarySigner)
	if err != nil {
		t.Fatalf("openTrustedLibrary: %v", err)
	}
	if file, err := os.OpenFile(library, os.O_WRONLY, 0); err == nil {
		_ = file.Close()
		_ = lease.Close()
		t.Fatal("verified library was writable while its lease was held")
	}
	if err := os.Rename(library, library+".replaced"); err == nil {
		_ = lease.Close()
		t.Fatal("verified library was renamed while its lease was held")
	}
	if err := os.Remove(library); err == nil {
		_ = lease.Close()
		t.Fatal("verified library was deleted while its lease was held")
	}
	module, err := windows.LoadLibraryEx(library, 0, windows.DONT_RESOLVE_DLL_REFERENCES)
	if err != nil {
		_ = lease.Close()
		t.Fatalf("LoadLibraryEx while the lease was held: %v", err)
	}
	if err := windows.FreeLibrary(module); err != nil {
		t.Fatalf("FreeLibrary: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	file, err := os.OpenFile(library, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("library remained locked after Close: %v", err)
	}
	_ = file.Close()
}

func TestOpenTrustedLibraryAppliesPathTrustBeforeOpenAndWhileHeld(t *testing.T) {
	library := copyLibrary(t, signedForeignLibrary(t))
	calls := 0
	lease, err := openTrustedLibrary(library, func(path string) error {
		if path != library {
			t.Fatalf("path trust received %q", path)
		}
		calls++
		return nil
	}, acceptLibrarySigner)
	if err != nil {
		t.Fatalf("openTrustedLibrary: %v", err)
	}
	_ = lease.Close()
	if calls != 2 {
		t.Fatalf("path trust ran %d times, want 2", calls)
	}

	untrusted := errors.New("untrusted ancestry")
	for failOn := 1; failOn <= 2; failOn++ {
		calls = 0
		lease, err := openTrustedLibrary(library, func(string) error {
			calls++
			if calls == failOn {
				return untrusted
			}
			return nil
		}, acceptLibrarySigner)
		if lease != nil {
			_ = lease.Close()
		}
		if !errors.Is(err, untrusted) {
			t.Fatalf("path trust failure on call %d: error = %v", failOn, err)
		}
		file, openErr := os.OpenFile(library, os.O_WRONLY, 0)
		if openErr != nil {
			t.Fatalf("rejected library stayed locked after path trust failure %d: %v", failOn, openErr)
		}
		_ = file.Close()
	}

	if _, err := OpenTrustedLibrary(library, nil); err == nil {
		t.Fatal("OpenTrustedLibrary accepted a nil path-trust policy")
	}
}
