// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cmidbroker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if observed != lease.Signer() || observed.CommonName == "" || observed.CommonName == CMIDLibraryPublisher {
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

func certificateContextForSubject(t *testing.T, subject pkix.Name) (*windows.CertContext, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	context, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&encoded[0],
		uint32(len(encoded)),
	)
	if err != nil {
		t.Fatalf("CertCreateCertificateContext: %v", err)
	}
	t.Cleanup(func() { _ = windows.CertFreeCertificateContext(context) })
	return context, encoded
}

func simpleDisplayName(context *windows.CertContext) string {
	name := make([]uint16, 256)
	written := windows.CertGetNameString(
		context, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nil, &name[0], uint32(len(name)),
	)
	if written <= 1 {
		return ""
	}
	return windows.UTF16ToString(name[:written])
}

// A certificate without a CN is displayed by its OU or O, so a signer whose
// OU is "Cisco Systems, Inc." has that simple display name. The pin must read
// the CN attribute and refuse the certificate.
func TestLibrarySignerIgnoresTheDisplayNameFallback(t *testing.T) {
	for name, test := range map[string]struct {
		subject pkix.Name
		accept  bool
	}{
		"Cisco common name": {
			subject: pkix.Name{
				CommonName:   CMIDLibraryPublisher,
				Organization: []string{CMIDLibraryPublisher},
				Country:      []string{"US"},
			},
			accept: true,
		},
		"Cisco organizational unit without a common name": {
			subject: pkix.Name{
				OrganizationalUnit: []string{CMIDLibraryPublisher},
				Organization:       []string{"Example"},
				Country:            []string{"US"},
			},
		},
		"Cisco organization without a common name": {
			subject: pkix.Name{
				Organization: []string{CMIDLibraryPublisher},
				Country:      []string{"US"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			context, encoded := certificateContextForSubject(t, test.subject)
			if !test.accept {
				if display := simpleDisplayName(context); display != CMIDLibraryPublisher {
					t.Fatalf("fixture premise: simple display name = %q, want the Windows fallback to %q",
						display, CMIDLibraryPublisher)
				}
			}
			signer, err := librarySignerFromContext(context)
			if err != nil {
				t.Fatalf("librarySignerFromContext: %v", err)
			}
			digest := sha256.Sum256(encoded)
			if signer.CertificateSHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("signer SHA-256 = %s, want the DER certificate digest", signer.CertificateSHA256)
			}
			err = CheckLibrarySigner(signer)
			if test.accept {
				if err != nil || signer.CommonName != CMIDLibraryPublisher {
					t.Fatalf("signer %#v rejected: %v", signer, err)
				}
				return
			}
			if signer.CommonName != "" || !errors.Is(err, ErrLibrarySigner) {
				t.Fatalf("signer %#v accepted or misread: %v", signer, err)
			}
		})
	}
}
