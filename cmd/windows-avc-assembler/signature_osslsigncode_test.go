// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// testSigner is a throwaway self-signed code-signing certificate.
type testSigner struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

func newTestSigner(t *testing.T, name string) testSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testSigner{cert: cert, key: key}
}

func (s testSigner) thumbprint() string {
	digest := sha256.Sum256(s.cert.Raw)
	return hex.EncodeToString(digest[:])
}

// fakeSignedData is a PKCS#7 SignedData whose signer is signer, carrying
// carried. Only the structure the verify path reads is real: the signature
// value is not.
func fakeSignedData(t *testing.T, signer *x509.Certificate, carried ...*x509.Certificate) []byte {
	t.Helper()
	var certificates []byte
	for _, certificate := range carried {
		certificates = append(certificates, certificate.Raw...)
	}
	signerInfo, err := asn1.Marshal(struct {
		Version int
		SID     struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
	}{Version: 1, SID: struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{Issuer: asn1.RawValue{FullBytes: signer.RawIssuer}, Serial: signer.SerialNumber}})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      struct{ ContentType asn1.ObjectIdentifier }
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      struct{ ContentType asn1.ObjectIdentifier }{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certificates},
		SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: signerInfo},
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{oidPKCS7SignedData, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed}})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

// writeTestPE writes a minimal PE32+ file whose attribute certificate
// table holds signedData (none when nil).
func writeTestPE(t *testing.T, dir, name string, signedData []byte) string {
	t.Helper()
	const (
		peOffset       = 0x40
		optionalOffset = peOffset + 4 + 20
		securityEntry  = optionalOffset + 112 + 4*8
		headersEnd     = optionalOffset + 240
	)
	image := make([]byte, headersEnd+512)
	image[0], image[1] = 'M', 'Z'
	binary.LittleEndian.PutUint32(image[0x3C:], peOffset)
	copy(image[peOffset:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(image[peOffset+4:], 0x8664)
	binary.LittleEndian.PutUint16(image[peOffset+4+16:], 240)
	binary.LittleEndian.PutUint16(image[peOffset+4+18:], 0x0022)
	binary.LittleEndian.PutUint16(image[optionalOffset:], 0x20B)
	binary.LittleEndian.PutUint32(image[optionalOffset+108:], 16)
	if signedData != nil {
		entry := make([]byte, 8, 8+len(signedData)+8)
		binary.LittleEndian.PutUint32(entry[0:], uint32(8+len(signedData)))
		binary.LittleEndian.PutUint16(entry[4:], 0x0200)
		binary.LittleEndian.PutUint16(entry[6:], winCertTypePKCSSignedData)
		entry = append(entry, signedData...)
		for len(entry)%8 != 0 {
			entry = append(entry, 0)
		}
		binary.LittleEndian.PutUint32(image[securityEntry:], uint32(len(image)))
		binary.LittleEndian.PutUint32(image[securityEntry+4:], uint32(len(entry)))
		image = append(image, entry...)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, image, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// powerShellSigned returns a script followed by a signature block holding
// signedData, in the layout Authenticode uses.
func powerShellSigned(body string, signedData []byte, newline string) string {
	encoded := base64.StdEncoding.EncodeToString(signedData)
	var text strings.Builder
	text.WriteString(body + newline + powerShellSignatureBegin + newline)
	for len(encoded) > 0 {
		chunk := min(64, len(encoded))
		text.WriteString("# " + encoded[:chunk] + newline)
		encoded = encoded[chunk:]
	}
	text.WriteString(powerShellSignatureEnd + newline)
	return text.String()
}

func TestInspectAuthenticodeSignatureReadsPEAndScripts(t *testing.T) {
	dir := t.TempDir()
	signer := newTestSigner(t, "DefenseClaw test signer")
	other := newTestSigner(t, "unrelated")
	signedData := fakeSignedData(t, signer.cert, other.cert, signer.cert)

	utf16Script := func(text string) []byte {
		units := utf16.Encode([]rune(text))
		raw := []byte{0xFF, 0xFE}
		for _, unit := range units {
			raw = binary.LittleEndian.AppendUint16(raw, unit)
		}
		return raw
	}
	write := func(name string, body []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, path := range map[string]string{
		"pe":         writeTestPE(t, dir, "defenseclaw.exe", signedData),
		"script lf":  write("install-enterprise.ps1", []byte(powerShellSigned("Write-Output 1", signedData, "\n"))),
		"script bom": write("bom.psm1", append([]byte{0xEF, 0xBB, 0xBF}, powerShellSigned("Write-Output 1", signedData, "\r\n")...)),
		"utf-16":     write("wide.ps1", utf16Script(powerShellSigned("Write-Output 1", signedData, "\r\n"))),
	} {
		rec, carried, err := inspectAuthenticodeSignature(path)
		if err != nil || rec.Thumbprint != signer.thumbprint() || len(carried) != 2 {
			t.Errorf("%s: thumbprint %q (want %q), %d carried, err %v", name, rec.Thumbprint, signer.thumbprint(), len(carried), err)
		}
	}
	for name, path := range map[string]string{
		"unsigned pe":     writeTestPE(t, dir, "unsigned.exe", nil),
		"unsigned script": write("unsigned.ps1", []byte("Write-Output 1\n")),
	} {
		if rec, _, err := inspectAuthenticodeSignature(path); err != nil || rec.Thumbprint != "" {
			t.Errorf("%s: thumbprint %q err %v, want an unsigned record", name, rec.Thumbprint, err)
		}
	}
	for name, path := range map[string]string{
		"not a PE":       write("text.exe", []byte("not a PE")),
		"bad base64":     write("bad.ps1", []byte("x\n"+powerShellSignatureBegin+"\n# !!!!\n"+powerShellSignatureEnd+"\n")),
		"no end line":    write("open.ps1", []byte("x\n"+powerShellSignatureBegin+"\n# AAAA\n")),
		"signer missing": writeTestPE(t, dir, "orphan.exe", fakeSignedData(t, signer.cert, other.cert)),
		"not pkcs7":      writeTestPE(t, dir, "junk.exe", []byte{0x30, 0x03, 0x02, 0x01, 0x01}),
	} {
		var signatureErr *signatureError
		if _, _, err := inspectAuthenticodeSignature(path); !errors.As(err, &signatureErr) {
			t.Errorf("%s: err %v, want a signature error", name, err)
		}
	}
}

func TestClassifyOsslsigncodeVerify(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	cases := []struct {
		name   string
		mode   signingType
		rec    osslsigncodeRecord
		accept bool
	}{
		{"unsigned", signingTypeDev, osslsigncodeRecord{Trusted: true, CarriedChainTrusted: true}, false},
		{"other signer", signingTypeDev, osslsigncodeRecord{Thumbprint: strings.Repeat("cd", 32), Trusted: true}, false},
		{"prod trusted", signingTypeProd, osslsigncodeRecord{Thumbprint: pin, Trusted: true}, true},
		{"prod carried only", signingTypeProd, osslsigncodeRecord{Thumbprint: pin, CarriedChainTrusted: true}, false},
		{"prod refused", signingTypeProd, osslsigncodeRecord{Thumbprint: pin}, false},
		{"dev trusted", signingTypeDev, osslsigncodeRecord{Thumbprint: pin, Trusted: true}, true},
		{"dev carried", signingTypeDev, osslsigncodeRecord{Thumbprint: pin, CarriedChainTrusted: true}, true},
		{"dev refused", signingTypeDev, osslsigncodeRecord{Thumbprint: pin}, false},
	}
	for _, tc := range cases {
		err := classifyOsslsigncodeVerify("file.exe", tc.mode, pin, tc.rec)
		var signatureErr *signatureError
		if tc.accept != (err == nil) || (err != nil && !errors.As(err, &signatureErr)) {
			t.Errorf("%s: err %v, accept %v", tc.name, err, tc.accept)
		}
	}
}

// installFakeOsslsigncode puts an osslsigncode on PATH that logs its
// arguments (and any -CAfile contents) and exits with $FAKE_OSSL_TRUSTED
// without -CAfile and $FAKE_OSSL_CARRIED with it.
func installFakeOsslsigncode(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake tool is a POSIX shell script; Windows verifies with PowerShell")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	script := `#!/bin/sh
printf 'call %s\n' "$*" >> "$FAKE_OSSL_LOG"
ca=""
while [ $# -gt 0 ]; do
  [ "$1" = "-CAfile" ] && ca="$2"
  shift
done
if [ -n "$ca" ]; then
  cat "$ca" >> "$FAKE_OSSL_LOG"
  echo "Signature verification: ${FAKE_OSSL_CARRIED_TEXT:-failed}"
  exit "${FAKE_OSSL_CARRIED:-1}"
fi
echo "Signature verification: failed (unable to get local issuer certificate)"
exit "${FAKE_OSSL_TRUSTED:-1}"
`
	if err := os.WriteFile(filepath.Join(dir, "osslsigncode"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_OSSL_LOG", log)
	return log
}

func TestVerifyWithOsslsigncodeRunsThePinnedVerify(t *testing.T) {
	log := installFakeOsslsigncode(t)
	dir := t.TempDir()
	signer := newTestSigner(t, "DefenseClaw test signer")
	pin := signer.thumbprint()
	file := writeTestPE(t, dir, "defenseclaw.exe", fakeSignedData(t, signer.cert, signer.cert))
	calls := func() string {
		t.Helper()
		body, err := os.ReadFile(log)
		if errors.Is(err, os.ErrNotExist) {
			return ""
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(log)
		return string(body)
	}

	t.Setenv("FAKE_OSSL_TRUSTED", "0")
	if err := verifyAuthenticode(file, signingTypeProd, pin); err != nil {
		t.Fatalf("PROD with a trusted chain: %v", err)
	}
	if got := calls(); got != "call verify -in "+file+" -require-leaf-hash sha256:"+pin+"\n" {
		t.Fatalf("PROD ran %q", got)
	}

	t.Setenv("FAKE_OSSL_TRUSTED", "1")
	var signatureErr *signatureError
	if err := verifyAuthenticode(file, signingTypeProd, pin); !errors.As(err, &signatureErr) || !strings.Contains(err.Error(), "unable to get local issuer certificate") {
		t.Fatalf("PROD without a trusted chain: %v", err)
	}
	if got := calls(); strings.Count(got, "call ") != 1 || strings.Contains(got, "-CAfile") {
		t.Fatalf("PROD tried more than the host store: %q", got)
	}

	t.Setenv("FAKE_OSSL_CARRIED", "0")
	if err := verifyAuthenticode(file, signingTypeDev, pin); err != nil {
		t.Fatalf("DEV with a chain to its own certificate: %v", err)
	}
	got := calls()
	var block *pem.Block
	if start := strings.Index(got, "-----BEGIN"); start >= 0 {
		block, _ = pem.Decode([]byte(got[start:]))
	}
	if strings.Count(got, "call ") != 2 || !strings.Contains(got, "-require-leaf-hash sha256:"+pin+" -CAfile ") ||
		block == nil || !bytes.Equal(block.Bytes, signer.cert.Raw) {
		t.Fatalf("DEV did not anchor the second verify at the carried certificate: %q", got)
	}

	t.Setenv("FAKE_OSSL_CARRIED", "1")
	t.Setenv("FAKE_OSSL_CARRIED_TEXT", "failed (message digest mismatch)")
	if err := verifyAuthenticode(file, signingTypeDev, pin); !errors.As(err, &signatureErr) || !strings.Contains(err.Error(), "message digest mismatch") {
		t.Fatalf("DEV with a refused signature: %v", err)
	}
	calls()

	// Another signer or no signature: refused without running the tool.
	if err := verifyAuthenticode(file, signingTypeDev, strings.Repeat("0", 64)); !errors.As(err, &signatureErr) || !strings.Contains(err.Error(), "thumbprint mismatch") {
		t.Fatalf("another signer: %v", err)
	}
	unsigned := writeTestPE(t, dir, "defenseclaw-hook.exe", nil)
	if err := verifyAuthenticode(unsigned, signingTypeDev, pin); !errors.As(err, &signatureErr) || !strings.Contains(err.Error(), "no signer certificate") {
		t.Fatalf("unsigned file: %v", err)
	}
	if got := calls(); got != "" {
		t.Fatalf("the tool ran for a file it cannot accept: %q", got)
	}

	t.Setenv("PATH", t.TempDir())
	var ioErr *ioError
	if err := verifyAuthenticode(file, signingTypeDev, pin); !errors.As(err, &ioErr) || !strings.Contains(err.Error(), "osslsigncode") {
		t.Fatalf("missing osslsigncode: %v", err)
	}
}

// TestVerifyWithRealOsslsigncode signs a script with a throwaway self-signed
// certificate and verifies it the way the release job does. It runs where
// osslsigncode is installed (the release runner and dc-build hosts).
func TestVerifyWithRealOsslsigncode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows verifies with PowerShell")
	}
	tool, err := exec.LookPath("osslsigncode")
	if err != nil {
		t.Skip("osslsigncode is not installed")
	}
	dir := t.TempDir()
	signer := newTestSigner(t, "DefenseClaw throwaway test signer")
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signer.cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer.key)}), 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(dir, "source.ps1")
	if err := os.WriteFile(source, []byte("Write-Output 'DefenseClaw signing path'\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(dir, "install-enterprise.ps1")
	if output, err := exec.Command(tool, "sign", "-certs", certFile, "-key", keyFile, "-h", "sha256",
		"-in", source, "-out", signed).CombinedOutput(); err != nil {
		t.Skipf("this osslsigncode cannot sign PowerShell scripts: %v\n%s", err, output)
	}
	pin := signer.thumbprint()
	if err := verifyAuthenticode(signed, signingTypeDev, pin); err != nil {
		t.Fatalf("DEV refused a script signed with the pinned self-signed certificate: %v", err)
	}
	var signatureErr *signatureError
	if err := verifyAuthenticode(signed, signingTypeProd, pin); !errors.As(err, &signatureErr) {
		t.Fatalf("PROD accepted a self-signed certificate: %v", err)
	}
	if err := verifyAuthenticode(signed, signingTypeDev, newTestSigner(t, "other").thumbprint()); !errors.As(err, &signatureErr) {
		t.Fatalf("DEV accepted another signer: %v", err)
	}
	body, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "install-enterprise.ps1")
	if err := os.WriteFile(tampered, bytes.Replace(body, []byte("signing path"), []byte("signing PATH"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyAuthenticode(tampered, signingTypeDev, pin); !errors.As(err, &signatureErr) {
		t.Fatalf("DEV accepted a script changed after signing: %v", err)
	}
}
