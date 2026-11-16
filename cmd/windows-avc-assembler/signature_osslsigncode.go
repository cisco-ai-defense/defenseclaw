// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"debug/pe"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf16"
)

// osslsigncodeRecord is what the Linux and macOS verify path learns about one
// payload file. classifyOsslsigncodeVerify turns it into a verdict.
type osslsigncodeRecord struct {
	// Thumbprint is SHA256 over the DER signer certificate, lower-case hex,
	// the same value the PowerShell path computes from
	// SignerCertificate.RawData. Empty when the file carries no signature.
	Thumbprint string
	// Trusted is set when osslsigncode verified the file digest, the
	// signature, the pinned signer certificate and a chain to a root in
	// the host's default CA store (OpenSSL's, for example
	// /etc/ssl/certs/ca-certificates.crt).
	Trusted        bool
	TrustedMessage string
	// CarriedChainTrusted is the same verification with the chain anchored
	// at the certificates the signature itself carries: a test or
	// self-signed certificate. Only DEV runs it, and only when Trusted is
	// not set. It is the counterpart of the PowerShell path's DEV
	// acceptance of CERT_E_CHAINING.
	CarriedChainTrusted bool
	CarriedMessage      string
}

// verifyAuthenticodeWithOsslsigncode is the non-Windows verify path. It reads
// the signer certificate out of the file itself (PE certificate table or
// PowerShell signature block), checks it against the pin, and has
// osslsigncode verify the file digest, the signature and the chain, with the
// same pin passed as -require-leaf-hash.
func verifyAuthenticodeWithOsslsigncode(path string, sigType signingType, expectedThumbprint string) error {
	tool, err := exec.LookPath("osslsigncode")
	if err != nil {
		return &ioError{msg: fmt.Sprintf(
			"Authenticode verify on %s needs osslsigncode 2.5 or later on PATH (%s); pass -AllowUnsigned to skip",
			runtime.GOOS, err,
		)}
	}
	rec, carried, err := inspectAuthenticodeSignature(path)
	if err != nil {
		return err
	}
	// osslsigncode runs only for the pinned signer: a missing or other
	// signer is refused as it is, with the exact mismatch.
	if rec.Thumbprint != "" && rec.Thumbprint == expectedThumbprint {
		rec.Trusted, rec.TrustedMessage, err = runOsslsigncodeVerify(tool, path, expectedThumbprint, "")
		if err != nil {
			return err
		}
		if !rec.Trusted && sigType == signingTypeDev {
			anchors, cleanup, err := writeCarriedChain(carried)
			if err != nil {
				return err
			}
			rec.CarriedChainTrusted, rec.CarriedMessage, err = runOsslsigncodeVerify(tool, path, expectedThumbprint, anchors)
			cleanup()
			if err != nil {
				return err
			}
		}
	}
	return classifyOsslsigncodeVerify(path, sigType, expectedThumbprint, rec)
}

// classifyOsslsigncodeVerify applies the trust matrix of classifyVerify to
// the osslsigncode record:
//
//	SigningType | Verified chain                       | Verdict
//	------------+--------------------------------------+---------
//	both        | thumbprint missing or not the pin    | reject
//	PROD        | to a root the host trusts            | accept
//	PROD        | otherwise                            | reject
//	DEV         | to a root the host trusts            | accept
//	DEV         | to a certificate the signature carries | accept
//	DEV         | otherwise                            | reject
//
// Every verification covers the file digest and the signature, so a file
// changed after signing is refused in both modes.
func classifyOsslsigncodeVerify(path string, sigType signingType, expectedThumbprint string, rec osslsigncodeRecord) error {
	if rec.Thumbprint == "" {
		return &signatureError{msg: fmt.Sprintf("%s: no signer certificate on payload (not signed)", path)}
	}
	if rec.Thumbprint != expectedThumbprint {
		return &signatureError{msg: fmt.Sprintf(
			"%s: signer thumbprint mismatch (expected %s, got %s)",
			path, expectedThumbprint, rec.Thumbprint,
		)}
	}
	if rec.Trusted {
		return nil
	}
	if sigType != signingTypeDev {
		return &signatureError{msg: fmt.Sprintf(
			"%s: osslsigncode verify refused the signature; PROD requires a chain to a root this host trusts (%s)",
			path, rec.TrustedMessage,
		)}
	}
	if rec.CarriedChainTrusted {
		return nil
	}
	return &signatureError{msg: fmt.Sprintf(
		"%s: osslsigncode verify refused the signature, also with the chain anchored at the certificates it carries (%s)",
		path, rec.CarriedMessage,
	)}
}

// runOsslsigncodeVerify runs `osslsigncode verify` on path with the signer
// pin and, when caFile is set, that CA bundle as the trust store. verified
// reports osslsigncode's verdict; message is the tail of its output for a
// refusal. err is set only for a runner-side fault (launch failure,
// timeout), which the exit-code contract puts in bucket 6.
func runOsslsigncodeVerify(tool, path, pin, caFile string) (verified bool, message string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), psVerifyTimeout)
	defer cancel()
	args := []string{"verify", "-in", path, "-require-leaf-hash", "sha256:" + pin}
	if caFile != "" {
		args = append(args, "-CAfile", caFile)
	}
	output, runErr := exec.CommandContext(ctx, tool, args...).CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, "", &ioError{msg: fmt.Sprintf("osslsigncode verify timed out after %s for %s", psVerifyTimeout, path)}
	}
	if runErr == nil {
		return true, "", nil
	}
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		return false, "", &ioError{msg: fmt.Sprintf("osslsigncode failed to launch while verifying %s: %s", path, runErr)}
	}
	return false, outputTail(output, 6), nil
}

// outputTail keeps the last lines of a tool's output for a diagnostic.
func outputTail(output []byte, lines int) string {
	all := strings.Split(strings.TrimSpace(strings.ReplaceAll(string(output), "\r\n", "\n")), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "; ")
}

// writeCarriedChain writes the certificates a signature carries to a PEM
// file for -CAfile and returns a cleanup function.
func writeCarriedChain(certificates []*x509.Certificate) (string, func(), error) {
	dir, err := os.MkdirTemp("", "dc-assembler-chain-")
	if err != nil {
		return "", func() {}, &ioError{msg: fmt.Sprintf("create a temporary CA file: %s", err)}
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	var body bytes.Buffer
	for _, certificate := range certificates {
		if err := pem.Encode(&body, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			cleanup()
			return "", func() {}, &ioError{msg: fmt.Sprintf("encode a carried certificate: %s", err)}
		}
	}
	path := filepath.Join(dir, "carried-chain.pem")
	if err := os.WriteFile(path, body.Bytes(), 0o600); err != nil {
		cleanup()
		return "", func() {}, &ioError{msg: fmt.Sprintf("write a temporary CA file: %s", err)}
	}
	return path, cleanup, nil
}

// inspectAuthenticodeSignature returns the signer thumbprint of path and the
// certificates its signature carries. A file with no signature returns an
// empty thumbprint; a signature that does not parse is a payload-side fault.
func inspectAuthenticodeSignature(path string) (osslsigncodeRecord, []*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return osslsigncodeRecord{}, nil, &ioError{msg: fmt.Sprintf("read %s for Authenticode verify: %s", path, err)}
	}
	var signedData []byte
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ps1", ".psm1", ".psd1":
		signedData, err = powerShellSignatureBlock(raw)
	default:
		signedData, err = peSignature(raw)
	}
	if err != nil {
		return osslsigncodeRecord{}, nil, &signatureError{msg: fmt.Sprintf("%s: %s", path, err)}
	}
	if signedData == nil {
		return osslsigncodeRecord{}, nil, nil
	}
	signer, certificates, err := pkcs7Signer(signedData)
	if err != nil {
		return osslsigncodeRecord{}, nil, &signatureError{msg: fmt.Sprintf("%s: %s", path, err)}
	}
	digest := sha256.Sum256(signer.Raw)
	return osslsigncodeRecord{Thumbprint: hex.EncodeToString(digest[:])}, certificates, nil
}

// winCertTypePKCSSignedData is WIN_CERT_TYPE_PKCS_SIGNED_DATA.
const winCertTypePKCSSignedData = 0x0002

// peSignature returns the PKCS#7 SignedData of the first entry of a PE
// file's attribute certificate table, or nil when the table is empty.
func peSignature(raw []byte) ([]byte, error) {
	file, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("not a PE file: %w", err)
	}
	defer file.Close()
	var directory pe.DataDirectory
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			directory = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	case *pe.OptionalHeader32:
		if len(header.DataDirectory) > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			directory = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	default:
		return nil, errors.New("PE file has no optional header")
	}
	if directory.Size == 0 {
		return nil, nil
	}
	// The security directory holds a file offset, not an RVA.
	start, size := uint64(directory.VirtualAddress), uint64(directory.Size)
	if size < 8 || start+size > uint64(len(raw)) {
		return nil, errors.New("the PE certificate table lies outside the file")
	}
	table := raw[start : start+size]
	length := uint64(binary.LittleEndian.Uint32(table[0:4]))
	certificateType := binary.LittleEndian.Uint16(table[6:8])
	if length < 8 || length > size {
		return nil, errors.New("the PE certificate table entry has an invalid length")
	}
	if certificateType != winCertTypePKCSSignedData {
		return nil, fmt.Errorf("the PE certificate table entry has type %#x, not PKCS#7 signed data", certificateType)
	}
	return table[8:length], nil
}

const (
	powerShellSignatureBegin = "# SIG # Begin signature block"
	powerShellSignatureEnd   = "# SIG # End signature block"
)

// powerShellSignatureBlock returns the PKCS#7 SignedData of a signed
// PowerShell script (the base64 comment block at its end), or nil when the
// script has none. UTF-8 (with or without a BOM) and UTF-16LE scripts are
// read.
func powerShellSignatureBlock(raw []byte) ([]byte, error) {
	text := string(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}))
	if bytes.HasPrefix(raw, []byte{0xFF, 0xFE}) {
		body := raw[2:]
		units := make([]uint16, len(body)/2)
		for index := range units {
			units[index] = binary.LittleEndian.Uint16(body[2*index:])
		}
		text = string(utf16.Decode(units))
	}
	begin := strings.LastIndex(text, powerShellSignatureBegin)
	if begin < 0 {
		return nil, nil
	}
	end := strings.Index(text[begin:], powerShellSignatureEnd)
	if end < 0 {
		return nil, errors.New("the PowerShell signature block has no end line")
	}
	var encoded strings.Builder
	for _, line := range strings.Split(text[begin+len(powerShellSignatureBegin):begin+end], "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		content, ok := strings.CutPrefix(line, "# ")
		if !ok {
			return nil, errors.New("the PowerShell signature block has a line that is not a comment")
		}
		encoded.WriteString(strings.TrimSpace(content))
	}
	signedData, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, fmt.Errorf("the PowerShell signature block is not base64: %w", err)
	}
	return signedData, nil
}

var oidPKCS7SignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue
}

type pkcs7SignedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	ContentInfo      asn1.RawValue
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type pkcs7IssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// pkcs7Signer returns the certificate of the first signer of a PKCS#7
// SignedData (the Authenticode signer) and every certificate it carries.
func pkcs7Signer(der []byte) (*x509.Certificate, []*x509.Certificate, error) {
	var info pkcs7ContentInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, nil, fmt.Errorf("the signature is not PKCS#7: %w", err)
	}
	if !info.ContentType.Equal(oidPKCS7SignedData) || info.Content.Class != asn1.ClassContextSpecific || info.Content.Tag != 0 {
		return nil, nil, errors.New("the signature is not PKCS#7 signed data")
	}
	var signed pkcs7SignedData
	if _, err := asn1.Unmarshal(info.Content.Bytes, &signed); err != nil {
		return nil, nil, fmt.Errorf("the PKCS#7 signed data does not parse: %w", err)
	}
	if len(signed.Certificates.Bytes) == 0 {
		return nil, nil, errors.New("the signature carries no certificates")
	}
	certificates, err := x509.ParseCertificates(signed.Certificates.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("a certificate in the signature does not parse: %w", err)
	}
	var signerInfo asn1.RawValue
	if _, err := asn1.Unmarshal(signed.SignerInfos.Bytes, &signerInfo); err != nil {
		return nil, nil, fmt.Errorf("the signature has no signer: %w", err)
	}
	var version int
	rest, err := asn1.Unmarshal(signerInfo.Bytes, &version)
	if err != nil {
		return nil, nil, fmt.Errorf("the signer info does not parse: %w", err)
	}
	var identifier asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &identifier); err != nil {
		return nil, nil, fmt.Errorf("the signer identifier does not parse: %w", err)
	}
	for _, certificate := range certificates {
		switch {
		case identifier.Class == asn1.ClassUniversal && identifier.Tag == asn1.TagSequence:
			var issuerAndSerial pkcs7IssuerAndSerial
			if _, err := asn1.Unmarshal(identifier.FullBytes, &issuerAndSerial); err != nil {
				return nil, nil, fmt.Errorf("the signer issuer and serial number do not parse: %w", err)
			}
			if bytes.Equal(issuerAndSerial.Issuer.FullBytes, certificate.RawIssuer) && issuerAndSerial.Serial != nil &&
				issuerAndSerial.Serial.Cmp(certificate.SerialNumber) == 0 {
				return certificate, certificates, nil
			}
		case identifier.Class == asn1.ClassContextSpecific && identifier.Tag == 0:
			if len(certificate.SubjectKeyId) != 0 && bytes.Equal(identifier.Bytes, certificate.SubjectKeyId) {
				return certificate, certificates, nil
			}
		}
	}
	return nil, nil, errors.New("the signature does not carry its signer's certificate")
}
