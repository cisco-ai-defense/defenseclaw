// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package secretshape

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"testing"

	privatekeyfixture "github.com/defenseclaw/defenseclaw/internal/secretshape/testfixture"
	"golang.org/x/crypto/ssh"
)

func TestValidPrivateKeyPEMAtAcceptsSupportedStructures(t *testing.T) {
	for _, label := range []string{
		"PRIVATE KEY",
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"DSA PRIVATE KEY",
		"OPENSSH PRIVATE KEY",
		"PGP PRIVATE KEY",
	} {
		t.Run(label, func(t *testing.T) {
			literal := strings.TrimSuffix(privatekeyfixture.MustPEM(label), "\n")
			for name, text := range map[string]string{
				"LF":   literal,
				"CRLF": strings.ReplaceAll(literal, "\n", "\r\n"),
			} {
				if !ValidPrivateKeyPEMAt(text, 0) {
					t.Errorf("%s private-key PEM was rejected", name)
				}
			}

			for name, escaped := range map[string]string{
				"escaped LF":   strings.ReplaceAll(literal, "\n", `\n`),
				"escaped CRLF": strings.ReplaceAll(literal, "\n", `\r\n`),
			} {
				text := `{"content":"` + escaped + `"}`
				if !ValidPrivateKeyPEMAt(text, len(`{"content":"`)) {
					t.Errorf("%s private-key PEM was rejected", name)
				}
			}
		})
	}
}

func TestECPrivateKeyFixtureIsDeterministic(t *testing.T) {
	want := privatekeyfixture.MustPEM("EC PRIVATE KEY")
	for range 3 {
		if got := privatekeyfixture.MustPEM("EC PRIVATE KEY"); got != want {
			t.Fatal("EC private-key fixture changed between calls")
		}
	}
}

func TestValidPrivateKeyPEMAtAcceptsLegacyEncryptedStructure(t *testing.T) {
	text := strings.TrimSuffix(privatekeyfixture.MustLegacyEncryptedRSAPEM(), "\n")
	if !ValidPrivateKeyPEMAt(text, 0) {
		t.Fatal("structurally valid encrypted private-key PEM was rejected")
	}
}

func TestValidPrivateKeyPEMAtPreservesUnsupportedAlgorithmRecall(t *testing.T) {
	secp256k1, err := asn1.Marshal(struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	}{
		Version:       1,
		PrivateKey:    []byte{1},
		NamedCurveOID: asn1.ObjectIdentifier{1, 3, 132, 0, 10},
	})
	if err != nil {
		t.Fatal(err)
	}
	unknownPKCS8, err := asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1},
		},
		PrivateKey: []byte{0x04, 0x01, 0x01},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, fixture := range []struct {
		label string
		der   []byte
	}{
		{label: "EC PRIVATE KEY", der: secp256k1},
		{label: "PRIVATE KEY", der: unknownPKCS8},
	} {
		encoded := pem.EncodeToMemory(&pem.Block{Type: fixture.label, Bytes: fixture.der})
		if !ValidPrivateKeyPEMAt(strings.TrimSuffix(string(encoded), "\n"), 0) {
			t.Errorf("structurally valid %s with an unsupported algorithm was rejected", fixture.label)
		}
	}
}

func TestValidPrivateKeyPEMAtPreservesUnsupportedOpenSSHAlgorithmRecall(t *testing.T) {
	for _, test := range []struct {
		name    string
		decoded []byte
	}{
		{name: "security-key Ed25519", decoded: unsupportedOpenSSHPrivateKeyFixture()},
		{name: "security-key ECDSA", decoded: unsupportedOpenSSHECDSAPrivateKeyFixture(t)},
	} {
		t.Run(test.name, func(t *testing.T) {
			text := encodeOpenSSHPrivateKeyFixture(test.decoded)
			if !ValidPrivateKeyPEMAt(text, 0) {
				t.Fatal("structurally valid OpenSSH private key with an unsupported algorithm was rejected")
			}
		})
	}
}

func TestValidPrivateKeyPEMAtAcceptsPassphraseProtectedOpenSSHStructure(t *testing.T) {
	block, err := ssh.MarshalPrivateKeyWithPassphrase(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)),
		"deterministic detector fixture",
		[]byte("detector-fixture-password"),
	)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(pem.EncodeToMemory(block)), "\n")
	if !ValidPrivateKeyPEMAt(text, 0) {
		t.Fatal("passphrase-protected OpenSSH private-key structure was rejected")
	}
}

func TestValidPrivateKeyPEMAtAcceptsSupportedEncryptedOpenSSHCipherShapes(t *testing.T) {
	publicKey, _ := unsupportedOpenSSHPrivateKeyParts()
	kdfOptions := appendOpenSSHPrivateKeyString(nil, bytes.Repeat([]byte{0x42}, 16))
	kdfOptions = binary.BigEndian.AppendUint32(kdfOptions, 16)
	for _, test := range []struct {
		cipher   string
		authSize int
	}{
		{cipher: "3des-cbc"},
		{cipher: "aes128-cbc"},
		{cipher: "aes192-cbc"},
		{cipher: "aes256-cbc"},
		{cipher: "aes128-ctr"},
		{cipher: "aes192-ctr"},
		{cipher: "aes256-ctr"},
		{cipher: "aes128-gcm@openssh.com", authSize: 16},
		{cipher: "aes256-gcm@openssh.com", authSize: 16},
		{cipher: "chacha20-poly1305@openssh.com", authSize: 16},
	} {
		t.Run(test.cipher, func(t *testing.T) {
			decoded := encodeOpenSSHPrivateKeyContainer(
				test.cipher,
				"bcrypt",
				kdfOptions,
				publicKey,
				bytes.Repeat([]byte{0x24}, 16),
			)
			decoded = append(decoded, bytes.Repeat([]byte{0x36}, test.authSize)...)
			if !ValidPrivateKeyPEMAt(encodeOpenSSHPrivateKeyFixture(decoded), 0) {
				t.Fatal("supported encrypted OpenSSH private-key cipher shape was rejected")
			}
		})
	}
}

func TestValidPrivateKeyPEMAtRejectsMalformedUnsupportedOpenSSHContainer(t *testing.T) {
	publicKey, privateKey := unsupportedOpenSSHPrivateKeyParts()
	nulApplicationPublicKey, nulApplicationPrivateKey := unsupportedOpenSSHPrivateKeyPartsFor(
		[]byte("ssh:\x00junk"), []byte("detector fixture"),
	)
	_, nulCommentPrivateKey := unsupportedOpenSSHPrivateKeyPartsFor(
		[]byte("ssh:"), []byte("detector\x00fixture"),
	)
	truncatedPrivateKey := make([]byte, 8)
	binary.BigEndian.PutUint32(truncatedPrivateKey, 0x01020304)
	binary.BigEndian.PutUint32(truncatedPrivateKey[4:], 0x01020304)
	truncatedPrivateKey = appendOpenSSHPrivateKeyString(
		truncatedPrivateKey, []byte(ssh.KeyAlgoSKED25519),
	)
	truncatedPrivateKey = append(truncatedPrivateKey, 0)

	malformedPublicKey := appendOpenSSHPrivateKeyString(nil, []byte(ssh.KeyAlgoSKED25519))
	malformedPublicKey = append(malformedPublicKey, 0)
	badPaddingPrivateKey := append([]byte(nil), privateKey...)
	badPaddingPrivateKey[len(badPaddingPrivateKey)-1] = 2

	for _, test := range []struct {
		name    string
		decoded []byte
	}{
		{
			name:    "outer trailing data",
			decoded: append(unsupportedOpenSSHPrivateKeyFixture(), 0),
		},
		{
			name: "truncated security-key private fields",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"none", "none", nil, publicKey, truncatedPrivateKey,
			),
		},
		{
			name: "malformed embedded public key",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"none", "none", nil, malformedPublicKey, privateKey,
			),
		},
		{
			name: "invalid security-key padding",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"none", "none", nil, publicKey, badPaddingPrivateKey,
			),
		},
		{
			name: "missing block-alignment padding",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"none", "none", nil, publicKey, privateKey[:len(privateKey)-1],
			),
		},
		{
			name: "nul-bearing security-key application",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"none", "none", nil, nulApplicationPublicKey, nulApplicationPrivateKey,
			),
		},
		{
			name: "nul-bearing security-key comment",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"none", "none", nil, publicKey, nulCommentPrivateKey,
			),
		},
		{
			name: "unsupported encrypted header",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"bogus-cipher", "bogus-kdf", []byte{1}, publicKey, bytes.Repeat([]byte{1}, 16),
			),
		},
		{
			name: "malformed bcrypt options",
			decoded: encodeOpenSSHPrivateKeyContainer(
				"aes256-ctr", "bcrypt", []byte{1}, publicKey, bytes.Repeat([]byte{1}, 16),
			),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if ValidPrivateKeyPEMAt(encodeOpenSSHPrivateKeyFixture(test.decoded), 0) {
				t.Fatal("malformed OpenSSH private-key container was accepted")
			}
		})
	}
}

func TestValidPrivateKeyPEMAtRejectsSupportedOpenSSHMissingBlockPadding(t *testing.T) {
	block, rest := pem.Decode([]byte(privatekeyfixture.MustPEM("OPENSSH PRIVATE KEY")))
	if block == nil || len(rest) != 0 {
		t.Fatal("invalid supported OpenSSH fixture")
	}
	container, ok := parseOpenSSHPrivateKeyContainer(block.Bytes)
	if !ok || container.cipherName != "none" || len(container.privateKeyBlock) < 1 {
		t.Fatal("supported OpenSSH fixture did not have the expected unencrypted container")
	}
	decoded := encodeOpenSSHPrivateKeyContainer(
		container.cipherName,
		container.kdfName,
		container.kdfOptions,
		container.publicKey,
		container.privateKeyBlock[:len(container.privateKeyBlock)-1],
	)
	if ValidPrivateKeyPEMAt(encodeOpenSSHPrivateKeyFixture(decoded), 0) {
		t.Fatal("supported OpenSSH private key with non-block-aligned padding was accepted")
	}
}

func TestValidPrivateKeyPEMAtRejectsArbitraryBase64ForEveryLabel(t *testing.T) {
	for _, label := range []string{
		"PRIVATE KEY",
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"DSA PRIVATE KEY",
		"OPENSSH PRIVATE KEY",
		"PGP PRIVATE KEY",
	} {
		t.Run(label, func(t *testing.T) {
			text := "-----BEGIN " + label + "-----\nQUJDRA==\n-----END " + label + "-----"
			if ValidPrivateKeyPEMAt(text, 0) {
				t.Fatal("arbitrary Base64 was accepted as a private key")
			}
		})
	}
}

func TestValidPrivateKeyPEMAtRejectsWrongOrMalformedStructures(t *testing.T) {
	rsaBlock, _ := pem.Decode([]byte(privatekeyfixture.MustPEM("RSA PRIVATE KEY")))
	if rsaBlock == nil {
		t.Fatal("decode RSA private-key fixture")
	}
	rsaPayload := base64.StdEncoding.EncodeToString(rsaBlock.Bytes)

	for _, text := range []string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nnot-base64\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\n" + rsaPayload + "\n-----END EC PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----\n" + rsaPayload + "\n-----END EC PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n" +
			"DEK-Info: UNKNOWN,0123456789ABCDEF\n\nQUJDRA==\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n" +
			"DEK-Info: AES-256-CBC,0123456789ABCDEF\n\nQUJDRA==\n-----END RSA PRIVATE KEY-----",
	} {
		if ValidPrivateKeyPEMAt(text, 0) {
			t.Errorf("invalid private-key PEM was accepted: %q", text)
		}
	}
}

func TestValidPrivateKeyPEMAtAcceptsOpenSSHSeventyColumnArmor(t *testing.T) {
	text := rewrapPrivateKeyFixture(t, privatekeyfixture.MustPEM("OPENSSH PRIVATE KEY"), 70)
	firstPayload := strings.Split(text, "\n")[1]
	if len(firstPayload) != 70 {
		t.Fatalf("OpenSSH regression fixture wrapped at %d columns, want 70", len(firstPayload))
	}
	if !ValidPrivateKeyPEMAt(text, 0) {
		t.Fatal("70-column OpenSSH private-key armor was rejected")
	}
}

func TestValidPrivateKeyPEMAtEnforcesLabelSpecificLineBounds(t *testing.T) {
	openSSH := rewrapPrivateKeyFixture(t, privatekeyfixture.MustPEM("OPENSSH PRIVATE KEY"), 71)
	if ValidPrivateKeyPEMAt(openSSH, 0) {
		t.Fatal("71-column OpenSSH private-key armor was accepted")
	}

	ecBlock, _ := pem.Decode([]byte(privatekeyfixture.MustPEM("EC PRIVATE KEY")))
	if ecBlock == nil {
		t.Fatal("decode EC private-key fixture")
	}
	payload := base64.StdEncoding.EncodeToString(ecBlock.Bytes)
	if len(payload) < 68 {
		t.Fatal("EC fixture is too short to exercise the 64-column bound")
	}
	ec := "-----BEGIN EC PRIVATE KEY-----\n" + payload[:68] + "\n" + payload[68:] +
		"\n-----END EC PRIVATE KEY-----"
	if ValidPrivateKeyPEMAt(ec, 0) {
		t.Fatal("68-column EC private-key armor was accepted")
	}

	misaligned := "-----BEGIN EC PRIVATE KEY-----\n" + payload[:62] + "\n" + payload[62:] +
		"\n-----END EC PRIVATE KEY-----"
	if ValidPrivateKeyPEMAt(misaligned, 0) {
		t.Fatal("62-column EC private-key armor was accepted")
	}
}

func unsupportedOpenSSHPrivateKeyFixture() []byte {
	publicKey, privateKey := unsupportedOpenSSHPrivateKeyParts()
	return encodeOpenSSHPrivateKeyContainer("none", "none", nil, publicKey, privateKey)
}

func unsupportedOpenSSHECDSAPrivateKeyFixture(t *testing.T) []byte {
	t.Helper()
	const encodedPublicKey = "AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTY" +
		"AAABBBGRNqlFgED/pf4zXz8IzqA6CALNwYcwgd4MQDmIS1GOtn1SySFObiuyJaOlpqkV5FeEifhxfIC2ejKKtNyO4CysAAAAEc3NoOg=="
	publicKey, err := base64.StdEncoding.DecodeString(encodedPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyType, publicFields, ok := readOpenSSHPrivateKeyString(publicKey, maxOpenSSHPrivateKeyNameBytes)
	if !ok || string(keyType) != ssh.KeyAlgoSKECDSA256 {
		t.Fatal("invalid security-key ECDSA public fixture")
	}
	curve, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxOpenSSHPrivateKeyNameBytes)
	if !ok {
		t.Fatal("security-key ECDSA fixture is missing its curve")
	}
	publicValue, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxPrivateKeyPEMBytes)
	if !ok {
		t.Fatal("security-key ECDSA fixture is missing its public value")
	}
	application, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxPrivateKeyPEMBytes)
	if !ok || len(publicFields) != 0 {
		t.Fatal("security-key ECDSA fixture is missing its application")
	}

	privateKey := make([]byte, 8)
	binary.BigEndian.PutUint32(privateKey, 0x01020304)
	binary.BigEndian.PutUint32(privateKey[4:], 0x01020304)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, keyType)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, curve)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, publicValue)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, application)
	privateKey = append(privateKey, 0)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, []byte("deterministic-key-handle"))
	privateKey = appendOpenSSHPrivateKeyString(privateKey, nil)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, []byte("detector fixture"))
	for padding := byte(1); len(privateKey)%8 != 0; padding++ {
		privateKey = append(privateKey, padding)
	}
	return encodeOpenSSHPrivateKeyContainer("none", "none", nil, publicKey, privateKey)
}

func unsupportedOpenSSHPrivateKeyParts() ([]byte, []byte) {
	return unsupportedOpenSSHPrivateKeyPartsFor([]byte("ssh:"), []byte("detector fixture"))
}

func unsupportedOpenSSHPrivateKeyPartsFor(application, comment []byte) ([]byte, []byte) {
	const keyType = ssh.KeyAlgoSKED25519
	publicKey := appendOpenSSHPrivateKeyString(nil, []byte(keyType))
	publicKey = appendOpenSSHPrivateKeyString(publicKey, bytes.Repeat([]byte{0x42}, 32))
	publicKey = appendOpenSSHPrivateKeyString(publicKey, application)

	privateKey := make([]byte, 8)
	binary.BigEndian.PutUint32(privateKey, 0x01020304)
	binary.BigEndian.PutUint32(privateKey[4:], 0x01020304)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, []byte(keyType))
	privateKey = appendOpenSSHPrivateKeyString(privateKey, bytes.Repeat([]byte{0x42}, 32))
	privateKey = appendOpenSSHPrivateKeyString(privateKey, application)
	privateKey = append(privateKey, 0)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, []byte("deterministic-key-handle"))
	privateKey = appendOpenSSHPrivateKeyString(privateKey, nil)
	privateKey = appendOpenSSHPrivateKeyString(privateKey, comment)
	for padding := byte(1); len(privateKey)%8 != 0; padding++ {
		privateKey = append(privateKey, padding)
	}
	return publicKey, privateKey
}

func encodeOpenSSHPrivateKeyContainer(
	cipherName, kdfName string,
	kdfOptions, publicKey, privateKey []byte,
) []byte {
	decoded := []byte(openSSHPrivateKeyAuthMagic)
	decoded = appendOpenSSHPrivateKeyString(decoded, []byte(cipherName))
	decoded = appendOpenSSHPrivateKeyString(decoded, []byte(kdfName))
	decoded = appendOpenSSHPrivateKeyString(decoded, kdfOptions)
	decoded = binary.BigEndian.AppendUint32(decoded, 1)
	decoded = appendOpenSSHPrivateKeyString(decoded, publicKey)
	return appendOpenSSHPrivateKeyString(decoded, privateKey)
}

func appendOpenSSHPrivateKeyString(encoded, value []byte) []byte {
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(value)))
	return append(encoded, value...)
}

func encodeOpenSSHPrivateKeyFixture(decoded []byte) string {
	encoded := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: decoded})
	return strings.TrimSuffix(string(encoded), "\n")
}

func rewrapPrivateKeyFixture(t *testing.T, encoded string, width int) string {
	t.Helper()
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		t.Fatal("decode private-key fixture")
	}
	payload := base64.StdEncoding.EncodeToString(block.Bytes)
	lines := make([]string, 0, len(payload)/width+1)
	for len(payload) > width {
		lines = append(lines, payload[:width])
		payload = payload[width:]
	}
	lines = append(lines, payload)
	return "-----BEGIN " + block.Type + "-----\n" + strings.Join(lines, "\n") +
		"\n-----END " + block.Type + "-----"
}
