// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package secretshape validates structured secret candidates shared by
// gateway and repository scanners.
package secretshape

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"

	"golang.org/x/crypto/openpgp/packet" //nolint:staticcheck // detector must parse supported OpenPGP private-key packets
	"golang.org/x/crypto/ssh"
)

const maxPrivateKeyPEMBytes = 64 * 1024
const maxPrivateKeyASN1Elements = 64
const openSSHPrivateKeyAuthMagic = "openssh-key-v1\x00"
const maxOpenSSHPrivateKeyNameBytes = 256
const maxOpenSSHPrivateKeyKDFSaltBytes = 1024

type openSSHPrivateKeyContainer struct {
	cipherName      string
	kdfName         string
	kdfOptions      []byte
	publicKey       []byte
	publicKeyType   string
	privateKeyBlock []byte
	authTag         []byte
}

// ValidPrivateKeyPEMAt reports whether text[start:] begins with a complete,
// bounded private-key PEM block. Both literal newlines and JSON-escaped
// newlines are accepted because gateway tool arguments are scanned in their
// serialized form while file scanners see literal lines.
func ValidPrivateKeyPEMAt(text string, start int) bool {
	if start < 0 || start >= len(text) {
		return false
	}
	headerEnd, separator, ok := privateKeyLineEnd(text, start)
	if !ok {
		return false
	}
	header := text[start:headerEnd]
	if !strings.HasPrefix(header, "-----BEGIN ") || !strings.HasSuffix(header, "-----") {
		return false
	}
	label := strings.TrimSuffix(strings.TrimPrefix(header, "-----BEGIN "), "-----")
	if !allowedPrivateKeyLabel(label) {
		return false
	}

	footer := "-----END " + label + "-----"
	position := headerEnd + len(separator)
	limit := start + maxPrivateKeyPEMBytes
	if limit > len(text) {
		limit = len(text)
	}
	payloadLines := make([]string, 0, 16)
	metadata := make(map[string]string)
	metadataSeen := false
	metadataEnded := false

	for position <= limit {
		if strings.HasPrefix(text[position:limit], footer) &&
			privateKeyFooterBoundary(text, position+len(footer), separator) {
			return len(payloadLines) > 0 && validPrivateKeyPayload(label, payloadLines, metadata)
		}
		relativeEnd := strings.Index(text[position:limit], separator)
		if relativeEnd < 0 {
			return false
		}
		lineEnd := position + relativeEnd
		line := text[position:lineEnd]
		if line == "" {
			if !metadataSeen || metadataEnded || len(payloadLines) > 0 {
				return false
			}
			metadataEnded = true
			position = lineEnd + len(separator)
			continue
		}
		if key, value, valid := parsePEMMetadataLine(line); len(payloadLines) == 0 && !metadataEnded && valid {
			if _, duplicate := metadata[key]; duplicate {
				return false
			}
			metadata[key] = value
			metadataSeen = true
			position = lineEnd + len(separator)
			continue
		}
		if metadataSeen && !metadataEnded {
			return false
		}
		if !validBase64PEMLine(label, line) {
			return false
		}
		payloadLines = append(payloadLines, line)
		position = lineEnd + len(separator)
	}
	return false
}

func privateKeyLineEnd(text string, start int) (int, string, bool) {
	end := len(text)
	separator := ""
	for _, candidate := range []string{"\r\n", "\n", `\r\n`, `\n`} {
		if index := strings.Index(text[start:], candidate); index >= 0 && start+index < end {
			end = start + index
			separator = candidate
		}
	}
	if separator == "" || end-start > 80 {
		return 0, "", false
	}
	return end, separator, true
}

func allowedPrivateKeyLabel(label string) bool {
	switch label {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
		"OPENSSH PRIVATE KEY", "PGP PRIVATE KEY":
		return true
	default:
		return false
	}
}

func privateKeyFooterBoundary(text string, end int, separator string) bool {
	if end == len(text) || strings.HasPrefix(text[end:], separator) {
		return true
	}
	switch text[end] {
	case ' ', '\t', '"', '\'', ',', '}', ']':
		return true
	case '\\':
		return end+1 < len(text) && (text[end+1] == '"' || text[end+1] == '\'' || text[end+1] == 'n' || text[end+1] == 'r')
	default:
		return false
	}
}

func parsePEMMetadataLine(line string) (string, string, bool) {
	colon := strings.IndexByte(line, ':')
	if colon < 1 || colon > 32 || len(line)-colon-1 < 1 || len(line)-colon-1 > 256 {
		return "", "", false
	}
	for _, character := range []byte(line[:colon]) {
		if !isPEMMetadataKeyByte(character) {
			return "", "", false
		}
	}
	for _, character := range []byte(line[colon+1:]) {
		if character < 0x20 || character > 0x7e {
			return "", "", false
		}
	}
	return line[:colon], strings.TrimSpace(line[colon+1:]), true
}

func isPEMMetadataKeyByte(character byte) bool {
	return (character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9') || character == '-'
}

func validBase64PEMLine(label, line string) bool {
	// Base64 alignment applies to the concatenated payload, not each physical
	// line for OpenSSH armor, which wraps at 70 columns. Other PEM labels retain
	// their stricter 64-column, four-byte-aligned line shape. The complete block
	// bound above limits work before validPrivateKeyPayload decodes the joined
	// payload authoritatively.
	if label == "OPENSSH PRIVATE KEY" {
		if len(line) < 1 || len(line) > 70 {
			return false
		}
	} else if len(line) < 4 || len(line) > 64 || len(line)%4 != 0 {
		return false
	}
	firstPadding := -1
	for index, character := range []byte(line) {
		if character == '=' {
			if firstPadding < 0 {
				firstPadding = index
			}
			continue
		}
		if firstPadding >= 0 || !isBase64Byte(character) {
			return false
		}
	}
	return firstPadding < 0 || firstPadding >= len(line)-2
}

func validPrivateKeyPayload(label string, lines []string, metadata map[string]string) bool {
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	if err != nil || len(decoded) == 0 {
		return false
	}
	if len(metadata) > 0 {
		return validLegacyEncryptedPrivateKey(label, metadata, decoded)
	}
	switch label {
	case "PRIVATE KEY":
		return validPKCS8PrivateKey(decoded)
	case "RSA PRIVATE KEY":
		return validPKCS1PrivateKey(decoded)
	case "EC PRIVATE KEY":
		return validSEC1PrivateKey(decoded)
	case "DSA PRIVATE KEY":
		return validDSAPrivateKey(decoded)
	case "OPENSSH PRIVATE KEY":
		return validOpenSSHPrivateKey(decoded)
	case "PGP PRIVATE KEY":
		return validOpenPGPPrivateKey(decoded)
	default:
		return false
	}
}

func validOpenSSHPrivateKey(decoded []byte) bool {
	container, ok := parseOpenSSHPrivateKeyContainer(decoded)
	if !ok {
		return false
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: decoded})
	if len(encoded) == 0 {
		return false
	}
	_, err := ssh.ParseRawPrivateKey(encoded)
	if err == nil {
		return true
	}
	var passphraseMissing *ssh.PassphraseMissingError
	if errors.As(err, &passphraseMissing) {
		return validEncryptedOpenSSHPrivateKeyContainer(container)
	}
	return err.Error() == "ssh: unhandled key type" &&
		validUnsupportedOpenSSHPrivateKeyContainer(container)
}

func parseOpenSSHPrivateKeyContainer(decoded []byte) (openSSHPrivateKeyContainer, bool) {
	var container openSSHPrivateKeyContainer
	if !bytes.HasPrefix(decoded, []byte(openSSHPrivateKeyAuthMagic)) {
		return container, false
	}
	remaining := decoded[len(openSSHPrivateKeyAuthMagic):]

	cipherName, remaining, ok := readOpenSSHPrivateKeyString(remaining, maxOpenSSHPrivateKeyNameBytes)
	if !ok || len(cipherName) == 0 {
		return container, false
	}
	kdfName, remaining, ok := readOpenSSHPrivateKeyString(remaining, maxOpenSSHPrivateKeyNameBytes)
	if !ok || len(kdfName) == 0 {
		return container, false
	}
	kdfOptions, remaining, ok := readOpenSSHPrivateKeyString(remaining, maxPrivateKeyPEMBytes)
	if !ok || len(remaining) < 4 || binary.BigEndian.Uint32(remaining) != 1 {
		return container, false
	}
	remaining = remaining[4:]

	publicKey, remaining, ok := readOpenSSHPrivateKeyString(remaining, maxPrivateKeyPEMBytes)
	if !ok || len(publicKey) == 0 {
		return container, false
	}
	privateKeyBlock, remaining, ok := readOpenSSHPrivateKeyString(remaining, maxPrivateKeyPEMBytes)
	if !ok || len(privateKeyBlock) == 0 {
		return container, false
	}
	blockSize, authSize, knownCipher := openSSHPrivateKeyCipherShape(string(cipherName))
	if (!knownCipher && len(remaining) != 0) ||
		(knownCipher && (len(remaining) != authSize || len(privateKeyBlock) < blockSize ||
			len(privateKeyBlock)%blockSize != 0)) {
		return container, false
	}

	publicKeyType, publicKeyFields, ok := readOpenSSHPrivateKeyString(publicKey, maxOpenSSHPrivateKeyNameBytes)
	if !ok || len(publicKeyType) == 0 || len(publicKeyFields) == 0 {
		return container, false
	}
	parsedPublicKey, err := ssh.ParsePublicKey(publicKey)
	if err != nil || parsedPublicKey.Type() != string(publicKeyType) {
		return container, false
	}
	return openSSHPrivateKeyContainer{
		cipherName:      string(cipherName),
		kdfName:         string(kdfName),
		kdfOptions:      kdfOptions,
		publicKey:       publicKey,
		publicKeyType:   string(publicKeyType),
		privateKeyBlock: privateKeyBlock,
		authTag:         remaining,
	}, true
}

func validEncryptedOpenSSHPrivateKeyContainer(container openSSHPrivateKeyContainer) bool {
	blockSize, authSize, ok := openSSHPrivateKeyCipherShape(container.cipherName)
	if !ok || container.cipherName == "none" || container.kdfName != "bcrypt" ||
		len(container.privateKeyBlock) < blockSize || len(container.privateKeyBlock)%blockSize != 0 ||
		len(container.authTag) != authSize {
		return false
	}
	salt, remaining, ok := readOpenSSHPrivateKeyString(
		container.kdfOptions, maxOpenSSHPrivateKeyKDFSaltBytes,
	)
	return ok && len(salt) > 0 && len(remaining) == 4 && binary.BigEndian.Uint32(remaining) > 0
}

func openSSHPrivateKeyCipherShape(name string) (blockSize, authSize int, ok bool) {
	switch name {
	case "none", "3des-cbc":
		return 8, 0, true
	case "aes128-cbc", "aes192-cbc", "aes256-cbc",
		"aes128-ctr", "aes192-ctr", "aes256-ctr":
		return 16, 0, true
	case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com":
		return 16, 16, true
	case "chacha20-poly1305@openssh.com":
		return 8, 16, true
	default:
		return 0, 0, false
	}
}

func validUnsupportedOpenSSHPrivateKeyContainer(container openSSHPrivateKeyContainer) bool {
	if container.cipherName != "none" || container.kdfName != "none" ||
		len(container.kdfOptions) != 0 || len(container.privateKeyBlock) < 8 ||
		len(container.privateKeyBlock)%8 != 0 || len(container.authTag) != 0 {
		return false
	}
	if binary.BigEndian.Uint32(container.privateKeyBlock) !=
		binary.BigEndian.Uint32(container.privateKeyBlock[4:]) {
		return false
	}
	privateKeyType, privateKeyFields, ok := readOpenSSHPrivateKeyString(
		container.privateKeyBlock[8:], maxOpenSSHPrivateKeyNameBytes,
	)
	if !ok || string(privateKeyType) != container.publicKeyType {
		return false
	}
	switch container.publicKeyType {
	case ssh.KeyAlgoSKED25519:
		return validOpenSSHSKEd25519PrivateKey(container.publicKey, privateKeyFields)
	case ssh.KeyAlgoSKECDSA256:
		return validOpenSSHSKECDSAPrivateKey(container.publicKey, privateKeyFields)
	default:
		return false
	}
}

func validOpenSSHSKEd25519PrivateKey(publicKey, privateFields []byte) bool {
	publicKeyType, publicFields, ok := readOpenSSHPrivateKeyString(publicKey, maxOpenSSHPrivateKeyNameBytes)
	if !ok || string(publicKeyType) != ssh.KeyAlgoSKED25519 {
		return false
	}
	publicValue, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, 32)
	if !ok || len(publicValue) != 32 {
		return false
	}
	application, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxPrivateKeyPEMBytes)
	if !ok || len(application) == 0 || bytes.IndexByte(application, 0) >= 0 || len(publicFields) != 0 {
		return false
	}
	privateValue, privateFields, ok := readOpenSSHPrivateKeyString(privateFields, 32)
	if !ok || !bytes.Equal(privateValue, publicValue) {
		return false
	}
	privateApplication, privateFields, ok := readOpenSSHPrivateKeyString(privateFields, maxPrivateKeyPEMBytes)
	return ok && bytes.Equal(privateApplication, application) &&
		validOpenSSHSecurityKeyPrivateTail(privateFields)
}

func validOpenSSHSKECDSAPrivateKey(publicKey, privateFields []byte) bool {
	publicKeyType, publicFields, ok := readOpenSSHPrivateKeyString(publicKey, maxOpenSSHPrivateKeyNameBytes)
	if !ok || string(publicKeyType) != ssh.KeyAlgoSKECDSA256 {
		return false
	}
	curve, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxOpenSSHPrivateKeyNameBytes)
	if !ok || string(curve) != "nistp256" {
		return false
	}
	publicValue, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxPrivateKeyPEMBytes)
	if !ok || len(publicValue) == 0 {
		return false
	}
	application, publicFields, ok := readOpenSSHPrivateKeyString(publicFields, maxPrivateKeyPEMBytes)
	if !ok || len(application) == 0 || bytes.IndexByte(application, 0) >= 0 || len(publicFields) != 0 {
		return false
	}
	privateCurve, privateFields, ok := readOpenSSHPrivateKeyString(privateFields, maxOpenSSHPrivateKeyNameBytes)
	if !ok || !bytes.Equal(privateCurve, curve) {
		return false
	}
	privateValue, privateFields, ok := readOpenSSHPrivateKeyString(privateFields, maxPrivateKeyPEMBytes)
	if !ok || !bytes.Equal(privateValue, publicValue) {
		return false
	}
	privateApplication, privateFields, ok := readOpenSSHPrivateKeyString(privateFields, maxPrivateKeyPEMBytes)
	return ok && bytes.Equal(privateApplication, application) &&
		validOpenSSHSecurityKeyPrivateTail(privateFields)
}

func validOpenSSHSecurityKeyPrivateTail(remaining []byte) bool {
	if len(remaining) < 1 {
		return false
	}
	remaining = remaining[1:] // OpenSSH security-key flags.
	handle, remaining, ok := readOpenSSHPrivateKeyString(remaining, maxPrivateKeyPEMBytes)
	if !ok || len(handle) == 0 {
		return false
	}
	_, remaining, ok = readOpenSSHPrivateKeyString(remaining, maxPrivateKeyPEMBytes) // reserved
	if !ok {
		return false
	}
	comment, padding, ok := readOpenSSHPrivateKeyString(remaining, maxPrivateKeyPEMBytes)
	return ok && bytes.IndexByte(comment, 0) < 0 && validOpenSSHPrivateKeyPadding(padding)
}

func validOpenSSHPrivateKeyPadding(padding []byte) bool {
	for index, value := range padding {
		if int(value) != index+1 {
			return false
		}
	}
	return true
}

func readOpenSSHPrivateKeyString(encoded []byte, maxLength int) ([]byte, []byte, bool) {
	if len(encoded) < 4 {
		return nil, nil, false
	}
	length := binary.BigEndian.Uint32(encoded)
	if length > uint32(maxLength) || length > uint32(len(encoded)-4) {
		return nil, nil, false
	}
	end := 4 + int(length)
	return encoded[4:end], encoded[end:], true
}

func validPKCS8PrivateKey(decoded []byte) bool {
	elements, ok := privateKeyASN1Sequence(decoded)
	if !ok || len(elements) < 3 || len(elements) > 5 ||
		!privateKeyASN1Version(elements[0], 0, 1) {
		return false
	}

	algorithm, ok := privateKeyASN1Sequence(elements[1].FullBytes)
	if !ok || len(algorithm) < 1 || len(algorithm) > 2 {
		return false
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(algorithm[0].FullBytes, &oid)
	if err != nil || len(rest) != 0 || len(oid) < 2 {
		return false
	}
	if !privateKeyASN1OctetString(elements[2]) {
		return false
	}

	attributesSeen := false
	publicKeySeen := false
	for _, element := range elements[3:] {
		if element.Class != asn1.ClassContextSpecific {
			return false
		}
		switch element.Tag {
		case 0:
			if attributesSeen || publicKeySeen || !element.IsCompound {
				return false
			}
			attributesSeen = true
		case 1:
			if publicKeySeen || !privateKeyASN1Version(elements[0], 1) || len(element.Bytes) == 0 {
				return false
			}
			publicKeySeen = true
		default:
			return false
		}
	}
	return true
}

func validPKCS1PrivateKey(decoded []byte) bool {
	elements, ok := privateKeyASN1Sequence(decoded)
	if !ok || (len(elements) != 9 && len(elements) != 10) ||
		!privateKeyASN1Version(elements[0], 0, 1) {
		return false
	}
	for _, element := range elements[1:9] {
		if !privateKeyASN1PositiveInteger(element) {
			return false
		}
	}

	multiPrime := len(elements) == 10
	if privateKeyASN1Version(elements[0], 1) != multiPrime {
		return false
	}
	if !multiPrime {
		return true
	}
	additionalPrimes, ok := privateKeyASN1Sequence(elements[9].FullBytes)
	if !ok || len(additionalPrimes) == 0 {
		return false
	}
	for _, additionalPrime := range additionalPrimes {
		values, ok := privateKeyASN1Sequence(additionalPrime.FullBytes)
		if !ok || len(values) != 3 {
			return false
		}
		for _, value := range values {
			if !privateKeyASN1PositiveInteger(value) {
				return false
			}
		}
	}
	return true
}

func validSEC1PrivateKey(decoded []byte) bool {
	elements, ok := privateKeyASN1Sequence(decoded)
	if !ok || len(elements) < 2 || len(elements) > 4 ||
		!privateKeyASN1Version(elements[0], 1) || !privateKeyASN1OctetString(elements[1]) {
		return false
	}

	position := 2
	if position < len(elements) && elements[position].Class == asn1.ClassContextSpecific && elements[position].Tag == 0 {
		if !validSEC1Parameters(elements[position]) {
			return false
		}
		position++
	}
	if position < len(elements) && elements[position].Class == asn1.ClassContextSpecific && elements[position].Tag == 1 {
		if !validSEC1PublicKey(elements[position]) {
			return false
		}
		position++
	}
	return position == len(elements)
}

func validSEC1Parameters(value asn1.RawValue) bool {
	if !value.IsCompound {
		return false
	}
	var parameters asn1.RawValue
	rest, err := asn1.Unmarshal(value.Bytes, &parameters)
	if err != nil || len(rest) != 0 || parameters.Class != asn1.ClassUniversal {
		return false
	}
	switch parameters.Tag {
	case asn1.TagOID:
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(parameters.FullBytes, &oid)
		return err == nil && len(rest) == 0 && len(oid) >= 2
	case asn1.TagNull:
		return len(parameters.Bytes) == 0
	case asn1.TagSequence:
		elements, ok := privateKeyASN1Sequence(parameters.FullBytes)
		return ok && len(elements) > 0
	default:
		return false
	}
}

func validSEC1PublicKey(value asn1.RawValue) bool {
	if !value.IsCompound {
		return false
	}
	var publicKey asn1.BitString
	rest, err := asn1.Unmarshal(value.Bytes, &publicKey)
	return err == nil && len(rest) == 0 && publicKey.BitLength > 0
}

func validDSAPrivateKey(decoded []byte) bool {
	elements, ok := privateKeyASN1Sequence(decoded)
	if !ok || len(elements) != 6 || !privateKeyASN1Version(elements[0], 0) {
		return false
	}
	for _, element := range elements[1:] {
		if !privateKeyASN1PositiveInteger(element) {
			return false
		}
	}
	return true
}

func privateKeyASN1Sequence(encoded []byte) ([]asn1.RawValue, bool) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(encoded, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal ||
		sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, false
	}

	elements := make([]asn1.RawValue, 0, 8)
	remaining := sequence.Bytes
	for len(remaining) > 0 {
		if len(elements) >= maxPrivateKeyASN1Elements {
			return nil, false
		}
		var element asn1.RawValue
		next, err := asn1.Unmarshal(remaining, &element)
		if err != nil || len(next) >= len(remaining) {
			return nil, false
		}
		elements = append(elements, element)
		remaining = next
	}
	return elements, true
}

func privateKeyASN1Version(value asn1.RawValue, allowed ...byte) bool {
	if value.Class != asn1.ClassUniversal || value.Tag != asn1.TagInteger ||
		value.IsCompound || len(value.Bytes) != 1 {
		return false
	}
	for _, candidate := range allowed {
		if value.Bytes[0] == candidate {
			return true
		}
	}
	return false
}

func privateKeyASN1PositiveInteger(value asn1.RawValue) bool {
	if value.Class != asn1.ClassUniversal || value.Tag != asn1.TagInteger ||
		value.IsCompound || len(value.Bytes) == 0 || value.Bytes[0]&0x80 != 0 {
		return false
	}
	if len(value.Bytes) > 1 && value.Bytes[0] == 0 && value.Bytes[1]&0x80 == 0 {
		return false
	}
	for _, octet := range value.Bytes {
		if octet != 0 {
			return true
		}
	}
	return false
}

func privateKeyASN1OctetString(value asn1.RawValue) bool {
	return value.Class == asn1.ClassUniversal && value.Tag == asn1.TagOctetString &&
		!value.IsCompound && len(value.Bytes) > 0
}

func validLegacyEncryptedPrivateKey(label string, metadata map[string]string, ciphertext []byte) bool {
	if label != "RSA PRIVATE KEY" && label != "EC PRIVATE KEY" && label != "DSA PRIVATE KEY" {
		return false
	}
	if len(metadata) != 2 || metadata["Proc-Type"] != "4,ENCRYPTED" {
		return false
	}
	dekParts := strings.Split(metadata["DEK-Info"], ",")
	if len(dekParts) != 2 {
		return false
	}
	blockSize, ok := legacyPEMCipherBlockSize(dekParts[0])
	if !ok || len(ciphertext) < blockSize || len(ciphertext)%blockSize != 0 {
		return false
	}
	iv, err := hex.DecodeString(dekParts[1])
	return err == nil && len(iv) == blockSize
}

func legacyPEMCipherBlockSize(cipherName string) (int, bool) {
	switch cipherName {
	case "DES-CBC", "DES-EDE3-CBC":
		return 8, true
	case "AES-128-CBC", "AES-192-CBC", "AES-256-CBC":
		return 16, true
	default:
		return 0, false
	}
}

func validOpenPGPPrivateKey(decoded []byte) bool {
	reader := bytes.NewReader(decoded)
	privateKeySeen := false
	for reader.Len() > 0 {
		parsed, err := packet.Read(reader)
		if err != nil {
			return false
		}
		if _, ok := parsed.(*packet.PrivateKey); ok {
			privateKeySeen = true
		}
	}
	return privateKeySeen
}

func isBase64Byte(character byte) bool {
	return (character >= 'A' && character <= 'Z') ||
		(character >= 'a' && character <= 'z') ||
		(character >= '0' && character <= '9') ||
		character == '+' || character == '/'
}
