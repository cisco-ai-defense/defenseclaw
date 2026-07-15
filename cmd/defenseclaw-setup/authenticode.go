// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	authenticodeInventorySchemaVersion = 1
	authenticodeEvidenceSchemaVersion  = 1
	productAuthenticodePolicy          = "defenseclaw-product-publisher"
	pinnedInputAuthenticodePolicy      = "pinned-input-observation"
	digestOnlyAuthenticodePolicy       = "digest-only-upstream"
)

var (
	cmsSignedDataOID       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	rfc3161TimestampOID    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
	nestedAuthenticodeOID  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
	requiredProductPEPaths = []string{
		"bin/defenseclaw.exe",
		"bin/skill-scanner.exe",
		"bin/mcp-scanner.exe",
		"bin/defenseclaw-observability.exe",
		"bin/defenseclaw-startup.exe",
		"bin/defenseclaw-gateway.exe",
		"bin/defenseclaw-hook.exe",
	}
)

func validLowerSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validPortableRelativePath(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.Contains(value, `\`) ||
		strings.Contains(value, ":") || path.IsAbs(value) || path.Clean(value) != value {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." ||
			strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return false
		}
		for _, char := range segment {
			if char < 0x20 || char > 0x7e || strings.ContainsRune(`<>:"/\|?*`, char) {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
				base[3] >= '1' && base[3] <= '9') {
			return false
		}
	}
	return true
}

func validateEmptyAuthenticodeIdentity(policy authenticodeFilePolicy) error {
	if policy.Publisher != "" || policy.SignerThumbprintSHA256 != "" ||
		policy.TimestampSignerThumbprintSHA256 != "" || policy.TimestampTokenSHA256 != "" ||
		policy.TimestampRequired {
		return errors.New("unsigned/digest-only policy contains signer or timestamp identity")
	}
	return nil
}

func validateAuthenticodeManifest(manifest payloadManifest) error {
	inventory := manifest.Authenticode
	if inventory.SchemaVersion != authenticodeInventorySchemaVersion || len(inventory.Files) == 0 {
		return errors.New("payload Authenticode inventory is missing or unsupported")
	}
	requiredProducts := make(map[string]bool, len(requiredProductPEPaths))
	for _, name := range requiredProductPEPaths {
		requiredProducts[name] = false
	}
	seenFolded := make(map[string]string, len(inventory.Files))
	pythonPEs := 0
	cosignSeen := false
	productSigner := ""
	for key, evidence := range inventory.Files {
		if evidence.SchemaVersion != authenticodeEvidenceSchemaVersion {
			return fmt.Errorf("unsupported Authenticode evidence schema for %s", key)
		}
		if key != evidence.InstalledPath || !validPortableRelativePath(key) {
			return fmt.Errorf("invalid Authenticode installed path %q", key)
		}
		folded := strings.ToLower(key)
		if previous, exists := seenFolded[folded]; exists {
			return fmt.Errorf("case-colliding Authenticode installed paths %q and %q", previous, key)
		}
		seenFolded[folded] = key
		if !strings.HasPrefix(evidence.SBOMFileName, "./") ||
			!validPortableRelativePath(strings.TrimPrefix(evidence.SBOMFileName, "./")) {
			return fmt.Errorf("invalid Authenticode SPDX file identity for %s", key)
		}
		if !validLowerSHA256(evidence.SHA256) {
			return fmt.Errorf("invalid Authenticode SHA-256 for %s", key)
		}
		var observed map[string]json.RawMessage
		if len(evidence.Observed) == 0 || json.Unmarshal(evidence.Observed, &observed) != nil ||
			len(observed) == 0 || observed["embedded_signatures"] == nil {
			return fmt.Errorf("invalid Authenticode observation for %s", key)
		}

		policy := evidence.Expected
		switch policy.Policy {
		case productAuthenticodePolicy:
			if _, required := requiredProducts[key]; !required {
				return fmt.Errorf("unexpected DefenseClaw product Authenticode path %s", key)
			}
			requiredProducts[key] = true
			if !policy.PlatformIdentityRequired {
				return fmt.Errorf("DefenseClaw product platform identity is not required for %s", key)
			}
			if manifest.Unsigned {
				if policy.Status != "NotSigned" || policy.SignatureType != "None" {
					return fmt.Errorf("unsigned local product has a signed policy for %s", key)
				}
				if err := validateEmptyAuthenticodeIdentity(policy); err != nil {
					return fmt.Errorf("invalid unsigned local product policy for %s: %w", key, err)
				}
			} else {
				if policy.Status != "Valid" || policy.SignatureType != "Authenticode" ||
					policy.Publisher != defaultPublisher || !policy.TimestampRequired ||
					!validLowerSHA256(policy.SignerThumbprintSHA256) ||
					!validLowerSHA256(policy.TimestampSignerThumbprintSHA256) ||
					!validLowerSHA256(policy.TimestampTokenSHA256) {
					return fmt.Errorf("invalid signed DefenseClaw product policy for %s", key)
				}
				if productSigner == "" {
					productSigner = policy.SignerThumbprintSHA256
				} else if productSigner != policy.SignerThumbprintSHA256 {
					return errors.New("DefenseClaw product executables have inconsistent signer identities")
				}
			}
		case pinnedInputAuthenticodePolicy:
			if !strings.HasPrefix(key, "runtime/python/") || policy.PlatformIdentityRequired ||
				(policy.Status != "Valid" && policy.Status != "NotSigned") ||
				policy.Publisher != "" || policy.SignatureType != "" || policy.TimestampRequired ||
				policy.SignerThumbprintSHA256 != "" || policy.TimestampSignerThumbprintSHA256 != "" ||
				policy.TimestampTokenSHA256 != "" {
				return fmt.Errorf("invalid pinned Python Authenticode policy for %s", key)
			}
			pythonPEs++
		case digestOnlyAuthenticodePolicy:
			if key != "runtime/tools/cosign.exe" || policy.Status != "NotSigned" ||
				policy.SignatureType != "None" || !policy.PlatformIdentityRequired {
				return fmt.Errorf("invalid digest-only Authenticode policy for %s", key)
			}
			if err := validateEmptyAuthenticodeIdentity(policy); err != nil {
				return fmt.Errorf("invalid digest-only policy for %s: %w", key, err)
			}
			cosignSeen = true
		default:
			return fmt.Errorf("unsupported Authenticode policy %q for %s", policy.Policy, key)
		}
	}
	for name, present := range requiredProducts {
		if !present {
			return fmt.Errorf("AuthentiCode inventory is missing required product executable %s", name)
		}
	}
	if pythonPEs == 0 {
		return errors.New("AuthentiCode inventory contains no managed Python portable executables")
	}
	if !cosignSeen {
		return errors.New("AuthentiCode inventory is missing the managed Cosign executable")
	}
	directDigests := map[string]string{
		"bin/defenseclaw.exe":               manifest.Files[manifest.Launcher],
		"bin/skill-scanner.exe":             manifest.Files[manifest.Launcher],
		"bin/mcp-scanner.exe":               manifest.Files[manifest.Launcher],
		"bin/defenseclaw-observability.exe": manifest.Files[manifest.Launcher],
		"bin/defenseclaw-startup.exe":       manifest.Files[manifest.StartupLauncher],
		"runtime/tools/cosign.exe":          manifest.Files[manifest.CosignVerifier],
	}
	for installedPath, digest := range directDigests {
		evidence, ok := inventory.Files[installedPath]
		if !ok || digest == "" || !strings.EqualFold(evidence.SHA256, digest) {
			return fmt.Errorf("AuthentiCode evidence does not bind direct payload file %s", installedPath)
		}
	}
	return nil
}

func isPortableExecutableFile(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	header := make([]byte, 64)
	if _, err := file.ReadAt(header, 0); err != nil {
		return false, nil
	}
	if binary.LittleEndian.Uint16(header[:2]) != 0x5a4d {
		return false, nil
	}
	peOffset := int64(int32(binary.LittleEndian.Uint32(header[0x3c:0x40])))
	if peOffset < 0 {
		return false, nil
	}
	signature := make([]byte, 4)
	if _, err := file.ReadAt(signature, peOffset); err != nil {
		return false, nil
	}
	return binary.LittleEndian.Uint32(signature) == 0x00004550, nil
}

func verifyInstalledPEInventory(root string, manifest payloadManifest) error {
	return verifyInstalledPEInventoryWith(root, manifest, verifyEmbeddedAuthenticodeTrust)
}

func verifyInstalledPEInventoryWith(
	root string,
	manifest payloadManifest,
	trustVerifier func(string) error,
) error {
	if err := validateAuthenticodeManifest(manifest); err != nil {
		return err
	}
	verified := make(map[string]bool, len(manifest.Authenticode.Files))
	for name, evidence := range manifest.Authenticode.Files {
		full, err := safeJoin(root, name)
		if err != nil {
			return err
		}
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("inventoried portable executable is missing or invalid: %s", name)
		}
		isPE, err := isPortableExecutableFile(full)
		if err != nil || !isPE {
			return fmt.Errorf("inventoried file is not a portable executable: %s", name)
		}
		digest, err := fileSHA256(full)
		if err != nil {
			return fmt.Errorf("hash inventoried portable executable %s: %w", name, err)
		}
		if digest != evidence.SHA256 {
			return fmt.Errorf("installed portable executable hash mismatch for %s", name)
		}
		if err := verifyInstalledAuthenticodePolicyWith(full, evidence.Expected, trustVerifier); err != nil {
			return fmt.Errorf("verify installed Authenticode policy for %s: %w", name, err)
		}
		verified[name] = true
	}
	err := filepath.WalkDir(root, func(filePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		isPE, err := isPortableExecutableFile(filePath)
		if err != nil {
			return err
		}
		if !isPE {
			return nil
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if _, present := manifest.Authenticode.Files[rel]; !present {
			return fmt.Errorf("unlisted portable executable in install tree: %s", rel)
		}
		if !verified[rel] {
			return fmt.Errorf("portable executable path casing differs from Authenticode inventory: %s", rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(verified) != len(manifest.Authenticode.Files) {
		return errors.New("installed Authenticode inventory verification was incomplete")
	}
	return nil
}

type embeddedAuthenticodeMetadata struct {
	Present                 bool
	PublisherMatchesCisco   bool
	SignerThumbprintSHA256  string
	RFC3161TimestampPresent bool
	NestedSignaturePresent  bool
}

type cmsIssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

func takeASN1(input []byte) (asn1.RawValue, []byte, error) {
	var value asn1.RawValue
	rest, err := asn1.Unmarshal(input, &value)
	if err != nil {
		return asn1.RawValue{}, nil, err
	}
	return value, rest, nil
}

func readEmbeddedPKCS7(filePath string) ([]byte, bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, false, err
	}
	if len(data) < 64 || binary.LittleEndian.Uint16(data[:2]) != 0x5a4d {
		return nil, false, errors.New("file is not a portable executable")
	}
	peOffset := int64(int32(binary.LittleEndian.Uint32(data[0x3c:0x40])))
	if peOffset < 0 || peOffset+24 > int64(len(data)) ||
		binary.LittleEndian.Uint32(data[peOffset:peOffset+4]) != 0x00004550 {
		return nil, false, errors.New("portable executable has an invalid PE header")
	}
	optionalSize := int64(binary.LittleEndian.Uint16(data[peOffset+20 : peOffset+22]))
	optionalOffset := peOffset + 24
	if optionalSize < 0 || optionalOffset+optionalSize > int64(len(data)) || optionalSize < 136 {
		return nil, false, errors.New("portable executable has an invalid optional header")
	}
	magic := binary.LittleEndian.Uint16(data[optionalOffset : optionalOffset+2])
	dataDirectoriesOffset := int64(0)
	switch magic {
	case 0x10b:
		dataDirectoriesOffset = optionalOffset + 96
	case 0x20b:
		dataDirectoriesOffset = optionalOffset + 112
	default:
		return nil, false, errors.New("portable executable has an unsupported optional header")
	}
	if dataDirectoriesOffset+40 > optionalOffset+optionalSize {
		return nil, false, errors.New("portable executable omits the security directory")
	}
	certificateOffset := int64(binary.LittleEndian.Uint32(data[dataDirectoriesOffset+32 : dataDirectoriesOffset+36]))
	certificateSize := int64(binary.LittleEndian.Uint32(data[dataDirectoriesOffset+36 : dataDirectoriesOffset+40]))
	if certificateOffset == 0 && certificateSize == 0 {
		return nil, false, nil
	}
	if certificateOffset <= 0 || certificateSize < 8 || certificateOffset+certificateSize > int64(len(data)) {
		return nil, false, errors.New("portable executable has an invalid certificate table")
	}
	var selected []byte
	for cursor, end := certificateOffset, certificateOffset+certificateSize; cursor+8 <= end; {
		length := int64(binary.LittleEndian.Uint32(data[cursor : cursor+4]))
		certificateType := binary.LittleEndian.Uint16(data[cursor+6 : cursor+8])
		if length < 8 || cursor+length > end {
			return nil, false, errors.New("portable executable has a malformed WIN_CERTIFICATE record")
		}
		if certificateType == 0x0002 {
			if selected != nil {
				return nil, false, errors.New("portable executable has multiple PKCS#7 certificate-table records")
			}
			selected = append([]byte(nil), data[cursor+8:cursor+length]...)
		}
		cursor += (length + 7) &^ 7
	}
	if selected == nil {
		return nil, false, errors.New("portable executable certificate table has no PKCS#7 signature")
	}
	return selected, true, nil
}

func parseCertificateSet(raw asn1.RawValue) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	remaining := raw.Bytes
	for len(remaining) > 0 {
		candidate, rest, err := takeASN1(remaining)
		if err != nil {
			return nil, err
		}
		remaining = rest
		if candidate.Class != asn1.ClassUniversal || candidate.Tag != asn1.TagSequence {
			continue
		}
		certificate, err := x509.ParseCertificate(candidate.FullBytes)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
	}
	if len(certificates) == 0 {
		return nil, errors.New("Authenticode SignedData has no X.509 certificates")
	}
	return certificates, nil
}

func countAttributeValues(values asn1.RawValue) (int, error) {
	count := 0
	remaining := values.Bytes
	for len(remaining) > 0 {
		_, rest, err := takeASN1(remaining)
		if err != nil {
			return 0, err
		}
		count++
		remaining = rest
	}
	return count, nil
}

func inspectEmbeddedAuthenticode(filePath string) (embeddedAuthenticodeMetadata, error) {
	pkcs7, present, err := readEmbeddedPKCS7(filePath)
	if err != nil || !present {
		return embeddedAuthenticodeMetadata{Present: present}, err
	}
	contentInfo, rest, err := takeASN1(pkcs7)
	if err != nil {
		return embeddedAuthenticodeMetadata{}, fmt.Errorf("parse Authenticode PKCS#7 ContentInfo: %w", err)
	}
	if contentInfo.Class != asn1.ClassUniversal || contentInfo.Tag != asn1.TagSequence {
		return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode PKCS#7 ContentInfo tag")
	}
	if len(rest) != 0 && !bytes.Equal(rest, make([]byte, len(rest))) {
		return embeddedAuthenticodeMetadata{}, errors.New("non-zero trailing data after Authenticode PKCS#7 ContentInfo")
	}
	contentTypeRaw, contentRemaining, err := takeASN1(contentInfo.Bytes)
	if err != nil {
		return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode PKCS#7 content type")
	}
	var contentType asn1.ObjectIdentifier
	if trailing, err := asn1.Unmarshal(contentTypeRaw.FullBytes, &contentType); err != nil || len(trailing) != 0 ||
		!contentType.Equal(cmsSignedDataOID) {
		return embeddedAuthenticodeMetadata{}, errors.New("unsupported Authenticode PKCS#7 content type")
	}
	explicitContent, trailing, err := takeASN1(contentRemaining)
	if err != nil || len(trailing) != 0 || explicitContent.Class != asn1.ClassContextSpecific ||
		explicitContent.Tag != 0 {
		return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode PKCS#7 explicit content")
	}
	signedData, trailing, err := takeASN1(explicitContent.Bytes)
	if err != nil || len(trailing) != 0 || signedData.Class != asn1.ClassUniversal ||
		signedData.Tag != asn1.TagSequence {
		return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode SignedData")
	}
	remaining := signedData.Bytes
	for range 3 { // version, digestAlgorithms, encapContentInfo
		_, remaining, err = takeASN1(remaining)
		if err != nil {
			return embeddedAuthenticodeMetadata{}, errors.New("truncated Authenticode SignedData")
		}
	}
	certificatesRaw, rest, err := takeASN1(remaining)
	if err != nil || certificatesRaw.Class != asn1.ClassContextSpecific || certificatesRaw.Tag != 0 {
		return embeddedAuthenticodeMetadata{}, errors.New("Authenticode SignedData has no certificate set")
	}
	remaining = rest
	certificates, err := parseCertificateSet(certificatesRaw)
	if err != nil {
		return embeddedAuthenticodeMetadata{}, err
	}
	if len(remaining) > 0 {
		candidate, rest, err := takeASN1(remaining)
		if err != nil {
			return embeddedAuthenticodeMetadata{}, err
		}
		if candidate.Class == asn1.ClassContextSpecific && candidate.Tag == 1 {
			remaining = rest // optional CRLs
		}
	}
	signerInfos, rest, err := takeASN1(remaining)
	if err != nil || len(rest) != 0 || signerInfos.Class != asn1.ClassUniversal ||
		signerInfos.Tag != asn1.TagSet {
		return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode signer set")
	}
	signerInfo, extraSigners, err := takeASN1(signerInfos.Bytes)
	if err != nil || len(extraSigners) != 0 || signerInfo.Tag != asn1.TagSequence {
		return embeddedAuthenticodeMetadata{}, errors.New("AuthentiCode requires exactly one top-level signer")
	}
	signerRemaining := signerInfo.Bytes
	_, signerRemaining, err = takeASN1(signerRemaining) // version
	if err != nil {
		return embeddedAuthenticodeMetadata{}, errors.New("truncated Authenticode signer")
	}
	signerID, signerRemaining, err := takeASN1(signerRemaining)
	if err != nil || signerID.Class != asn1.ClassUniversal || signerID.Tag != asn1.TagSequence {
		return embeddedAuthenticodeMetadata{}, errors.New("unsupported Authenticode signer identifier")
	}
	var issuerAndSerial cmsIssuerAndSerial
	if trailing, err := asn1.Unmarshal(signerID.FullBytes, &issuerAndSerial); err != nil || len(trailing) != 0 ||
		issuerAndSerial.SerialNumber == nil {
		return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode signer identifier")
	}
	var signer *x509.Certificate
	for _, certificate := range certificates {
		if bytes.Equal(certificate.RawIssuer, issuerAndSerial.Issuer.FullBytes) &&
			certificate.SerialNumber.Cmp(issuerAndSerial.SerialNumber) == 0 {
			signer = certificate
			break
		}
	}
	if signer == nil {
		return embeddedAuthenticodeMetadata{}, errors.New("AuthentiCode signer certificate is absent")
	}
	_, signerRemaining, err = takeASN1(signerRemaining) // digestAlgorithm
	if err != nil {
		return embeddedAuthenticodeMetadata{}, errors.New("truncated Authenticode signer digest")
	}
	if len(signerRemaining) > 0 {
		candidate, rest, err := takeASN1(signerRemaining)
		if err != nil {
			return embeddedAuthenticodeMetadata{}, err
		}
		if candidate.Class == asn1.ClassContextSpecific && candidate.Tag == 0 {
			signerRemaining = rest // optional signedAttrs
		}
	}
	for range 2 { // signatureAlgorithm, signature
		_, signerRemaining, err = takeASN1(signerRemaining)
		if err != nil {
			return embeddedAuthenticodeMetadata{}, errors.New("truncated Authenticode signature value")
		}
	}
	timestampPresent := false
	nestedPresent := false
	if len(signerRemaining) > 0 {
		unsignedAttributes, rest, err := takeASN1(signerRemaining)
		if err != nil || len(rest) != 0 || unsignedAttributes.Class != asn1.ClassContextSpecific ||
			unsignedAttributes.Tag != 1 {
			return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode unsigned attributes")
		}
		attributeBytes := unsignedAttributes.Bytes
		for len(attributeBytes) > 0 {
			rawAttribute, rest, err := takeASN1(attributeBytes)
			if err != nil {
				return embeddedAuthenticodeMetadata{}, err
			}
			attributeBytes = rest
			var attribute cmsAttribute
			if trailing, err := asn1.Unmarshal(rawAttribute.FullBytes, &attribute); err != nil || len(trailing) != 0 {
				return embeddedAuthenticodeMetadata{}, errors.New("invalid Authenticode unsigned attribute")
			}
			valueCount, err := countAttributeValues(attribute.Values)
			if err != nil || valueCount == 0 {
				return embeddedAuthenticodeMetadata{}, errors.New("empty Authenticode unsigned attribute")
			}
			if attribute.Type.Equal(rfc3161TimestampOID) {
				if valueCount != 1 || timestampPresent {
					return embeddedAuthenticodeMetadata{}, errors.New("AuthentiCode has an ambiguous RFC3161 timestamp")
				}
				timestampPresent = true
			}
			if attribute.Type.Equal(nestedAuthenticodeOID) {
				nestedPresent = true
			}
		}
	}
	digest := sha256.Sum256(signer.Raw)
	publisherMatches := signer.Subject.CommonName == defaultPublisher
	for _, organization := range signer.Subject.Organization {
		publisherMatches = publisherMatches || organization == defaultPublisher
	}
	return embeddedAuthenticodeMetadata{
		Present:                 true,
		PublisherMatchesCisco:   publisherMatches,
		SignerThumbprintSHA256:  hex.EncodeToString(digest[:]),
		RFC3161TimestampPresent: timestampPresent,
		NestedSignaturePresent:  nestedPresent,
	}, nil
}

func verifyInstalledAuthenticodePolicy(filePath string, policy authenticodeFilePolicy) error {
	return verifyInstalledAuthenticodePolicyWith(filePath, policy, verifyEmbeddedAuthenticodeTrust)
}

func verifyInstalledAuthenticodePolicyWith(
	filePath string,
	policy authenticodeFilePolicy,
	trustVerifier func(string) error,
) error {
	metadata, err := inspectEmbeddedAuthenticode(filePath)
	if err != nil {
		return err
	}
	if policy.Status == "NotSigned" {
		if metadata.Present {
			return errors.New("expected an unsigned executable but found embedded Authenticode")
		}
		return nil
	}
	if policy.Status != "Valid" || !metadata.Present {
		return errors.New("signed executable has no embedded Authenticode signature")
	}
	if trustVerifier == nil {
		return errors.New("Authenticode trust verifier is unavailable")
	}
	if err := trustVerifier(filePath); err != nil {
		return err
	}
	if policy.Policy != productAuthenticodePolicy {
		return nil
	}
	if !metadata.PublisherMatchesCisco || metadata.SignerThumbprintSHA256 != policy.SignerThumbprintSHA256 {
		return errors.New("DefenseClaw signer identity does not match the signed payload manifest")
	}
	if policy.TimestampRequired && !metadata.RFC3161TimestampPresent {
		return errors.New("DefenseClaw executable has no RFC3161 timestamp")
	}
	if metadata.NestedSignaturePresent {
		return errors.New("DefenseClaw executable unexpectedly contains a nested Authenticode signature")
	}
	return nil
}

func verifySetupExecutablePolicyAt(filePath string, unsignedLocal bool) error {
	metadata, err := inspectEmbeddedAuthenticode(filePath)
	if err != nil {
		return err
	}
	if unsignedLocal {
		if metadata.Present {
			return errors.New("unsigned local setup policy conflicts with an embedded signature")
		}
		return nil
	}
	if !metadata.Present || !metadata.PublisherMatchesCisco || !metadata.RFC3161TimestampPresent ||
		metadata.NestedSignaturePresent {
		return errors.New("release setup lacks the required Cisco RFC3161 Authenticode identity")
	}
	return verifyEmbeddedAuthenticodeTrust(filePath)
}
