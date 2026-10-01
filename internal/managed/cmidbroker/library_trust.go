// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// CMIDLibraryPublisher is the Authenticode publisher of the Cisco Secure
// Client Cloud Management identity library (cmidapi.dll). It is compared with
// the one common name (CN attribute) in the signer certificate's subject, the
// same rule the enterprise lifecycle module, its installer, and Setup
// assembly apply.
const CMIDLibraryPublisher = "Cisco Systems, Inc."

var (
	// ErrLibrarySignature reports a library whose Authenticode signature is
	// missing, invalid, or does not chain to a trusted root.
	ErrLibrarySignature = errors.New("the Cloud Management identity library has no valid Authenticode signature")
	// ErrLibrarySigner reports a validly signed library from a publisher
	// other than CMIDLibraryPublisher.
	ErrLibrarySigner = errors.New("the Cloud Management identity library is not signed by " + CMIDLibraryPublisher)
)

// LibrarySigner identifies the certificate that produced a library's verified
// Authenticode signature.
type LibrarySigner struct {
	// CommonName is the one common name (CN attribute) in the signer
	// certificate's subject, or "" when the subject has none, more than one,
	// or one that is not a string. The simple display name is not used: for
	// a subject without a CN, Windows displays its OU, O, or e-mail address
	// instead, so it would let OU=Cisco Systems, Inc. pass as the publisher.
	CommonName string
	// CertificateSHA256 is the lowercase hex SHA-256 of the DER certificate.
	CertificateSHA256 string
}

// CheckLibrarySigner accepts only the Cisco Secure Client publisher. The
// comparison is exact: a case-folded or punctuation near miss is a different
// publisher.
func CheckLibrarySigner(signer LibrarySigner) error {
	if signer.CommonName == "" {
		return fmt.Errorf(
			"%w: signer certificate has no single subject common name (certificate SHA-256 %s)",
			ErrLibrarySigner,
			signer.CertificateSHA256,
		)
	}
	if signer.CommonName != CMIDLibraryPublisher {
		return fmt.Errorf(
			"%w: signer is %q (certificate SHA-256 %s)",
			ErrLibrarySigner,
			signer.CommonName,
			signer.CertificateSHA256,
		)
	}
	return nil
}

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// subjectAttribute and subjectAttributeSET mirror X.509's
// AttributeTypeAndValue and RelativeDistinguishedName. Values stay raw so an
// attribute other than the common name cannot make the subject unreadable.
type subjectAttribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type subjectAttributeSET []subjectAttribute

// subjectCommonName returns the one common name in a DER-encoded X.509 Name,
// or "" when the name is malformed, has no common name, has more than one, or
// has one that is not a UTF8String, PrintableString, IA5String, or BMPString.
func subjectCommonName(rawSubject []byte) string {
	var name []subjectAttributeSET
	rest, err := asn1.Unmarshal(rawSubject, &name)
	if err != nil || len(rest) != 0 {
		return ""
	}
	commonName, found := "", 0
	for _, rdn := range name {
		for _, attribute := range rdn {
			if !attribute.Type.Equal(oidCommonName) {
				continue
			}
			value, ok := directoryString(attribute.Value)
			if !ok {
				return ""
			}
			commonName = value
			found++
		}
	}
	if found != 1 {
		return ""
	}
	return commonName
}

func directoryString(value asn1.RawValue) (string, bool) {
	if value.Class != asn1.ClassUniversal || value.IsCompound {
		return "", false
	}
	switch value.Tag {
	case asn1.TagUTF8String, asn1.TagPrintableString, asn1.TagIA5String:
		if !utf8.Valid(value.Bytes) {
			return "", false
		}
		return string(value.Bytes), true
	case asn1.TagBMPString:
		if len(value.Bytes)%2 != 0 {
			return "", false
		}
		units := make([]uint16, len(value.Bytes)/2)
		for index := range units {
			units[index] = uint16(value.Bytes[2*index])<<8 | uint16(value.Bytes[2*index+1])
		}
		return string(utf16.Decode(units)), true
	default:
		return "", false
	}
}
