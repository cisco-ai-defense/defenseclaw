// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"errors"
	"fmt"
)

// CMIDLibraryPublisher is the Authenticode publisher of the Cisco Secure
// Client Cloud Management identity library (cmidapi.dll). It is compared with
// the signer certificate's simple display name, the same value PowerShell's
// X509Certificate2.GetNameInfo(SimpleName) reports and the enterprise
// installer pins.
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
	// SimpleName is the signer certificate's simple display name.
	SimpleName string
	// CertificateSHA256 is the lowercase hex SHA-256 of the DER certificate.
	CertificateSHA256 string
}

// CheckLibrarySigner accepts only the Cisco Secure Client publisher. The
// comparison is exact: a case-folded or punctuation near miss is a different
// publisher.
func CheckLibrarySigner(signer LibrarySigner) error {
	if signer.SimpleName != CMIDLibraryPublisher {
		return fmt.Errorf(
			"%w: signer is %q (certificate SHA-256 %s)",
			ErrLibrarySigner,
			signer.SimpleName,
			signer.CertificateSHA256,
		)
	}
	return nil
}
