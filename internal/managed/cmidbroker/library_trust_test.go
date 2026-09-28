// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckLibrarySignerAcceptsOnlyTheCiscoPublisher(t *testing.T) {
	fingerprint := strings.Repeat("ab", 32)
	if err := CheckLibrarySigner(LibrarySigner{
		SimpleName:        "Cisco Systems, Inc.",
		CertificateSHA256: fingerprint,
	}); err != nil {
		t.Fatalf("Cisco publisher rejected: %v", err)
	}
	for _, name := range []string{
		"",
		"Microsoft Corporation",
		"Cisco Systems Inc.",
		"cisco systems, inc.",
		"Cisco Systems, Inc. ",
		" Cisco Systems, Inc.",
		"Cisco Systems, Inc.\x00",
	} {
		err := CheckLibrarySigner(LibrarySigner{SimpleName: name, CertificateSHA256: fingerprint})
		if !errors.Is(err, ErrLibrarySigner) {
			t.Fatalf("publisher %q: error = %v, want ErrLibrarySigner", name, err)
		}
		if !strings.Contains(err.Error(), fingerprint) {
			t.Fatalf("publisher %q: error does not name the signer certificate: %v", name, err)
		}
	}
}
