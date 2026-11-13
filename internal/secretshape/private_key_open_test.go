// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package secretshape

import (
	"strings"
	"testing"

	privatekeyfixture "github.com/defenseclaw/defenseclaw/internal/secretshape/testfixture"
)

func TestOpenPrivateKeyPEMStart(t *testing.T) {
	block := privatekeyfixture.MustPEM("RSA PRIVATE KEY")
	prefix := "Here is the key:\n"
	text := prefix + block
	footer := strings.Index(text, "-----END ")
	for cut := len(prefix); cut <= len(text); cut++ {
		got := OpenPrivateKeyPEMStart(text[:cut])
		open := cut < footer+len("-----END RSA PRIVATE KEY-----")
		// Before "-----BEGIN " is complete the header is a word still being
		// written; the stream guard holds a trailing word on its own.
		if open && cut >= len(prefix)+len("-----BEGIN ") && got != len(prefix) {
			t.Fatalf("cut %d: open block reported at %d, want %d", cut, got, len(prefix))
		}
		if !open && got != -1 {
			t.Fatalf("cut %d: closed block reported open at %d", cut, got)
		}
	}
	if got := OpenPrivateKeyPEMStart("-----BEGIN CERTIFICATE-----\nMIIB\n"); got != -1 {
		t.Fatalf("certificate header reported as an open private key at %d", got)
	}
}
