// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactOpenSSLPKCS12PrivateKeyExtraction(t *testing.T) {
	for _, command := range []string{
		"openssl pkcs12 -in /tmp/account.pfx -nodes -passin pass:",
		"openssl pkcs12 -legacy -nocerts -in ./identity.pkcs12 -passin file:/tmp/pass -nodes",
		`openssl.exe pkcs12 -in C:\\Temp\\identity.p12 -nodes`,
	} {
		facts := Analyze(Input{Tool: "execute_command", Command: command})
		if !ExactOpenSSLPKCS12PrivateKeyExtraction(facts) {
			t.Fatalf("exact extraction not classified: %q: %+v", command, facts)
		}
	}
}

func TestOpenSSLPKCS12PrivateKeyExtractionHardNegatives(t *testing.T) {
	for _, command := range []string{
		"openssl pkcs12 -in /tmp/account.pfx -nokeys",
		"openssl pkcs12 -in /tmp/account.pfx -noout -info",
		"openssl pkcs12 -in /tmp/account.pem -nodes",
		"openssl pkcs12 -in $BUNDLE -nodes",
		"openssl pkcs12 -in /tmp/account.pfx -nodes -out /tmp/key.pem",
		"openssl pkcs12 -help",
		"echo 'openssl pkcs12 -in /tmp/account.pfx -nodes'",
		"openssl pkcs12 -in /tmp/account.pfx -nodes | sed -n 1,20p",
	} {
		facts := Analyze(Input{Tool: "execute_command", Command: command})
		if ExactOpenSSLPKCS12PrivateKeyExtraction(facts) {
			t.Fatalf("hard negative classified: %q: %+v", command, facts)
		}
	}
}

func TestBashLoginPKCS12PrivateKeyExtractionDetectionOnly(t *testing.T) {
	command := `bash -lc 'ls -l /tmp/account.pfx; openssl pkcs12 -in /tmp/account.pfx -nodes -passin pass: 2>/dev/null | sed -n "1,20p"'`
	facts := Analyze(Input{Tool: "execute_command", Command: command})
	if facts.Authoritative() || facts.EnforcementEligible() ||
		!ExactOpenSSLPKCS12PrivateKeyExtraction(facts) {
		t.Fatalf("login-wrapper extraction boundary=%+v", facts)
	}
}
