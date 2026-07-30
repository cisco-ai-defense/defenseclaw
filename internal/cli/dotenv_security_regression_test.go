// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func unsetEnvironmentForDotenvTest(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		value, present := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}

func TestLoadDotEnvIntoOSRejectsProcessControlAndMalformedEntries(t *testing.T) {
	allowed := []string{
		"DC_SECURITY_TEST_CREDENTIAL",
		"DC_SECURITY_TEST_CREDENTIAL_AFTER",
	}
	rejected := []string{
		"1INVALID",
		"BAD-KEY",
		"NUL_VALUE",
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
		"PYTHONPATH",
		"BASH_ENV",
		"DEFENSECLAW_GATEWAY_BIN",
		"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT",
		"DEFENSECLAW_DISABLE_REDACTION",
		"DEFENSECLAW_DAEMON",
		"CLAUDE_CONFIG_DIR",
		"NODE_OPTIONS",
		"SSL_CERT_DIR",
		"SSL_CERT_FILE",
		"NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
		"GIT_SSL_NO_VERIFY",
	}
	unsetEnvironmentForDotenvTest(t, append(allowed, rejected...)...)

	path := filepath.Join(t.TempDir(), ".env")
	body := []byte(
		"DC_SECURITY_TEST_CREDENTIAL=credential-before\n" +
			"1INVALID=ignored\n" +
			"BAD-KEY=ignored\n" +
			"NUL_VALUE=before\x00after\n" +
			"LD_PRELOAD=/tmp/attacker.so\n" +
			"DYLD_INSERT_LIBRARIES=/tmp/attacker.dylib\n" +
			"PYTHONPATH=/tmp/attacker-python\n" +
			"BASH_ENV=/tmp/attacker-shell\n" +
			"DEFENSECLAW_GATEWAY_BIN=/tmp/attacker-gateway\n" +
			"DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1\n" +
			"DEFENSECLAW_DISABLE_REDACTION=1\n" +
			"DEFENSECLAW_DAEMON=1\n" +
			"CLAUDE_CONFIG_DIR=/tmp/attacker-claude-home\n" +
			"NODE_OPTIONS=--require=/tmp/attacker.js\n" +
			"SSL_CERT_DIR=/tmp/attacker-ca-directory\n" +
			"SSL_CERT_FILE=/tmp/attacker-ca.pem\n" +
			"NODE_EXTRA_CA_CERTS=/tmp/attacker-node-ca.pem\n" +
			"REQUESTS_CA_BUNDLE=/tmp/attacker-requests-ca.pem\n" +
			"CURL_CA_BUNDLE=/tmp/attacker-curl-ca.pem\n" +
			"GIT_SSL_NO_VERIFY=true\n" +
			"DC_SECURITY_TEST_CREDENTIAL_AFTER=credential-after\n",
	)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write dotenv: %v", err)
	}

	loadDotEnvIntoOS(path)

	if got := os.Getenv(allowed[0]); got != "credential-before" {
		t.Fatalf("%s = %q, want credential-before", allowed[0], got)
	}
	if got := os.Getenv(allowed[1]); got != "credential-after" {
		t.Fatalf("%s = %q, want credential-after", allowed[1], got)
	}
	for _, name := range rejected {
		if value, present := os.LookupEnv(name); present {
			t.Errorf("unsafe dotenv key %s was loaded with value %q", name, value)
		}
	}
}
