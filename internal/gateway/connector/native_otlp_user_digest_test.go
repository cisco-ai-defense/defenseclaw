// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

// A managed Unix account's configuration can keep an exporter an earlier
// install left with the product gateway token as its bearer and a port no
// DefenseClaw process serves. The as-the-user worker never holds that token,
// only its digest, and must still know the exporter as DefenseClaw's while it
// keeps an exporter with a foreign bearer (GAP-2376).
func TestUserNativeOTLPWithoutKnowsAProductCredentialByItsDigest(t *testing.T) {
	const product = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
	codex := []byte("model = \"gpt-5\"\n\n[otel]\nenvironment = \"pc2376\"\n\n" +
		"[otel.exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18971/v1/logs\"\nprotocol = \"json\"\n\n" +
		"[otel.exporter.otlp-http.headers]\nAuthorization = \"Bearer " + product + "\"\n\n" +
		"[otel.trace_exporter.otlp-http]\nendpoint = \"http://127.0.0.1:18972/v1/traces\"\nprotocol = \"json\"\n\n" +
		"[otel.trace_exporter.otlp-http.headers]\nAuthorization = \"Bearer foreign-collector-0123456789abcdef\"\n")
	claude := []byte(`{"model":"haiku","env":{"OTEL_EXPORTER_OTLP_ENDPOINT":"http://127.0.0.1:18971",` +
		`"OTEL_EXPORTER_OTLP_HEADERS":"Authorization=Bearer ` + product + `","CLAUDE_CODE_ENABLE_TELEMETRY":"1"}}`)
	opts := SetupOpts{DataDir: t.TempDir(), ManagedEnterprise: true}
	digest, ok := NativeOTLPCredentialDigestOf(product)
	if !ok {
		t.Fatal("no digest for the product credential")
	}
	if _, ok := NativeOTLPCredentialDigestOf("short"); ok {
		t.Fatal("a credential too short to prove ownership got a digest")
	}
	for _, tc := range []struct {
		connector string
		config    []byte
	}{{"codex", codex}, {"claudecode", claude}} {
		// Without the digest nothing proves the exporter is DefenseClaw's.
		if out, removed, err := UserNativeOTLPWithout(tc.connector, tc.config, nil, opts, nil); err != nil || len(removed) != 0 || out != nil {
			t.Fatalf("%s: removed %v without a known credential (err %v)", tc.connector, removed, err)
		}
		other, _ := NativeOTLPCredentialDigestOf("another-product-credential-not-in-the-file")
		if _, removed, err := UserNativeOTLPWithout(tc.connector, tc.config, nil, opts, []NativeOTLPCredentialDigest{other}); err != nil || len(removed) != 0 {
			t.Fatalf("%s: removed %v for a credential the file does not carry (err %v)", tc.connector, removed, err)
		}
		out, removed, err := UserNativeOTLPWithout(tc.connector, tc.config, nil, opts, []NativeOTLPCredentialDigest{other, digest})
		if err != nil || len(removed) == 0 {
			t.Fatalf("%s: the exporter with the product bearer was not named: %v %v", tc.connector, removed, err)
		}
		if strings.Contains(string(out), product) {
			t.Fatalf("%s: the product credential is still in the configuration:\n%s", tc.connector, out)
		}
		if !strings.Contains(string(out), "haiku") && !strings.Contains(string(out), "gpt-5") {
			t.Fatalf("%s: an unrelated setting was lost:\n%s", tc.connector, out)
		}
	}
	out, _, _ := UserNativeOTLPWithout("codex", codex, nil, opts, []NativeOTLPCredentialDigest{digest})
	if !strings.Contains(string(out), "foreign-collector-0123456789abcdef") || !strings.Contains(string(out), "18972") {
		t.Fatalf("the exporter with a foreign bearer was not kept:\n%s", out)
	}
	if strings.Contains(string(out), "18971") {
		t.Fatalf("the product exporter's endpoint is still there:\n%s", out)
	}
	// The read-only check is unchanged: no digest, no residue.
	if names, err := UserNativeOTLPResidueIn("codex", codex, nil, opts); err != nil || len(names) != 0 {
		t.Fatalf("UserNativeOTLPResidueIn changed: %v %v", names, err)
	}
}
