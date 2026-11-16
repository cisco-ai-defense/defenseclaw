// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStandaloneSetupCoworkReleaseInputs(t *testing.T) {
	for _, input := range []string{"COWORKPACKAGE", "CoworkPackage", "cowork-package"} {
		opts, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", input + `=C:\release\defenseclaw-cowork-amd64.tar.gz`, `COWORKSIGNATURE=C:\release\sensor.sig`})
		if err != nil || opts.CoworkPackage != `C:\release\defenseclaw-cowork-amd64.tar.gz` || opts.CoworkSignature != `C:\release\sensor.sig` {
			t.Fatalf("%s: %+v, %v", input, opts, err)
		}
	}
	opts, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/repair", `COWORKSIGNATURE=C:\release\sensor.sig`})
	if err != nil || opts.CoworkSignature == "" || opts.CoworkPackage != "" {
		t.Fatalf("signature-only repair: %+v, %v", opts, err)
	}
	opts, _, err = parseStandaloneEnterpriseSetupOptions([]string{"/ensure", `COWORKPACKAGE=C:\release\sensor.tar.gz `})
	if err != nil || !strings.HasSuffix(opts.CoworkPackage, " ") {
		t.Fatalf("padding must reach the strict input-path validator: %+v, %v", opts, err)
	}
}

func TestStandaloneSetupCoworkInputsRefuseReadOnlyAndBundles(t *testing.T) {
	for _, action := range []string{"/status", "/verify", "/uninstall", "/reconcile"} {
		if _, _, err := parseStandaloneEnterpriseSetupOptions([]string{action, `COWORKPACKAGE=C:\release\sensor.tar.gz`}); err == nil {
			t.Fatalf("accepted Cowork input with %s", action)
		}
	}
	if _, _, err := parseStandaloneEnterpriseSetupOptions([]string{"/ensure", `BUNDLE=C:\release\policy.dcbundle`, `COWORKPACKAGE=C:\release\sensor.tar.gz`}); err == nil {
		t.Fatal("accepted Cowork inputs with a policy bundle")
	}
	if _, _, err := parseEnterpriseSetupOptions([]string{"/repair", `COWORKPACKAGE=C:\release\sensor.tar.gz`}); err == nil {
		t.Fatal("Secure Client accepted standalone Cowork input")
	}
}

func TestStandaloneSetupUsageIncludesCoworkInputs(t *testing.T) {
	var out bytes.Buffer
	writeStandaloneSetupUsage(&out)
	for _, property := range []string{"COWORKPACKAGE=<path>", "COWORKSIGNATURE=<path>"} {
		if !strings.Contains(out.String(), property) {
			t.Fatalf("usage is missing %s", property)
		}
	}
}
