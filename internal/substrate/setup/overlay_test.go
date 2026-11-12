// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if string(want) != string(got) {
		t.Errorf("%s differs from the golden (run with -update after checking):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

func baseOpts() OverlayOptions {
	return OverlayOptions{Namespace: "defenseclaw-system", CalloutPort: 9443, BodyInspection: true}
}

func allCaps() Capabilities {
	return Capabilities{Settings: map[string]bool{KeyExtprocBodyOptIn: true, KeyExtprocTimeout: true, KeyRouteTimeout: true}}
}

const existingInstall = `apiVersion: install.ate.dev/v1alpha1
kind: SubstrateInstall
kindCluster:
  enabled: true
  name: substrate
images:
  repo: ghcr.io/agent-substrate
  tag: "0.10"
atenet:
  dataplane: envoy
ingressAllowedSPIFFEIDs: spiffe://cluster.local/ns/demo/sa/client
cluster:
  context: kind-substrate
  outcome: succeeded
`

func TestRenderOverlayGoldens(t *testing.T) {
	cases := []struct {
		name     string
		existing string
		opts     func(o *OverlayOptions)
	}{
		{"new-v1.0.0", "", func(*OverlayOptions) {}},
		{"new-all-capabilities", "", func(o *OverlayOptions) { o.Capabilities = allCaps(); o.Issuer = "https://idp.cluster-a.example" }},
		{"existing-record", existingInstall, func(*OverlayOptions) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := baseOpts()
			c.opts(&opts)
			out, report, err := RenderOverlay([]byte(c.existing), opts)
			if err != nil {
				t.Fatal(err)
			}
			golden(t, "overlay/"+c.name+".yaml", out)
			if len(report.Changes) == 0 {
				t.Fatal("no changes reported")
			}
			// The output is a valid document that renders to itself.
			again, report2, err := RenderOverlay(out, opts)
			if err != nil {
				t.Fatal(err)
			}
			if string(again) != string(out) || len(report2.Changes) != 0 {
				t.Errorf("second render changed the document: %+v", report2.Changes)
			}
		})
	}
}

func TestRenderOverlayKeepsStringText(t *testing.T) {
	out, _, err := RenderOverlay([]byte(existingInstall), baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseInstall(out)
	if err != nil {
		t.Fatal(err)
	}
	// "0.10" must not become 0.1, the trap ate-setup's parser avoids.
	if got := doc.settings["images.tag"]; got != "0.10" {
		t.Errorf("images.tag = %q", got)
	}
	if got := doc.settings[KeyIngressClients]; got != "spiffe://cluster.local/ns/demo/sa/client,"+IngressClientID("defenseclaw-system") {
		t.Errorf("ingress clients = %q", got)
	}
	if doc.record == nil {
		t.Error("the install record metadata was dropped")
	}
}

func TestRenderOverlayStockSubstrateWritesNoUnknownSetting(t *testing.T) {
	out, report, err := RenderOverlay(nil, baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{KeyExtprocBodyOptIn, KeyExtprocTimeout, KeyRouteTimeout, KeyActorJWTIssuer} {
		if strings.Contains(string(out), strings.Split(key, ".")[len(strings.Split(key, "."))-1]+":") {
			t.Errorf("v1.0.0 overlay sets %s, which v1.0.0 ate-setup rejects", key)
		}
	}
	notes := strings.Join(report.Notes, "\n")
	for _, want := range []string{"#3817", "#2560", "actorJWT.issuer"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes do not mention %s:\n%s", want, notes)
		}
	}
}

func TestRenderOverlayRefusesAnotherCallout(t *testing.T) {
	for name, doc := range map[string]string{
		"other service": "apiVersion: install.ate.dev/v1alpha1\nkind: SubstrateInstall\natenet:\n  egress:\n    additionalExtprocService: security/vendor-proc:50051\n",
		"openappa":      "apiVersion: install.ate.dev/v1alpha1\nkind: SubstrateInstall\nopenappa:\n  enabled: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := RenderOverlay([]byte(doc), baseOpts())
			var taken *ErrCalloutTaken
			if !errors.As(err, &taken) {
				t.Fatalf("err = %v, want ErrCalloutTaken", err)
			}
			msg := err.Error()
			for _, want := range []string{"does not replace", "substrate.extproc.enabled: false", "doctor"} {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal %q does not say %q", msg, want)
				}
			}
		})
	}
}

func TestRenderOverlayOwnCalloutOtherPort(t *testing.T) {
	doc := "apiVersion: install.ate.dev/v1alpha1\nkind: SubstrateInstall\natenet:\n  egress:\n    additionalExtprocService: defenseclaw-system/defenseclaw-callout:8443\n"
	out, report, err := RenderOverlay([]byte(doc), baseOpts())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "defenseclaw-system/defenseclaw-callout:9443") || report.Changes[0].Old == "" {
		t.Errorf("port not updated: %s %+v", out, report.Changes)
	}
}

func TestRenderOverlayRefusesOtherDataplane(t *testing.T) {
	doc := "apiVersion: install.ate.dev/v1alpha1\nkind: SubstrateInstall\natenet:\n  dataplane: agentgateway\n"
	if _, _, err := RenderOverlay([]byte(doc), baseOpts()); !errors.Is(err, ErrDataplane) {
		t.Fatalf("err = %v", err)
	}
}

func TestRenderOverlayRejectsBadDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"wrong kind": "apiVersion: install.ate.dev/v1alpha1\nkind: Other\n",
		"list":       "apiVersion: install.ate.dev/v1alpha1\nkind: SubstrateInstall\npreview: [a, b]\n",
		"not yaml":   "apiVersion: [",
		"scalar":     "just text",
	} {
		if _, _, err := RenderOverlay([]byte(doc), baseOpts()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := RenderOverlay(nil, OverlayOptions{}); err == nil {
		t.Error("no namespace accepted")
	}
}

func TestRemoveOverlay(t *testing.T) {
	opts := baseOpts()
	opts.Capabilities = allCaps()
	installed, _, err := RenderOverlay([]byte(existingInstall), opts)
	if err != nil {
		t.Fatal(err)
	}
	out, report, err := RemoveOverlay(installed, opts)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "overlay/removed.yaml", out)
	s := string(out)
	for _, gone := range []string{"defenseclaw-callout", "additionalExtprocAllowModeOverride", "additionalExtprocTimeout", "sa/defenseclaw-gateway"} {
		if strings.Contains(s, gone) {
			t.Errorf("%s is still set:\n%s", gone, s)
		}
	}
	if !strings.Contains(s, "spiffe://cluster.local/ns/demo/sa/client") || !strings.Contains(s, "routeTimeout") {
		t.Errorf("other settings were removed:\n%s", s)
	}
	if len(report.Notes) == 0 {
		t.Error("no note about the route timeout that stays")
	}

	// Another callout is never removed.
	other := "apiVersion: install.ate.dev/v1alpha1\nkind: SubstrateInstall\natenet:\n  egress:\n    additionalExtprocService: security/vendor-proc:50051\n"
	out, report, err = RemoveOverlay([]byte(other), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "security/vendor-proc:50051") || len(report.Changes) != 0 {
		t.Errorf("removed another callout: %s", out)
	}
}

// TestRenderOverlayOfAFile renders and removes the overlay of a real
// SubstrateInstall document (A8_OVERLAY_IN) into A8_OVERLAY_OUT/{added,removed}.yaml,
// for checking with the target's own ate-setup parser. Skipped without it.
func TestRenderOverlayOfAFile(t *testing.T) {
	in, out := os.Getenv("A8_OVERLAY_IN"), os.Getenv("A8_OVERLAY_OUT")
	if in == "" || out == "" {
		t.Skip("A8_OVERLAY_IN and A8_OVERLAY_OUT are not set")
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	opts := OverlayOptions{Namespace: os.Getenv("A8_OVERLAY_NS"), CalloutPort: 9443, BodyInspection: true}
	added, report, err := RenderOverlay(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	removed, _, err := RemoveOverlay(added, opts)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"added.yaml": added, "removed.yaml": removed} {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range report.Changes {
		t.Logf("set %s: %q -> %q", c.Key, c.Old, c.New)
	}
	for _, n := range report.Notes {
		t.Logf("note: %s", n)
	}
}
