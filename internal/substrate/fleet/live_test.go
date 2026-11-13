// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// capturedCluster is what a live cell captured from a real cluster
// (lane A8 c7-capture.sh): the ate-api-server image, the access policies,
// the SubstrateInstall settings in effect, the namespace labels and the
// replica counts.
type capturedCluster struct {
	SubstrateImage  string                    `json:"substrate_image"`
	Global          []setup.Binding           `json:"global"`
	Launcher        []setup.Binding           `json:"a8-launch"`
	Managed         []setup.Binding           `json:"a8-gv"`
	ExtprocService  string                    `json:"extproc_service"`
	IngressClients  string                    `json:"ingress_clients"`
	Issuer          string                    `json:"issuer"`
	NamespaceLabels map[string]string         `json:"namespace_labels"`
	Replicas        map[string]map[string]int `json:"replicas"`
}

// TestStatusFromALiveCluster builds the status and verify documents from a
// capture of a real cluster and validates them against the contract. It
// runs when A8_FLEET_OBSERVED names a capture; A8_FLEET_OUT, when set,
// receives the two documents.
func TestStatusFromALiveCluster(t *testing.T) {
	path := os.Getenv("A8_FLEET_OBSERVED")
	if path == "" {
		t.Skip("A8_FLEET_OBSERVED is not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c capturedCluster
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	version := c.SubstrateImage
	if _, tag, ok := strings.Cut(version, ":"); ok {
		version, _, _ = strings.Cut(tag, "@")
	}
	ns := "a8-dc"
	sa := func(n string) string { return "system:serviceaccount:" + ns + ":defenseclaw-" + n }
	issuer := c.Issuer
	if issuer == "" {
		issuer = DefaultIssuer("ate-system")
	}
	var clients []string
	for _, s := range strings.Split(c.IngressClients, ",") {
		if s = strings.TrimSpace(s); s != "" {
			clients = append(clients, s)
		}
	}
	o := Observed{
		ClusterName: "kind-e1", Namespace: ns, SubstrateVersion: version, SupportedVersions: ">=1.0.0 <1.1.0",
		Issuer: issuer, SubstrateNamespace: "ate-system", Clusters: 1,
		GlobalPolicy: &setup.AccessPolicy{Bindings: c.Global},
		AtespacePolicies: map[string]*setup.AccessPolicy{
			"a8-launch": {Atespace: "a8-launch", Bindings: c.Launcher}, "a8-gv": {Atespace: "a8-gv", Bindings: c.Managed}},
		LauncherAtespaces: []string{"a8-launch"}, WritableAtespaces: []string{"a8-gv", "a8-launch"},
		Editors:          []string{sa("gateway"), sa("controller"), sa("hooks")},
		GlobalViewers:    []string{sa("gateway"), sa("controller"), sa("callout"), sa("hooks")},
		PoliciesReadable: true, ExtprocService: c.ExtprocService, CalloutPort: 9443, IngressClients: clients,
		NamespaceLabels: c.NamespaceLabels,
	}
	r := func(name string) Replicas {
		return Replicas{Desired: c.Replicas[name]["desired"], Ready: c.Replicas[name]["ready"]}
	}
	leader := r("defenseclaw-gateway-leader")
	ctrl := r("defenseclaw-controller")
	callout := r("defenseclaw-callout")
	report := Report{ProductVersion: "1.0.10", Now: time.Now(),
		Health: Health{Gateway: r("defenseclaw-gateway"), Leader: Leader{Ready: leader.Ready > 0},
			Controller: Controller(ctrl), Callout: Callout{Desired: callout.Desired, Ready: callout.Ready}},
		Atespaces: []Atespace{{Name: "a8-launch", Launcher: true}, {Name: "a8-gv"}},
	}
	s := compile(t)
	status := BuildStatus(o, report)
	verify := BuildVerify(o, "1.0.10", time.Now())
	s.ValidateValue(t, "substrate-status.schema.json", status)
	s.ValidateValue(t, "substrate-verify.schema.json", verify)
	if out := os.Getenv("A8_FLEET_OUT"); out != "" {
		for name, doc := range map[string]any{"status.json": status, "verify.json": verify} {
			b, _ := json.MarshalIndent(doc, "", "  ")
			if err := os.WriteFile(filepath.Join(out, name), append(b, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, ch := range status.Checks {
		t.Logf("%-22s %-4s %s", ch.ID, ch.Status, ch.Message)
	}
}
