// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

const fleetInstallOK = `apiVersion: install.ate.dev/v1alpha1
kind: SubstrateInstall
atenet.dataplane: envoy
atenet.egress.additionalExtprocService: defenseclaw-system/defenseclaw-callout:9443
ingressAllowedSPIFFEIDs: spiffe://cluster.local/ns/defenseclaw-system/sa/defenseclaw-gateway
actorJWT.issuer: https://idp.cluster-a.example.test
storage.snapshotLocation: s3://dc-snapshots-e1/snapshots/
`

func writeInstall(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "install.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fakeKubectl answers the reads collectFleet makes, and fakes the other
// readers (port-forward, the access policies, the object store CLI) for a
// healthy cluster.
func fakeKubectl(t *testing.T, fail error) {
	t.Helper()
	fakeFleetReaders(t, fail)
	old := substrateKubectl
	substrateKubectl = func(_ context.Context, _ *substrateClusterFlags, args ...string) ([]byte, error) {
		if fail != nil {
			return nil, fail
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(joined, "config current-context"):
			return []byte("kind-e1\n"), nil
		case strings.HasPrefix(joined, "get namespace defenseclaw-system"):
			return []byte(`{"metadata":{"name":"defenseclaw-system","labels":{"ate.dev/api-access":"true"}}}`), nil
		case strings.HasPrefix(joined, "get deployments,statefulsets -n defenseclaw-system"):
			return []byte(`{"items":[
			 {"metadata":{"name":"defenseclaw-gateway"},"spec":{"replicas":2},"status":{"readyReplicas":2}},
			 {"metadata":{"name":"defenseclaw-gateway-leader"},"spec":{"replicas":1},"status":{"readyReplicas":1}},
			 {"metadata":{"name":"defenseclaw-controller"},"spec":{"replicas":1},"status":{"readyReplicas":1}},
			 {"metadata":{"name":"defenseclaw-callout"},"spec":{"replicas":2},"status":{"readyReplicas":2}}]}`), nil
		case strings.HasPrefix(joined, "get leases.coordination.k8s.io"):
			return []byte(`{"items":[{"metadata":{"name":"defenseclaw-gateway-leader"},"spec":{"holderIdentity":"pod-1"}}]}`), nil
		case strings.HasPrefix(joined, "get configmaps -n defenseclaw-system"):
			return []byte(`{"items":[{"metadata":{"name":"defenseclaw-config"},"data":{"config.yaml":"substrate:\n  supported_versions: \">=1.0.0 <1.1.0\"\n  identity:\n    issuer: https://idp.cluster-a.example.test\n  launcher_atespaces:\n    eng: [eng-web]\n"}}]}`), nil
		case strings.HasPrefix(joined, "get nodes -l topology.kubernetes.io/region"):
			return []byte(`{"items":[{"metadata":{"name":"n1","labels":{"topology.kubernetes.io/region":"us-east-1"}}}]}`), nil
		// The idp Service through the API server's Service proxy
		// (GAP-0194): its key set and its discovery document.
		case joined == "get --raw /api/v1/namespaces/ate-system/services/https:idp:443/proxy/openid/v1/jwks":
			return []byte(`{"keys":[{"kty":"EC","kid":"k1"}]}`), nil
		case joined == "get --raw /api/v1/namespaces/ate-system/services/https:idp:443/proxy/.well-known/openid-configuration":
			return []byte(`{"issuer":"https://idp.cluster-a.example.test","jwks_uri":"https://idp.cluster-a.example.test/openid/v1/jwks"}`), nil
		case strings.HasPrefix(joined, "get deployments -n ate-system"):
			return []byte(`{"items":[{"metadata":{"name":"ate-api-server"},"spec":{"template":{"spec":{"containers":[{"name":"api","image":"ghcr.io/agent-substrate/substrate:v1.0.0"}]}}}}]}`), nil
		}
		return nil, errors.New("unexpected kubectl call: " + joined)
	}
	t.Cleanup(func() { substrateKubectl = old })
}

func TestSubstrateVerifyReadsTheClusterAndPasses(t *testing.T) {
	fakeKubectl(t, nil)
	install := writeInstall(t, fleetInstallOK)
	out, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", install, "--json")
	if err != nil {
		t.Fatalf("verify failed: %v\n%s", err, out)
	}
	var doc fleet.VerifyDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Command != "verify" || !doc.OK || doc.Cluster.Name != "kind-e1" || doc.Cluster.SubstrateVersion != "1.0.0" {
		t.Fatalf("document = %+v", doc)
	}
	status := map[string]string{}
	for _, c := range doc.Checks {
		status[c.ID] = c.Status
	}
	// Every check passes on a healthy cluster: none is left unread
	// (GAP-0200, GAP-0209).
	for _, c := range doc.Checks {
		if c.Status != fleet.Pass {
			t.Errorf("check %s = %s %q, want pass", c.ID, c.Status, c.Message)
		}
	}
	for id, want := range map[string]string{
		fleet.CheckSubstrateVersion: fleet.Pass, fleet.CheckCallout: fleet.Pass, fleet.CheckIngressClients: fleet.Pass,
		fleet.CheckAPIAccess: fleet.Pass, fleet.CheckIssuer: fleet.Pass, fleet.CheckActorKeys: fleet.Pass,
		fleet.CheckBucket: fleet.Pass, fleet.CheckGrants: fleet.Pass, fleet.CheckActorRoutes: fleet.Pass,
	} {
		if status[id] != want {
			t.Errorf("check %s = %q, want %q (%+v)", id, status[id], want, status)
		}
	}
	text, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", install)
	if err != nil || !strings.Contains(text, "cluster verified") {
		t.Fatalf("text = %q, %v", text, err)
	}
}

func TestSubstrateVerifyExitCodes(t *testing.T) {
	install := writeInstall(t, fleetInstallOK)
	t.Run("a failed check is exit 1 with the document", func(t *testing.T) {
		fakeKubectl(t, nil)
		bad := writeInstall(t, strings.Replace(fleetInstallOK, "atenet.egress.additionalExtprocService: defenseclaw-system/defenseclaw-callout:9443\n", "atenet.egress.additionalExtprocService: other/callout:1\n", 1))
		out, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", bad, "--json")
		if err == nil || commandExitCode(err) != 1 {
			t.Fatalf("err = %v, want exit 1", err)
		}
		var doc fleet.VerifyDocument
		if json.Unmarshal([]byte(out), &doc) != nil || doc.OK {
			t.Fatalf("a document with ok=false must still print: %q", out)
		}
	})
	t.Run("an unreachable cluster is exit 75 with no document", func(t *testing.T) {
		fakeKubectl(t, errors.New("the connection to the server was refused"))
		out, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", install, "--json")
		if err == nil || commandExitCode(err) != substrateExitUnreachable || strings.TrimSpace(out) != "" {
			t.Fatalf("err = %v, code %d, out %q", err, commandExitCode(err), out)
		}
	})
	t.Run("a missing install file is a usage error", func(t *testing.T) {
		fakeKubectl(t, nil)
		_, _, err := runSubstrate(t, newSubstrateVerifyCmd())
		if err == nil || commandExitCode(err) != 2 || !strings.Contains(err.Error(), "--install-file") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a bad output format is a usage error", func(t *testing.T) {
		_, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--output", "xml")
		if err == nil || commandExitCode(err) != 2 {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestSubstrateStatusClusterPrintsTheHealthDocument(t *testing.T) {
	fakeKubectl(t, nil)
	install := writeInstall(t, fleetInstallOK)
	out, _, err := runSubstrate(t, newSubstrateStatusCmd(), "--cluster", "--install-file", install, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc fleet.StatusDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	h := doc.Health
	if doc.Command != "status" || h.Gateway.Ready != 2 || !h.Leader.LeaseHeld || h.Callout.Desired != 2 || !h.Callout.Registered {
		t.Fatalf("health = %+v", h)
	}
	if doc.Atespaces == nil || doc.Batches == nil || doc.Checks == nil {
		t.Errorf("lists must not be null: %s", out)
	}
	if _, _, err := runSubstrate(t, newSubstrateStatusCmd(), "--cluster", "somename"); err == nil || commandExitCode(err) != 2 {
		t.Errorf("--cluster with a name must be a usage error, got %v", err)
	}
}

func TestSubstrateDoctorReadsClusterChecksWithKubectl(t *testing.T) {
	fakeKubectl(t, nil)
	kf := &substrateClusterFlags{installFile: writeInstall(t, fleetInstallOK), namespace: "defenseclaw-system", substrateNS: "ate-system"}
	checks := doctorKubeChecks(t.Context(), kf)
	seen := map[string]string{}
	for _, c := range checks {
		seen[c.ID] = c.Status
	}
	for _, id := range []string{"cluster.substrate_version", "cluster.issuer_unique", "cluster.snapshot_bucket", "cluster.openfga_grants", "cluster.callout_registered"} {
		if _, ok := seen[id]; !ok {
			t.Errorf("doctor lacks %s: %v", id, seen)
		}
	}
	if seen["cluster.callout_registered"] != doctorOK {
		t.Errorf("callout = %q", seen["cluster.callout_registered"])
	}
	kf.installFile = ""
	if got := doctorKubeChecks(t.Context(), kf); len(got) != 1 || got[0].Status != doctorFail || !strings.Contains(got[0].Summary, "--install-file") {
		t.Errorf("without the install file doctor must say so: %+v", got)
	}
}

// fakeFleetReaders fakes the port-forward (an actor listener that answers
// 401 on its routes and 404 elsewhere, as the real one does without a
// token), the access policies (DefenseClaw's grants in place) and the aws
// CLI (an encrypted, private, expiring bucket in the cluster's region).
func fakeFleetReaders(t *testing.T, fail error) {
	t.Helper()
	oldPF, oldAP, oldCLI := substratePortForward, substrateAccessPolicies, substrateCloudCLI
	t.Cleanup(func() { substratePortForward, substrateAccessPolicies, substrateCloudCLI = oldPF, oldAP, oldCLI })
	actor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fleet.ActorRouteAllowed(r.RequestURI) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(actor.Close)
	substratePortForward = func(_ context.Context, _ *substrateClusterFlags, _, target string, _ int) (string, func(), error) {
		if fail != nil {
			return "", nil, fail
		}
		if target != "svc/defenseclaw-actor" {
			return "", nil, errors.New("unexpected port-forward to " + target)
		}
		return strings.TrimPrefix(actor.URL, "http://"), func() {}, nil
	}
	policies := fleetHealthyPolicies("defenseclaw-system", "eng-web")
	substrateAccessPolicies = func(context.Context, *substrateClusterFlags, apiTarget) (accessPolicyReader, error) {
		if fail != nil {
			return nil, fail
		}
		return fakePolicyReader(policies), nil
	}
	substrateCloudCLI = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if fail != nil {
			return nil, fail
		}
		if name != "aws" || len(args) < 2 {
			return nil, errors.New("unexpected cloud CLI call")
		}
		if s3, ok := fakeS3Healthy[args[1]]; ok && args[0] == "s3api" {
			return []byte(s3), nil
		}
		return nil, errors.New("unexpected aws call: " + strings.Join(args, " "))
	}
}

var fakeS3Healthy = map[string]string{
	"get-bucket-location":                `{"LocationConstraint":null}`,
	"get-bucket-encryption":              `{"ServerSideEncryptionConfiguration":{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}}`,
	"get-public-access-block":            `{"PublicAccessBlockConfiguration":{"BlockPublicAcls":true,"IgnorePublicAcls":true,"BlockPublicPolicy":true,"RestrictPublicBuckets":true}}`,
	"get-bucket-lifecycle-configuration": `{"Rules":[{"ID":"x","Status":"Enabled","Filter":{"Prefix":"snapshots/"},"Expiration":{"Days":30}}]}`,
}

type fakePolicyReader map[string]*setup.AccessPolicy

func (f fakePolicyReader) GetAccessPolicy(_ context.Context, atespace string) (*setup.AccessPolicy, error) {
	return f[atespace], nil
}
func (fakePolicyReader) Close() error { return nil }

// fleetHealthyPolicies are the grants the chart bootstrap writes.
func fleetHealthyPolicies(ns string, launcher ...string) map[string]*setup.AccessPolicy {
	members := func(ps []string) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = setup.Member(p)
		}
		return out
	}
	out := map[string]*setup.AccessPolicy{"": {Bindings: []setup.Binding{
		{Role: setup.RoleOwner, Members: []string{"user:admin"}},
		{Role: setup.RoleViewer, Members: members(setup.ChartGlobalViewers(ns))}}}}
	for _, a := range launcher {
		out[a] = &setup.AccessPolicy{Atespace: a, Bindings: []setup.Binding{{Role: setup.RoleEditor, Members: members(setup.ChartEditors(ns))}}}
	}
	return out
}

func TestImageTag(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/agent-substrate/substrate:v1.0.0":           "1.0.0",
		"reg.example.test:5000/substrate:1.0.1":              "1.0.1",
		"reg.example.test:5000/substrate":                    "",
		"ghcr.io/x/substrate:v1.0.0@sha256:abcdef0123456789": "1.0.0",
		"ghcr.io/x/substrate@sha256:abcdef0123456789":        "",
	} {
		if got := imageTag(in); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", in, got, want)
		}
	}
}
