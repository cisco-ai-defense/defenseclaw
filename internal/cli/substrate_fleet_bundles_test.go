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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/bundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// bundleCluster is a cluster with substrate.bundles on and one stage
// (s-eng, atespace eng-web) whose bundle was signed with key k1.
type bundleCluster struct {
	state   []byte // the defenseclaw-bundles ConfigMap as kubectl prints it
	anchors []byte // bundle-anchors.json of the anchors Secret
	store   *bundle.Store
}

func testBundleAnchors(t *testing.T, keyID string, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	raw, _ := json.Marshal(map[string]any{"schema_version": 1, "tenant_id": "acme", "device_groups": []string{"cluster-e1"}, "min_version": 0,
		"keys": []map[string]any{{"key_id": keyID, "alg": eb.AlgEd25519, "public_key": base64.StdEncoding.EncodeToString(der),
			"not_before": now.Add(-24 * time.Hour).Format(time.RFC3339), "not_after": now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
			"status": eb.KeyActive}}})
	return raw
}

func testBundleArchive(t *testing.T, keyID string, key ed25519.PrivateKey) []byte {
	t.Helper()
	cfgYAML := "config_version: 9\nguardrail:\n  profiles:\n    eng:\n      description: engineering actors\n      sandbox:\n        egress_block: [x.example.org]\n"
	sum := sha256.Sum256([]byte(cfgYAML))
	m := &eb.Manifest{SchemaVersion: 1, BundleID: "b-01" + strings.Repeat("0", 23) + "3", TenantID: "acme",
		Target: eb.Target{DeviceGroup: "cluster-e1", Platforms: []string{"linux"}}, Version: 3,
		CreatedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), CreatedBy: "operator:admin",
		Files: []eb.FileEntry{{Path: "config.yaml", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(cfgYAML))}},
		EffectivePolicy: eb.EffectivePolicy{ProductVersion: "1.0.10", ComputedOn: "linux",
			Digests: map[string]string{"linux": "sha256:" + strings.Repeat("a", 64)}}}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := eb.Sign(raw, key, keyID)
	if err != nil {
		t.Fatal(err)
	}
	b := &eb.Bundle{Manifest: raw, Files: map[string][]byte{"config.yaml": []byte(cfgYAML)}}
	if b.Signature, err = sig.Marshal(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := eb.WriteArchive(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func newBundleCluster(t *testing.T) *bundleCluster {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &bundleCluster{anchors: testBundleAnchors(t, "k1", key)}
	base := &config.Config{}
	base.Substrate.Enabled = true
	// eng-web must be an atespace DefenseClaw manages, or Apply refuses the stage (GAP-0438).
	base.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "eng", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Atespaces: []string{"eng-web"}}}}}
	mem := bundle.NewMemoryConfigMaps()
	c.store = &bundle.Store{CM: mem, Base: base, Anchors: func() (*eb.Anchors, error) { return eb.DecodeAnchors(c.anchors) }}
	if _, err := c.store.Apply(context.Background(), testBundleArchive(t, "k1", key), "s-eng", []string{"eng-web"}, bundle.SourceAdmin); err != nil {
		t.Fatal(err)
	}
	cm, err := mem.Get(context.Background(), bundle.StateConfigMap)
	if err != nil || cm == nil {
		t.Fatalf("state: %v", err)
	}
	c.state, _ = json.Marshal(map[string]any{"metadata": map[string]string{"name": cm.Name}, "data": cm.Data, "binaryData": cm.BinaryData})
	return c
}

// rotateAnchors replaces the anchors with another key under the same id, as
// on d2: every kept bundle stops verifying (signature_invalid).
func (c *bundleCluster) rotateAnchors(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.anchors = testBundleAnchors(t, "k1", other)
}

// fakeBundleKubectl answers the bundle reads on top of fakeKubectl, with
// substrate.bundles on in the cluster's config. secretErr fails the read of
// the anchors Secret.
func fakeBundleKubectl(t *testing.T, c *bundleCluster, secretErr error) {
	t.Helper()
	fakeKubectl(t, nil)
	inner := substrateKubectl
	substrateKubectl = func(ctx context.Context, f *substrateClusterFlags, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "get configmap defenseclaw-bundles -n defenseclaw-system -o json --ignore-not-found":
			return c.state, nil
		case "get secret defenseclaw-bundle-anchors -n defenseclaw-system -o json":
			if secretErr != nil {
				return nil, secretErr
			}
			return json.Marshal(map[string]any{"data": map[string][]byte{eb.AnchorsName: c.anchors}})
		}
		out, err := inner(ctx, f, args...)
		if strings.HasPrefix(joined, "get configmaps -n defenseclaw-system") {
			out = []byte(strings.Replace(string(out), `substrate:\n  supported_versions`,
				`substrate:\n  enabled: true\n  bundles:\n    enabled: true\n  supported_versions`, 1))
		}
		return out, err
	}
}

// TestVerifyReportsTheBundleState is GAP-0429 and GAP-0432: verify and
// status --cluster carry the bundle in force per stage (id, version, key,
// manifest, the apply receipt's time and source), and the bundle_state
// check fails, with the stage, the code and the fix, when a stage's bundle
// no longer verifies against the trust anchors.
func TestVerifyReportsTheBundleState(t *testing.T) {
	find := func(t *testing.T, doc fleet.VerifyDocument) fleet.Check {
		t.Helper()
		for _, c := range doc.Checks {
			if c.ID == "bundle_state" {
				return c
			}
		}
		t.Fatalf("verify has no bundle_state check: %+v", doc.Checks)
		return fleet.Check{}
	}
	verify := func(t *testing.T) (fleet.VerifyDocument, string, error) {
		t.Helper()
		out, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", writeInstall(t, fleetInstallOK), "--json")
		var doc fleet.VerifyDocument
		if jerr := json.Unmarshal([]byte(out), &doc); jerr != nil {
			t.Fatalf("verify --json = %q: %v", out, jerr)
		}
		return doc, out, err
	}
	t.Run("a verified bundle passes and is in the documents", func(t *testing.T) {
		c := newBundleCluster(t)
		fakeBundleKubectl(t, c, nil)
		doc, out, err := verify(t)
		wantCheck(t, find(t, doc), fleet.Pass, "1 stage(s) enforce bundles that verify")
		if err != nil {
			t.Errorf("verify: %v", err)
		}
		for _, want := range []string{`"bundles"`, `"stage": "s-eng"`, `"key_id": "k1"`, `"version": 3`, `"state": "verified"`, `"source": "admin"`, `"receipt_id": "r-`} {
			if !strings.Contains(out, want) {
				t.Errorf("verify --json lacks %s: %s", want, out)
			}
		}
		st, _, err := runSubstrate(t, newSubstrateStatusCmd(), "--cluster", "--install-file", writeInstall(t, fleetInstallOK), "--json")
		if err != nil || !strings.Contains(st, `"bundle_id": "b-01`) || !strings.Contains(st, `"key_id": "k1"`) {
			t.Errorf("status --cluster --json = %v %s", err, st)
		}
	})
	t.Run("anchors that no longer verify the bundle fail", func(t *testing.T) {
		c := newBundleCluster(t)
		c.rotateAnchors(t)
		fakeBundleKubectl(t, c, nil)
		doc, out, err := verify(t)
		ck := find(t, doc)
		wantCheck(t, ck, fleet.Fail, "stage s-eng")
		wantCheck(t, ck, fleet.Fail, "signature_invalid")
		wantCheck(t, ck, fleet.Fail, "bundle apply")
		if err == nil || doc.OK {
			t.Errorf("verify must exit 1: %v ok=%t", err, doc.OK)
		}
		if !strings.Contains(out, `"state": "unverified"`) || !strings.Contains(out, `"problem": "signature_invalid"`) {
			t.Errorf("verify --json = %s", out)
		}
	})
	t.Run("an unreadable anchors Secret warns", func(t *testing.T) {
		c := newBundleCluster(t)
		fakeBundleKubectl(t, c, errors.New(`secrets "defenseclaw-bundle-anchors" is forbidden`))
		doc, out, _ := verify(t)
		wantCheck(t, find(t, doc), fleet.Warn, "could not be verified from here")
		if !strings.Contains(out, `"state": "unchecked"`) {
			t.Errorf("verify --json = %s", out)
		}
	})
	t.Run("bundles off is skipped and leaves the member out", func(t *testing.T) {
		fakeKubectl(t, nil)
		doc, out, _ := verify(t)
		wantCheck(t, find(t, doc), fleet.Skip, "bundles are off")
		if strings.Contains(out, `"bundles"`) {
			t.Errorf("verify --json carries bundles with bundles off: %s", out)
		}
	})
}
