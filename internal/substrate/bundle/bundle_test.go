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

package bundle

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
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

var testNow = time.Date(2026, 11, 12, 22, 0, 0, 0, time.UTC)

type signer struct {
	id  string
	key ed25519.PrivateKey
}

func newSigner(t *testing.T, id string) signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{id: id, key: k}
}

type keyStatus struct {
	s      signer
	status string
}

func ks(s signer, status string) keyStatus { return keyStatus{s, status} }

func anchorsFor(t *testing.T, minVersion uint64, keys ...keyStatus) *eb.Anchors {
	t.Helper()
	type key struct {
		KeyID     string `json:"key_id"`
		Alg       string `json:"alg"`
		PublicKey string `json:"public_key"`
		NotBefore string `json:"not_before"`
		NotAfter  string `json:"not_after"`
		Status    string `json:"status"`
	}
	doc := struct {
		SchemaVersion int      `json:"schema_version"`
		TenantID      string   `json:"tenant_id"`
		DeviceGroups  []string `json:"device_groups"`
		MinVersion    uint64   `json:"min_version"`
		Keys          []key    `json:"keys"`
	}{SchemaVersion: 1, TenantID: "acme", DeviceGroups: []string{"cluster-e1"}, MinVersion: minVersion}
	for _, k := range keys {
		s, status := k.s, k.status
		der, err := x509.MarshalPKIXPublicKey(s.key.Public())
		if err != nil {
			t.Fatal(err)
		}
		doc.Keys = append(doc.Keys, key{KeyID: s.id, Alg: eb.AlgEd25519, PublicKey: base64.StdEncoding.EncodeToString(der),
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z", Status: status})
	}
	slices.SortFunc(doc.Keys, func(a, b key) int { return strings.Compare(a.KeyID, b.KeyID) })
	raw, _ := json.Marshal(doc)
	a, err := eb.DecodeAnchors(raw)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const ulidChars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func bundleID(n uint64) string {
	id := []byte("b-01" + strings.Repeat("0", 24))
	for i := len(id) - 1; n > 0 && i > 4; i-- {
		id[i] = ulidChars[n%32]
		n /= 32
	}
	return string(id)
}

// buildBundle signs a bundle holding config.yaml with s, as bundle sign
// would (the effective digest is not checked by a cluster).
func buildBundle(t *testing.T, s signer, version uint64, cfgYAML string, mutate ...func(*eb.Manifest, *eb.Bundle)) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(cfgYAML))
	m := &eb.Manifest{SchemaVersion: 1, BundleID: bundleID(version), TenantID: "acme",
		Target: eb.Target{DeviceGroup: "cluster-e1", Platforms: []string{"linux"}}, Version: version,
		CreatedAt: testNow.Add(-time.Hour).Format(time.RFC3339), CreatedBy: "operator:admin",
		Files: []eb.FileEntry{{Path: "config.yaml", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(cfgYAML))}},
		EffectivePolicy: eb.EffectivePolicy{ProductVersion: "1.0.10", ComputedOn: "linux",
			Digests: map[string]string{"linux": "sha256:" + strings.Repeat("a", 64)}}}
	b := &eb.Bundle{Files: map[string][]byte{"config.yaml": []byte(cfgYAML)}}
	for _, f := range mutate {
		f(m, b)
	}
	raw, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := eb.Sign(raw, s.key, s.id)
	if err != nil {
		t.Fatal(err)
	}
	b.Manifest = raw
	if b.Signature, err = sig.Marshal(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := eb.WriteArchive(&out, b); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func policyYAML(block string) string {
	return fmt.Sprintf(`config_version: 9
deployment_mode: managed_enterprise
guardrail:
  profiles:
    eng:
      description: engineering actors
      sandbox:
        egress_block: [%s]
  profile_assignments:
    - profile: eng
      match:
        substrate:
          atespaces: [team-a, team-b, team-c]
`, block)
}

func baseConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	return cfg
}

type env struct {
	cm      *MemoryConfigMaps
	store   *Store
	key     signer
	anchors *eb.Anchors
}

func newEnv(t *testing.T) *env {
	e := &env{cm: NewMemoryConfigMaps(), key: newSigner(t, "acme-2026a")}
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyActive))
	e.store = &Store{CM: e.cm, Base: baseConfig(), Now: func() time.Time { return testNow },
		Anchors: func() (*eb.Anchors, error) { return e.anchors, nil }}
	return e
}

func resolveBlock(t *testing.T, r *Resolver, atespace string) (bool, []string) {
	t.Helper()
	res, err := r.Resolve(controller.Registration{Atespace: atespace, Name: "a", UID: "u", Source: controller.SourceAtespace}, false)
	if err != nil {
		t.Fatal(err)
	}
	return res.Managed, res.Profile.Block
}

func (e *env) load(t *testing.T) (*Resolver, []Problem) {
	t.Helper()
	snap, problems, err := e.store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r := NewResolver(e.store.Base)
	r.Set(snap)
	return r, problems
}

func TestApplyStagedAndResolve(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rc, err := e.store.Apply(ctx, buildBundle(t, e.key, 1, policyYAML("paste.example.com")), "canary", []string{"team-a"}, SourceCLI)
	if err != nil || rc.Result != ResultApplied || rc.KeyID != "acme-2026a" || rc.Version != 1 {
		t.Fatalf("apply: %+v %v", rc, err)
	}
	r, problems := e.load(t)
	if len(problems) > 0 {
		t.Fatalf("problems: %+v", problems)
	}
	if managed, block := resolveBlock(t, r, "team-a"); !managed || !slices.Contains(block, "paste.example.com") {
		t.Fatalf("team-a: managed %v block %v", managed, block)
	}
	// team-b is named by the bundle's assignment but not in the stage.
	if managed, _ := resolveBlock(t, r, "team-b"); managed {
		t.Fatal("team-b got the canary bundle")
	}
	if !slices.Contains(r.ManagedAtespaces(), "team-a") {
		t.Fatalf("managed atespaces %v", r.ManagedAtespaces())
	}
	// The all stage covers the rest; the canary stage keeps team-a.
	if _, err := e.store.Apply(ctx, buildBundle(t, e.key, 2, policyYAML("bin.example.com")), StageAll, nil, SourceCLI); err != nil {
		t.Fatal(err)
	}
	r, _ = e.load(t)
	if _, block := resolveBlock(t, r, "team-b"); !slices.Equal(block, []string{"bin.example.com"}) {
		t.Fatalf("team-b block %v", block)
	}
	if _, block := resolveBlock(t, r, "team-a"); !slices.Equal(block, []string{"paste.example.com"}) {
		t.Fatalf("team-a block %v", block)
	}
	// The same bundle again is a no-op.
	rc, err = e.store.Apply(ctx, buildBundle(t, e.key, 1, policyYAML("paste.example.com")), "canary", []string{"team-a"}, SourceCLI)
	if err != nil || rc.Result != ResultAlreadyApplied {
		t.Fatalf("re-apply: %+v %v", rc, err)
	}
}

func TestTamperIsRefusedAndReceipted(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	good := buildBundle(t, e.key, 5, policyYAML("paste.example.com"))
	if _, err := e.store.Apply(ctx, good, "canary", []string{"team-a"}, SourceCLI); err != nil {
		t.Fatal(err)
	}
	other := newSigner(t, "acme-2026a") // same key id, another key
	stranger := newSigner(t, "rogue")
	edited := buildBundle(t, e.key, 6, policyYAML("paste.example.com"), func(_ *eb.Manifest, b *eb.Bundle) {})
	{ // edit config.yaml after signing
		bb, err := eb.ReadArchive(bytes.NewReader(edited))
		if err != nil {
			t.Fatal(err)
		}
		bb.Files["config.yaml"] = []byte(strings.Replace(string(bb.Files["config.yaml"]), "paste.example.com", "nothing.invalid", 1))
		var out bytes.Buffer
		if err := eb.WriteArchive(&out, bb); err != nil {
			t.Fatal(err)
		}
		edited = out.Bytes()
	}
	cases := map[string]struct {
		archive []byte
		code    eb.Code
	}{
		"edited content": {edited, eb.CodeFileHashMismatch},
		"bad signature":  {buildBundle(t, other, 6, policyYAML("x.example.com")), eb.CodeSignatureInvalid},
		"unknown key":    {buildBundle(t, stranger, 6, policyYAML("x.example.com")), eb.CodeKeyUnknown},
		"replay older":   {buildBundle(t, e.key, 4, policyYAML("x.example.com")), eb.CodeVersionNotNewer},
		"same version":   {buildBundle(t, e.key, 5, policyYAML("x.example.com")), eb.CodeVersionNotNewer},
		"other tenant": {buildBundle(t, e.key, 6, policyYAML("x.example.com"), func(m *eb.Manifest, _ *eb.Bundle) {
			m.TenantID = "other"
		}), eb.CodeTenantMismatch},
		"laptop only": {buildBundle(t, e.key, 6, policyYAML("x.example.com"), func(m *eb.Manifest, _ *eb.Bundle) {
			m.Target.Platforms = []string{"darwin"}
			m.EffectivePolicy.Digests = map[string]string{"darwin": "sha256:" + strings.Repeat("b", 64)}
		}), eb.CodeTargetMismatch},
		"not a policy":    {buildBundle(t, e.key, 6, "config_version: 9\ngateway:\n  api_port: 1\n"), CodeNotSubstrate},
		"host assignment": {buildBundle(t, e.key, 6, "guardrail:\n  profiles:\n    eng: {}\n  profile_assignments:\n    - profile: eng\n      match: {groups: [eng]}\n"), CodeNotSubstrate},
		"guardrail mode":  {buildBundle(t, e.key, 6, "guardrail:\n  profiles:\n    eng: {mode: observe}\n"), CodeNotSubstrate},
		"garbage":         {[]byte("not a bundle"), eb.CodeArchiveInvalid},
		"other mode":      {buildBundle(t, e.key, 6, "deployment_mode: standalone\nguardrail:\n  profiles:\n    eng: {}\n"), eb.CodeConfigInvalid},
	}
	for name, tc := range cases {
		rc, err := e.store.Apply(ctx, tc.archive, "canary", []string{"team-a"}, SourceCLI)
		if eb.CodeOf(err) != tc.code || rc.Result != ResultRefused || rc.Code != string(tc.code) {
			t.Errorf("%s: code %q (receipt %+v), want %q", name, eb.CodeOf(err), rc, tc.code)
		}
	}
	r, _ := e.load(t)
	if _, block := resolveBlock(t, r, "team-a"); !slices.Equal(block, []string{"paste.example.com"}) {
		t.Fatalf("a refused bundle changed the policy: %v", block)
	}
	receipts, err := e.store.Receipts(ctx, 0)
	if err != nil || len(receipts) != len(cases)+1 {
		t.Fatalf("receipts %d %v", len(receipts), err)
	}
	if receipts[0].Result != ResultApplied || receipts[len(receipts)-1].Result != ResultRefused {
		t.Fatalf("receipt order %+v", receipts)
	}
}

func TestRollbackRestoresAndKeepsTheFloor(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	v1, v2 := buildBundle(t, e.key, 1, policyYAML("one.example.com")), buildBundle(t, e.key, 2, policyYAML("two.example.com"))
	for _, b := range [][]byte{v1, v2} {
		if _, err := e.store.Apply(ctx, b, "canary", []string{"team-a"}, SourceCLI); err != nil {
			t.Fatal(err)
		}
	}
	rc, err := e.store.Rollback(ctx, "canary", SourceCLI)
	if err != nil || rc.Result != ResultRolledBack || rc.Version != 1 {
		t.Fatalf("rollback: %+v %v", rc, err)
	}
	r, _ := e.load(t)
	if _, block := resolveBlock(t, r, "team-a"); !slices.Equal(block, []string{"one.example.com"}) {
		t.Fatalf("after rollback: %v", block)
	}
	// Replaying the rolled-back bundle is refused: the floor stays at 2.
	if _, err := e.store.Apply(ctx, v2, "canary", []string{"team-a"}, SourceCLI); eb.CodeOf(err) != eb.CodeVersionNotNewer {
		t.Fatalf("replay after rollback: %v", err)
	}
	// Rolling back again rolls forward to v2 (verified again).
	if rc, err := e.store.Rollback(ctx, "canary", SourceCLI); err != nil || rc.Version != 2 {
		t.Fatalf("roll forward: %+v %v", rc, err)
	}
	// A rollback re-verifies against the current anchors.
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyRevoked))
	if _, err := e.store.Rollback(ctx, "canary", SourceCLI); eb.CodeOf(err) != eb.CodeKeyRevoked {
		t.Fatalf("rollback with a revoked key: %v", err)
	}
	if _, err := e.store.Rollback(ctx, "nope", SourceCLI); eb.CodeOf(err) != CodeNoPrevious {
		t.Fatalf("rollback of an unknown stage: %v", err)
	}
}

func TestRevocationAndTamperedStateFallBackToConfig(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if _, err := e.store.Apply(ctx, buildBundle(t, e.key, 1, policyYAML("paste.example.com")), "canary", []string{"team-a"}, SourceCLI); err != nil {
		t.Fatal(err)
	}
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyRevoked))
	r, problems := e.load(t)
	if len(problems) != 1 || problems[0].Code != string(eb.CodeKeyRevoked) || r.For("team-a") != nil {
		t.Fatalf("revoked: %+v", problems)
	}
	// A retired key still verifies the active bundle, not a new one.
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyRetired))
	if _, problems := e.load(t); len(problems) != 0 {
		t.Fatalf("retired: %+v", problems)
	}
	if _, err := e.store.Apply(ctx, buildBundle(t, e.key, 2, policyYAML("x.example.com")), "canary", []string{"team-a"}, SourceCLI); eb.CodeOf(err) != eb.CodeKeyExpired {
		t.Fatalf("new bundle with a retired key: %v", err)
	}
	// Anchors raised above the active version.
	e.anchors = anchorsFor(t, 3, ks(e.key, eb.KeyActive))
	if _, problems := e.load(t); len(problems) != 1 || problems[0].Code != string(eb.CodeVersionNotNewer) {
		t.Fatalf("min_version: %+v", problems)
	}
	// Someone edits the kept archive in the state ConfigMap.
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyActive))
	cm, _ := e.cm.Get(ctx, StateConfigMap)
	for k := range cm.BinaryData {
		cm.BinaryData[k] = buildBundle(t, e.key, 1, policyYAML("evil.example.com"))
	}
	e.cm.Put(cm)
	if r, problems := e.load(t); len(problems) != 1 || problems[0].Code != string(CodeStateInvalid) || r.For("team-a") != nil {
		t.Fatalf("tampered state: %+v", problems)
	}
	// No anchors at all.
	e.store.Anchors = func() (*eb.Anchors, error) { return LoadAnchorsFile(t.TempDir() + "/missing.json") }
	if _, problems := e.load(t); len(problems) != 1 || problems[0].Code != string(eb.CodeAnchorMissing) {
		t.Fatalf("no anchors: %+v", problems)
	}
}

func TestStageRules(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := func(v uint64) []byte { return buildBundle(t, e.key, v, policyYAML("x.example.com")) }
	if _, err := e.store.Apply(ctx, b(1), "canary", []string{"team-a"}, SourceCLI); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		stage string
		ns    []string
	}{
		"overlap":       {"wave2", []string{"team-a"}},
		"glob":          {"wave2", []string{"team-*"}},
		"no atespaces":  {"wave2", nil},
		"all with list": {StageAll, []string{"team-z"}},
		"bad name":      {"Wave_2", []string{"team-z"}},
	} {
		if _, err := e.store.Apply(ctx, b(2), tc.stage, tc.ns, SourceCLI); eb.CodeOf(err) != CodeStageInvalid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInboxAppliesOnceAndRefusesTamper(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.cm.Put(&ConfigMap{Name: "defenseclaw-bundle-inbox",
		Data:       map[string]string{"canary.atespaces": "team-a, team-b"},
		BinaryData: map[string][]byte{"canary.dcbundle": buildBundle(t, e.key, 3, policyYAML("paste.example.com"))}})
	rcs, err := e.store.SyncInbox(ctx, "defenseclaw-bundle-inbox")
	if err != nil || len(rcs) != 1 || rcs[0].Result != ResultApplied || rcs[0].Source != SourceInbox || !slices.Equal(rcs[0].Atespaces, []string{"team-a", "team-b"}) {
		t.Fatalf("inbox: %+v %v", rcs, err)
	}
	if rcs, err := e.store.SyncInbox(ctx, "defenseclaw-bundle-inbox"); err != nil || len(rcs) != 0 {
		t.Fatalf("unchanged inbox: %+v %v", rcs, err)
	}
	e.cm.Put(&ConfigMap{Name: "defenseclaw-bundle-inbox",
		Data:       map[string]string{"canary.atespaces": "team-a"},
		BinaryData: map[string][]byte{"canary.dcbundle": buildBundle(t, newSigner(t, "rogue"), 4, policyYAML("x.example.com"))}})
	for range 2 {
		rcs, err := e.store.SyncInbox(ctx, "defenseclaw-bundle-inbox")
		if err != nil {
			t.Fatal(err)
		}
		if len(rcs) > 1 || len(rcs) == 1 && rcs[0].Code != string(eb.CodeKeyUnknown) {
			t.Fatalf("tampered inbox: %+v", rcs)
		}
	}
	all, _ := e.store.Receipts(ctx, 0)
	if len(all) != 2 {
		t.Fatalf("receipts %+v", all)
	}
	r, _ := e.load(t)
	if r.For("team-b") == nil {
		t.Fatal("the refused inbox entry changed the stage")
	}
}

type recSink struct{ evs []controller.Event }

func (s *recSink) Emit(ev controller.Event) { s.evs = append(s.evs, ev) }

func TestManagerReportsChangesOnce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	sink := &recSink{}
	m := &Manager{Store: e.store, Resolver: NewResolver(e.store.Base), Inbox: "defenseclaw-bundle-inbox", Sink: sink}
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Apply(ctx, buildBundle(t, e.key, 1, policyYAML("paste.example.com")), "canary", []string{"team-a"}, SourceCLI); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := m.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if m.Resolver.For("team-a") == nil || len(sink.evs) != 1 || sink.evs[0].Type != EventActive {
		t.Fatalf("events %+v", sink.evs)
	}
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyRevoked))
	_ = m.Refresh(ctx)
	_ = m.Refresh(ctx)
	if m.Resolver.For("team-a") != nil || len(sink.evs) != 2 || sink.evs[1].Type != EventUnverified || sink.evs[1].Severity != controller.SeverityAlert {
		t.Fatalf("events %+v", sink.evs)
	}
}
