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
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// testRegistry is an OCI distribution (v2) server for GAP-0437: one
// repository, a Bearer token service, and an optional blob redirect.
type testRegistry struct {
	t        *testing.T
	srv      *httptest.Server // registry + token service
	cdn      *httptest.Server // another host the blob may redirect to
	plain    *httptest.Server // plain http
	manifest []byte
	blob     []byte
	token    string // the token service issues this one
	accept   string // the registry accepts only this one
	redirect string // "", "cdn", "http"

	manifestGets, blobGets, tokenGets atomic.Int32
	cdnAuth                           atomic.Value // Authorization seen by the CDN
	tokenBasic                        atomic.Value // Basic user seen by the token service
}

func newTestRegistry(t *testing.T, archive []byte) *testRegistry {
	r := &testRegistry{t: t, blob: archive, token: "good", accept: "good"}
	r.manifest = ociManifest(MediaTypeBundleLayer, sha256Digest(archive), int64(len(archive)))
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.serve))
	r.cdn = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.cdnAuth.Store(req.Header.Get("Authorization"))
		_, _ = w.Write(r.blob)
	}))
	r.plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(r.blob) }))
	t.Cleanup(func() { r.srv.Close(); r.cdn.Close(); r.plain.Close() })
	return r
}

func ociManifest(mediaType, digest string, size int64) []byte {
	return fmt.Appendf(nil, `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json",`+
		`"config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},`+
		`"layers":[{"mediaType":%q,"digest":%q,"size":%d}]}`, mediaType, digest, size)
}

func (r *testRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "https://") }

func (r *testRegistry) ref() string { return r.host() + "/policy/prod@" + sha256Digest(r.manifest) }

func (r *testRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/token" {
		r.tokenGets.Add(1)
		if u, _, ok := req.BasicAuth(); ok {
			r.tokenBasic.Store(u)
		}
		if req.URL.Query().Get("scope") != "repository:policy/prod:pull" {
			http.Error(w, "scope", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, `{"token":%q}`, r.token)
		return
	}
	if req.Header.Get("Authorization") != "Bearer "+r.accept {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+r.srv.URL+`/token",service="test-registry",scope="repository:policy/prod:pull"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case strings.HasPrefix(req.URL.Path, "/v2/policy/prod/manifests/"):
		r.manifestGets.Add(1)
		w.Header().Set("Content-Type", mediaTypeOCIManifest)
		_, _ = w.Write(r.manifest)
	case strings.HasPrefix(req.URL.Path, "/v2/policy/prod/blobs/"):
		r.blobGets.Add(1)
		switch r.redirect {
		case "cdn":
			http.Redirect(w, req, r.cdn.URL+"/blob", http.StatusTemporaryRedirect)
		case "http":
			http.Redirect(w, req, r.plain.URL+"/blob", http.StatusTemporaryRedirect)
		default:
			_, _ = w.Write(r.blob)
		}
	default:
		http.NotFound(w, req)
	}
}

// client trusts both TLS servers through ca_file, as a private CA.
func (r *testRegistry) client(t *testing.T, creds string) *OCIClient {
	t.Helper()
	dir := t.TempDir()
	var ca bytes.Buffer
	for _, s := range []*httptest.Server{r.srv, r.cdn} {
		_ = pem.Encode(&ca, &pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	}
	o := config.SubstrateBundleOCIConfig{CAFile: filepath.Join(dir, "ca.pem")}
	if err := os.WriteFile(o.CAFile, ca.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if creds != "" {
		o.CredentialsFile = filepath.Join(dir, "config.json")
		if err := os.WriteFile(o.CredentialsFile, []byte(creds), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := NewOCIClient(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ociStage(ref string) []OCIStage {
	return []OCIStage{{Stage: "prod", Ref: ref, Atespaces: []string{"team-a"}}}
}

func TestGAP0437OCIValidPullAppliesOnceByDigest(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	c := reg.client(t, "")
	e.store.OCIStages = ociStage(reg.ref())
	if st, err := e.store.Status(ctx, 0); err != nil || len(st.OCI) != 1 || st.OCI[0].State != OCIPending {
		t.Fatalf("status before the pull: %+v %v", st, err)
	}
	rcs, pulls, err := e.store.SyncOCI(ctx, c, e.store.OCIStages)
	if err != nil || len(pulls) != 0 || len(rcs) != 1 || rcs[0].Result != ResultApplied || rcs[0].Source != SourceOCI || rcs[0].Stage != "prod" {
		t.Fatalf("valid pull: %+v %v", rcs, err)
	}
	// The digest is immutable: the next passes make no registry call.
	for range 2 {
		if rcs, pulls, err := e.store.SyncOCI(ctx, c, e.store.OCIStages); err != nil || len(pulls) != 0 || len(rcs) != 0 {
			t.Fatalf("second pass: %+v %v", rcs, err)
		}
	}
	if m, b := reg.manifestGets.Load(), reg.blobGets.Load(); m != 1 || b != 1 {
		t.Fatalf("registry calls: manifest %d blob %d", m, b)
	}
	if r, _ := e.load(t); r.For("team-a") == nil {
		t.Fatal("the pulled bundle is not active for team-a")
	}
	st, err := e.store.Status(ctx, 0)
	if err != nil || st.OCI[0].State != OCIProcessed || st.OCI[0].Result != ResultApplied {
		t.Fatalf("status after the pull: %+v %v", st.OCI, err)
	}
}

func TestGAP0437OCIWrongSignatureIsRefusedOnceAndKeepsTheStage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	good := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	if _, pulls, err := e.store.SyncOCI(ctx, good.client(t, ""), ociStage(good.ref())); err != nil || len(pulls) != 0 {
		t.Fatal(err)
	}
	rogue := newTestRegistry(t, buildBundle(t, newSigner(t, "rogue"), 4, policyYAML("x.example.com")))
	c := rogue.client(t, "")
	e.store.OCIStages = ociStage(rogue.ref())
	for i := range 2 {
		rcs, pulls, err := e.store.SyncOCI(ctx, c, e.store.OCIStages)
		if err != nil || len(pulls) != 0 {
			t.Fatal(err, pulls)
		}
		if i == 0 && (len(rcs) != 1 || rcs[0].Result != ResultRefused || rcs[0].Code != string(eb.CodeKeyUnknown) || rcs[0].Source != SourceOCI) {
			t.Fatalf("rogue bundle: %+v", rcs)
		}
		if i == 1 && len(rcs) != 0 {
			t.Fatalf("refused digest receipted twice: %+v", rcs)
		}
	}
	r, _ := e.load(t)
	if ap := r.For("team-a"); ap == nil || ap.Record.Version != 3 {
		t.Fatalf("the refused bundle changed the stage: %+v", ap)
	}
	st, _ := e.store.Status(ctx, 0)
	if st.OCI[0].Result != ResultRefused || st.OCI[0].Code != string(eb.CodeKeyUnknown) {
		t.Fatalf("status: %+v", st.OCI)
	}
}

// Every pull failure applies nothing, writes no receipt and leaves the
// stage pending, so it is tried again the next pass.
func TestGAP0437OCIPullFailuresFailClosed(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		setup func(r *testRegistry) string // returns the ref
		want  string
	}{
		{"bad manifest digest", func(r *testRegistry) string {
			return r.host() + "/policy/prod@" + sha256Digest([]byte("another manifest"))
		}, "manifest digest"},
		{"bad blob digest", func(r *testRegistry) string {
			r.blob = append(bytes.Clone(r.blob[:len(r.blob)-1]), r.blob[len(r.blob)-1]^1)
			return r.ref()
		}, "does not match its digest"},
		{"oversize manifest", func(r *testRegistry) string {
			r.manifest = append(bytes.Repeat([]byte(" "), ociMaxManifestBytes), r.manifest...)
			return r.ref()
		}, "larger than"},
		{"oversize blob declared", func(r *testRegistry) string {
			r.manifest = ociManifest(MediaTypeBundleLayer, sha256Digest(r.blob), MaxArchiveBytes+1)
			return r.ref()
		}, "layer size"},
		{"index not a manifest", func(r *testRegistry) string {
			r.manifest = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`)
			return r.ref()
		}, "not an image manifest"},
		{"no bundle layer", func(r *testRegistry) string {
			r.manifest = ociManifest("application/octet-stream", sha256Digest(r.blob), int64(len(r.blob)))
			return r.ref()
		}, "no application/vnd.defenseclaw.bundle.v1 layer"},
		{"redirect to http", func(r *testRegistry) string { r.redirect = "http"; return r.ref() }, "https only"},
		{"expired token", func(r *testRegistry) string { r.token = "expired"; return r.ref() }, "401 unauthorized"},
		{"tag-only reference", func(r *testRegistry) string { return r.host() + "/policy/prod:v7" }, "not pinned by digest"},
		{"tag and digest", func(r *testRegistry) string {
			return r.host() + "/policy/prod:v7@" + sha256Digest(r.manifest)
		}, "names a tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
			ref := tc.setup(reg)
			e.store.OCIStages = ociStage(ref)
			rcs, pulls, serr := e.store.SyncOCI(ctx, reg.client(t, ""), e.store.OCIStages)
			if serr != nil || len(pulls) != 1 || !strings.Contains(pulls[0].Error(), tc.want) || len(rcs) != 0 {
				t.Fatalf("want %q, got %+v %v %v", tc.want, rcs, pulls, serr)
			}
			if err := pulls[0]; strings.Contains(err.Error(), "Bearer") || strings.Contains(err.Error(), reg.token+`"`) {
				t.Fatalf("error leaks the token: %v", err)
			}
			if strings.HasPrefix(tc.name, "tag") && reg.manifestGets.Load()+reg.tokenGets.Load() != 0 {
				t.Fatal("a tag reference reached the registry")
			}
			if all, _ := e.store.Receipts(ctx, 0); len(all) != 0 {
				t.Fatalf("receipts: %+v", all)
			}
			if st, _ := e.store.Status(ctx, 0); len(st.Stages) != 0 || st.OCI[0].State != OCIPending {
				t.Fatalf("status: %+v", st)
			}
		})
	}
}

// A blob redirect to another host (a CDN) works, but the registry token is
// not sent there; the token service gets the configured credentials.
func TestGAP0437OCIRedirectToAnotherHostDropsAuth(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	reg.redirect = "cdn"
	creds := fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, reg.host(), base64.StdEncoding.EncodeToString([]byte("puller:s3cret")))
	rcs, pulls, err := e.store.SyncOCI(ctx, reg.client(t, creds), ociStage(reg.ref()))
	if err != nil || len(pulls) != 0 || len(rcs) != 1 || rcs[0].Result != ResultApplied {
		t.Fatalf("redirected pull: %+v %v", rcs, err)
	}
	if a, _ := reg.cdnAuth.Load().(string); a != "" {
		t.Fatalf("the CDN got the registry Authorization header %q", a)
	}
	if u, _ := reg.tokenBasic.Load().(string); u != "puller" {
		t.Fatalf("token service Basic user %q", u)
	}
}

func TestGAP0437OCIRefParse(t *testing.T) {
	d := "sha256:" + strings.Repeat("ab", 32)
	for ref, ok := range map[string]bool{
		"registry.example.com/policy/prod@" + d:      true,
		"localhost:5000/p@" + d:                      true,
		"127.0.0.1:5000/p/q@" + d:                    true,
		"policy/prod@" + d:                           false, // no explicit host
		"prod@" + d:                                  false,
		"registry.example.com/policy/prod:v1":        false,
		"registry.example.com/policy/prod:v1@" + d:   false,
		"registry.example.com/policy/prod@sha256:ab": false,
		"registry.example.com/policy/prod@sha512:" + strings.Repeat("ab", 64): false,
		"registry.example.com/Policy@" + d:                                    false,
	} {
		if _, _, _, err := config.ParseSubstrateOCIRef(ref); (err == nil) != ok {
			t.Errorf("%s: err %v, want ok=%v", ref, err, ok)
		}
	}
}
