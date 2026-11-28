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

// RV-OCI fixes (GAP-0950..0954): the review probes as red/green tests.

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	eb "github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

type lockedSink struct {
	mu  sync.Mutex
	evs []controller.Event
}

func (s *lockedSink) Emit(ev controller.Event) { s.mu.Lock(); s.evs = append(s.evs, ev); s.mu.Unlock() }

func (s *lockedSink) of(typ string) []controller.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(s.evs), func(ev controller.Event) bool { return ev.Type != typ })
}

// realmServer is a token service on a third host; it records what it got.
func realmServer(t *testing.T, c *OCIClient, token string) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	var hits atomic.Int32
	var auth atomic.Value
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		auth.Store(req.Header.Get("Authorization"))
		fmt.Fprintf(w, `{"token":%q}`, token)
	}))
	t.Cleanup(s.Close)
	c.http.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(s.Certificate())
	return s, &hits, &auth
}

func basicCreds(host string) string {
	return fmt.Sprintf(`{"auths":{%q:{"auth":%q}}}`, host, base64.StdEncoding.EncodeToString([]byte("puller:s3cret")))
}

// GAP-0950 (probe RVOCI-A): the blob CDN a registry redirects to answers 401
// with a Bearer realm on a third host. The challenge is not answered, so the
// third host never sees the registry credentials.
func TestGAP0950OCIRedirectTarget401IsNotAnswered(t *testing.T) {
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	c := reg.client(t, basicCreds(reg.host()))
	evil, hits, auth := realmServer(t, c, "x")
	reg.cdn.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+evil.URL+`/t"`)
		http.Error(w, "no", http.StatusUnauthorized)
	})
	reg.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/manifests/") {
			_, _ = w.Write(reg.manifest)
			return
		}
		http.Redirect(w, req, reg.cdn.URL+"/blob", http.StatusTemporaryRedirect)
	})
	_, err := c.Pull(context.Background(), reg.ref())
	if err == nil || !strings.Contains(err.Error(), "401 from the redirect target") {
		t.Fatalf("pull: %v", err)
	}
	if n := hits.Load(); n != 0 {
		a, _ := auth.Load().(string)
		t.Fatalf("the realm named by the redirect target was asked %d times (Authorization %q)", n, a)
	}
}

// GAP-0950: the registry's own realm must be on the registry host or on
// substrate.bundles.oci.auth_hosts; nothing is sent to any other host.
func TestGAP0950OCITokenRealmMustBeRegistryOrAuthHost(t *testing.T) {
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	var realmURL string
	reg.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer good" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="`+realmURL+`/token",service="test-registry"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		reg.serve(w, req)
	})
	c := reg.client(t, basicCreds(reg.host()))
	evil, hits, _ := realmServer(t, c, "good")
	realmURL = evil.URL
	if _, err := c.Pull(context.Background(), reg.ref()); err == nil || !strings.Contains(err.Error(), "auth_hosts") || hits.Load() != 0 {
		t.Fatalf("realm on a third host: err %v, realm asked %d times", err, hits.Load())
	}
	c2 := reg.client(t, basicCreds(reg.host()))
	evil2, hits2, auth2 := realmServer(t, c2, "good")
	realmURL = evil2.URL
	c2.authHosts[ociHostKey(strings.TrimPrefix(evil2.URL, "https://"))] = true
	if _, err := c2.Pull(context.Background(), reg.ref()); err != nil || hits2.Load() != 1 {
		t.Fatalf("realm on a configured auth host: %v (asked %d times)", err, hits2.Load())
	}
	if a, _ := auth2.Load().(string); a != "Basic "+base64.StdEncoding.EncodeToString([]byte("puller:s3cret")) {
		t.Fatalf("auth host got %q", a)
	}
}

// GAP-0951 (probe RVOCI-F): with the registry down the controller still
// starts (the pull is a warning), within about one pull timeout.
func TestGAP0951OCIRegistryDownDoesNotFailStart(t *testing.T) {
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	c := reg.client(t, "")
	ref := reg.ref()
	reg.srv.Close()
	sink := &lockedSink{}
	m := &Manager{Store: e.store, Resolver: NewResolver(e.store.Base), OCI: c, OCIStages: ociStage(ref), Sink: sink, Interval: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t0 := time.Now()
	if err := m.Start(ctx); err != nil {
		t.Fatalf("Start with the registry down: %v", err)
	}
	if el := time.Since(t0); el > 10*time.Second {
		t.Fatalf("Start took %v", el)
	}
	if w := sink.of(controller.EventWarning); len(w) != 1 || !strings.Contains(w[0].Message, "tried again at the next refresh") || w[0].Severity != controller.SeverityWarn {
		t.Fatalf("warnings: %+v", w)
	}
}

// GAP-0952 (probe RVOCI-B): a refusal caused by the cluster (the anchors
// Secret not mounted yet) is receipted once while the cluster stays the same
// and pulled again once it changes.
func TestGAP0952OCIClusterRefusalIsRetriedWhenTheClusterChanges(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	c := reg.client(t, "")
	good := e.store.Anchors
	missing := filepath.Join(t.TempDir(), "missing.json")
	e.store.Anchors = func() (*eb.Anchors, error) { return LoadAnchorsFile(missing) }
	e.store.OCIStages = ociStage(reg.ref())
	for i := range 2 {
		rcs, pulls, err := e.store.SyncOCI(ctx, c, e.store.OCIStages)
		if err != nil || len(pulls) != 0 || len(rcs) != 1-i {
			t.Fatalf("pass %d with the anchors missing: %+v %v %v", i, rcs, pulls, err)
		}
		if i == 0 && rcs[0].Code != string(eb.CodeAnchorMissing) {
			t.Fatalf("refusal: %+v", rcs[0])
		}
	}
	if n := reg.manifestGets.Load(); n != 1 {
		t.Fatalf("pulled %d times while the cluster did not change", n)
	}
	if st, err := e.store.Status(ctx, 0); err != nil || st.OCI[0].State != OCIProcessed || st.OCI[0].Code != string(eb.CodeAnchorMissing) {
		t.Fatalf("status with the anchors missing: %+v %v", st.OCI, err)
	}
	e.store.Anchors = good
	if st, err := e.store.Status(ctx, 0); err != nil || st.OCI[0].State != OCIPending {
		t.Fatalf("status once the anchors are back: %+v %v", st.OCI, err)
	}
	rcs, pulls, err := e.store.SyncOCI(ctx, c, e.store.OCIStages)
	if err != nil || len(pulls) != 0 || len(rcs) != 1 || rcs[0].Result != ResultApplied {
		t.Fatalf("pass once the anchors are back: %+v %v %v", rcs, pulls, err)
	}
	if r, _ := e.load(t); r.For("team-a") == nil || reg.manifestGets.Load() != 2 {
		t.Fatalf("not active after the anchors came back (pulls %d)", reg.manifestGets.Load())
	}
}

// GAP-0953: a pass re-verifies the active bundles before it asks any
// registry, and blackholed registries cost about one pull timeout per pass,
// not one per stage.
func TestGAP0953ReverifyRunsBeforeOCIAndThePassIsBounded(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	if _, err := e.store.Apply(ctx, buildBundle(t, e.key, 1, policyYAML("paste.example.com")), "canary", []string{"team-a"}, SourceCLI); err != nil {
		t.Fatal(err)
	}
	sink := &lockedSink{}
	m := &Manager{Store: e.store, Resolver: NewResolver(e.store.Base), Sink: sink}
	if err := m.Refresh(ctx); err != nil || m.Resolver.For("team-a") == nil {
		t.Fatalf("first refresh: %v", err)
	}
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	var hits, enforced atomic.Int32
	reg.srv.Config.Handler = http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		if m.Resolver.For("team-a") == nil {
			enforced.Add(1)
		}
		<-req.Context().Done() // blackholed
	})
	m.OCI = reg.client(t, "")
	m.OCI.timeout = time.Second
	d := sha256Digest(reg.manifest)
	for i, ns := range []string{"team-x", "team-y", "team-z"} {
		m.OCIStages = append(m.OCIStages, OCIStage{Stage: fmt.Sprintf("s%d", i), Ref: reg.host() + "/policy/s" + fmt.Sprint(i) + "@" + d, Atespaces: []string{ns}})
	}
	e.anchors = anchorsFor(t, 0, ks(e.key, eb.KeyRevoked))
	t0 := time.Now()
	err := m.Refresh(ctx)
	el := time.Since(t0)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if hits.Load() != 3 || enforced.Load() != 3 {
		t.Fatalf("registry asked %d times, %d after the revocation was enforced", hits.Load(), enforced.Load())
	}
	if el > 2500*time.Millisecond {
		t.Fatalf("a pass with 3 blackholed stages took %v (one timeout is 1s)", el)
	}
	if w := sink.of(controller.EventWarning); len(w) != 3 || !strings.Contains(w[0].Message, "timed out") {
		t.Fatalf("warnings: %+v", w)
	}
	if u := sink.of(EventUnverified); len(u) != 1 || u[0].Detail["code"] != string(eb.CodeKeyRevoked) {
		t.Fatalf("unverified: %+v", u)
	}
}

// GAP-0954 (probe RVOCI-E): docker login keys match, an identitytoken entry
// gives no credentials and is named when the registry asks for them.
func TestGAP0954DockerConfigKeysAndIdentityToken(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	a := base64.StdEncoding.EncodeToString([]byte("u:p"))
	z := base64.StdEncoding.EncodeToString([]byte("00000000-0000-0000-0000-000000000000:"))
	doc := fmt.Sprintf(`{"auths":{"https://index.docker.io/v1/":{"auth":%q},"Reg.Example.com:5000":{"auth":%q},"https://ghcr.io/v2/":{"username":"g","password":"p"},"acr.example.io":{"auth":%q,"identitytoken":"refresh-secret"}}}`, a, a, z)
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, idTok, err := readDockerConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"registry-1.docker.io", "reg.example.com:5000", "ghcr.io"} {
		if creds[ociHostKey(h)].user == "" {
			t.Fatalf("no credentials for %s: %v", h, creds)
		}
	}
	if _, ok := creds["acr.example.io"]; ok || !idTok["acr.example.io"] || len(creds) != 3 {
		t.Fatalf("identitytoken entry: creds %v idTok %v", creds, idTok)
	}
	for _, h := range []string{"docker.io", "index.docker.io", "registry-1.docker.io:443"} {
		if ociHostKey(h) != "registry-1.docker.io" {
			t.Fatalf("ociHostKey(%s) = %s", h, ociHostKey(h))
		}
	}

	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	reg.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	c := reg.client(t, fmt.Sprintf(`{"auths":{%q:{"identitytoken":"refresh-secret"}}}`, reg.host()))
	_, err = c.Pull(context.Background(), reg.ref())
	if err == nil || !strings.Contains(err.Error(), "identitytoken, which is not supported") || strings.Contains(err.Error(), "refresh-secret") {
		t.Fatalf("pull: %v", err)
	}
}

// GAP-0954 (probe RVOCI-D): a body cut by the pull deadline says timed out.
func TestGAP0954BodyReadDeadlineSaysTimedOut(t *testing.T) {
	e := newEnv(t)
	reg := newTestRegistry(t, buildBundle(t, e.key, 3, policyYAML("paste.example.com")))
	reg.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		for range 1000 {
			_, _ = w.Write([]byte(" "))
			w.(http.Flusher).Flush()
			select {
			case <-req.Context().Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	})
	c := reg.client(t, "")
	c.timeout = time.Second
	t0 := time.Now()
	_, err := c.Pull(context.Background(), reg.ref())
	if err == nil || !strings.Contains(err.Error(), "manifests "+reg.host()+": timed out") || time.Since(t0) > 5*time.Second {
		t.Fatalf("slow body: %v after %v", err, time.Since(t0))
	}
}
