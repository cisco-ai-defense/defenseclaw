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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// GAP-0967: docker.io/<org>/<repo>@sha256:... (the form docker pull shows) is
// requested from registry-1.docker.io, not https://docker.io/v2, which
// redirects to the web site.
func TestGAP0967DockerHubRefGoesToRegistryHost(t *testing.T) {
	archive := buildBundle(t, newEnv(t).key, 3, policyYAML("paste.example.com"))
	manifest := ociManifest(MediaTypeBundleLayer, sha256Digest(archive), int64(len(archive)))
	for _, host := range []string{"docker.io", "index.docker.io", "Docker.IO"} {
		var hosts sync.Map
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			hosts.Store(req.Host, true)
			switch {
			case strings.Contains(req.URL.Path, "/manifests/"):
				w.Header().Set("Content-Type", mediaTypeOCIManifest)
				_, _ = w.Write(manifest)
			case strings.Contains(req.URL.Path, "/blobs/"):
				_, _ = w.Write(archive)
			default:
				http.NotFound(w, req)
			}
		}))
		reg := &testRegistry{srv: srv, cdn: srv}
		c := reg.client(t, "")
		tr := c.http.Transport.(*http.Transport)
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		}
		tr.TLSClientConfig.ServerName = "example.com" // the httptest certificate
		got, err := c.Pull(context.Background(), host+"/policy/prod@"+sha256Digest(manifest))
		srv.Close()
		if err != nil || !bytes.Equal(got, archive) {
			t.Fatalf("%s: err=%v, archive match=%v", host, err, bytes.Equal(got, archive))
		}
		if _, ok := hosts.Load("registry-1.docker.io"); !ok {
			t.Errorf("%s: the registry never saw a request for registry-1.docker.io", host)
		}
		if _, ok := hosts.Load(host); ok && !strings.EqualFold(host, "registry-1.docker.io") {
			t.Errorf("%s: a request was sent to the web host", host)
		}
	}
}
