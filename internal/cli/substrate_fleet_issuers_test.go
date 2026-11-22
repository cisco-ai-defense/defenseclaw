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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// fleetKubeconfig is an administrator's kubeconfig: this cluster (kind-e1,
// also under a second context name), a second DefenseClaw cluster
// (kind-stk), a cluster without DefenseClaw (kind-bare) and one whose API
// server is gone (kind-gone).
const fleetKubeconfig = `{"current-context":"kind-e1",
 "clusters":[{"name":"kind-e1","cluster":{"server":"https://127.0.0.1:6443"}},
  {"name":"kind-e1-alias","cluster":{"server":"https://127.0.0.1:6443/"}},
  {"name":"kind-stk","cluster":{"server":"https://127.0.0.1:7443"}},
  {"name":"kind-bare","cluster":{"server":"https://127.0.0.1:8443"}},
  {"name":"kind-gone","cluster":{"server":"https://127.0.0.1:9443"}}],
 "contexts":[{"name":"kind-e1","context":{"cluster":"kind-e1"}},{"name":"e1-admin","context":{"cluster":"kind-e1-alias"}},
  {"name":"kind-stk","context":{"cluster":"kind-stk"}},{"name":"kind-bare","context":{"cluster":"kind-bare"}},
  {"name":"kind-gone","context":{"cluster":"kind-gone"}}]}`

// fakeFleetKubeconfig answers the kubeconfig and the other clusters'
// reads on top of fakeKubectl. This cluster's issuer becomes thisIssuer
// (in its config and its install file); stkIssuer is kind-stk's ("" for a
// kind-stk without DefenseClaw). It returns the contexts that were read.
func fakeFleetKubeconfig(t *testing.T, thisIssuer, stkIssuer string) (install string, read func() []string) {
	t.Helper()
	fakeKubectl(t, nil)
	inner := substrateKubectl
	var mu sync.Mutex
	var contexts []string
	substrateKubectl = func(ctx context.Context, f *substrateClusterFlags, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if f.kubeContext == "" {
			if joined == "config view -o json" {
				return []byte(fleetKubeconfig), nil
			}
			out, err := inner(ctx, f, args...)
			return []byte(strings.ReplaceAll(string(out), "https://idp.cluster-a.example.test", thisIssuer)), err
		}
		mu.Lock()
		contexts = append(contexts, f.kubeContext)
		mu.Unlock()
		if !strings.HasPrefix(joined, "get configmaps -A -l app.kubernetes.io/name=defenseclaw-substrate") {
			return nil, errors.New("unexpected kubectl call on " + f.kubeContext + ": " + joined)
		}
		switch {
		case f.kubeContext == "kind-stk" && stkIssuer != "":
			return []byte(`{"items":[{"metadata":{"name":"defenseclaw-config"},"data":{"config.yaml":"substrate:\n  identity:\n    issuer: ` +
				stkIssuer + `\n"}}]}`), nil
		case f.kubeContext == "kind-gone":
			return nil, errors.New("dial tcp 127.0.0.1:9443: connect: connection refused")
		}
		return []byte(`{"items":[]}`), nil
	}
	install = writeInstall(t, strings.ReplaceAll(fleetInstallOK, "https://idp.cluster-a.example.test", thisIssuer))
	return install, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string{}, contexts...)
	}
}

func issuerCheck(t *testing.T, install string, flags ...string) fleet.Check {
	t.Helper()
	f := &substrateClusterFlags{installFile: install, namespace: "defenseclaw-system", substrateNS: "ate-system",
		timeout: 10 * time.Second, fleetContexts: flags}
	o, r, err := collectFleet(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fleet.BuildVerify(o, r.ProductVersion, r.Now).Checks {
		if c.ID == fleet.CheckIssuer {
			return c
		}
	}
	t.Fatal("no issuer_unique check")
	return fleet.Check{}
}

// TestVerifyComparesTheIssuersOfTheKubeconfigClusters is GAP-0383: verify
// and doctor read the other clusters of the kubeconfig, so a default issuer
// on a second DefenseClaw cluster, or one issuer on two clusters, is red
// and names the issuer and the fix.
func TestVerifyComparesTheIssuersOfTheKubeconfigClusters(t *testing.T) {
	const def = "https://idp.ate-system.svc"
	t.Run("two clusters with the default issuer fail", func(t *testing.T) {
		install, read := fakeFleetKubeconfig(t, def, def)
		c := issuerCheck(t, install)
		wantCheck(t, c, fleet.Fail, "another cluster uses the same actor JWT issuer, the default "+def)
		wantCheck(t, c, fleet.Fail, "setup --issuer")
		// e1-admin is this cluster under another name: it is not read.
		got := strings.Join(read(), ",")
		if strings.Contains(got, "e1-admin") || !strings.Contains(got, "kind-stk") || !strings.Contains(got, "kind-gone") {
			t.Errorf("contexts read = %s", got)
		}
	})
	t.Run("a default issuer next to another DefenseClaw cluster fails", func(t *testing.T) {
		install, _ := fakeFleetKubeconfig(t, def, "https://stk.example.test")
		c := issuerCheck(t, install)
		wantCheck(t, c, fleet.Fail, "2 clusters run DefenseClaw and this one uses the default issuer "+def)
		wantCheck(t, c, fleet.Fail, "setup --issuer")
	})
	t.Run("one unique issuer on two clusters fails", func(t *testing.T) {
		install, _ := fakeFleetKubeconfig(t, "https://e1.example.test", "https://e1.example.test/")
		wantCheck(t, issuerCheck(t, install), fleet.Fail, "another cluster uses the same actor JWT issuer so")
	})
	t.Run("unique issuers pass", func(t *testing.T) {
		install, _ := fakeFleetKubeconfig(t, "https://e1.example.test", "https://stk.example.test")
		wantCheck(t, issuerCheck(t, install), fleet.Pass, "unique to this cluster")
	})
	t.Run("a default issuer with no other DefenseClaw cluster warns and counts the unread one", func(t *testing.T) {
		install, _ := fakeFleetKubeconfig(t, def, "")
		wantCheck(t, issuerCheck(t, install), fleet.Warn, "1 other cluster(s) of the kubeconfig could not be read")
	})
	t.Run("--fleet-contexts names the clusters to compare", func(t *testing.T) {
		install, read := fakeFleetKubeconfig(t, def, def)
		wantCheck(t, issuerCheck(t, install, "kind-bare"), fleet.Warn, "fine for one cluster; set a unique one")
		if got := read(); len(got) != 1 || got[0] != "kind-bare" {
			t.Errorf("contexts read = %v, want only kind-bare", got)
		}
		wantCheck(t, issuerCheck(t, install, "kind-missing"), fleet.Warn, "1 other cluster(s)")
	})
	t.Run("--fleet-contexts none reads this cluster only", func(t *testing.T) {
		install, read := fakeFleetKubeconfig(t, def, def)
		wantCheck(t, issuerCheck(t, install, "none"), fleet.Warn, "fine for one cluster; set a unique one")
		if got := read(); len(got) != 0 {
			t.Errorf("contexts read = %v, want none", got)
		}
	})
}
