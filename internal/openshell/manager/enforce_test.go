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

package manager

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// approvedRule creates a ready sandbox with one approved triaged rule to
// host and returns the sandbox name and the rule.
func approvedRule(t *testing.T, e *harnessEnv, name, host string) string {
	t.Helper()
	rule := "allow_" + ruleToken(host) + "_443"
	sb := e.create(sandboxapi.CreateRequest{Name: name})
	e.watch.waitStarted(t, sb.Name)
	id := addChunk(e, sb.Name, chunk(rule, host, 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "approval applied", func() bool { return chunkStatus(e, sb.Name, id) == "approved" })
	return rule
}

func ruleToken(host string) string {
	out := []byte(host)
	for i, c := range out {
		if c == '.' || c == '-' {
			out[i] = '_'
		}
	}
	return string(out)
}

func hasRule(e *harnessEnv, sandbox, rule string) bool {
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sandbox)
	_, ok := policy.NetworkPolicies[rule]
	return ok
}

// TestBlockListRemovesApprovedRules pins that a destination the user adds
// to the block list loses the approved direct rules it already has: they
// bypass the proxy that now blocks it. Rules to other destinations stay.
func TestBlockListRemovesApprovedRules(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	drop := approvedRule(t, e, "blkbox", "drop.example.org")
	id := addChunk(e, "blkbox", chunk("allow_keep_example_org_443", "keep.example.org", 443))
	e.watch.push(t, "blkbox", stream.Event{Kind: stream.KindDraft})
	eventually(t, "second approval applied", func() bool { return chunkStatus(e, "blkbox", id) == "approved" })

	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"drop.example.org"} })
	e.m.enforceAll(context.Background())
	if hasRule(e, "blkbox", drop) {
		t.Fatal("the rule to the blocked destination is still in the policy")
	}
	if !hasRule(e, "blkbox", "allow_keep_example_org_443") {
		t.Fatal("a rule to another destination was removed")
	}
	var recorded bool
	e.tel.mu.Lock()
	for _, p := range e.tel.policy {
		recorded = recorded || (p.Operation == audit.SandboxPolicyRuleRemove && p.Target == drop && p.Reason == policyReasonBlocklist)
	}
	e.tel.mu.Unlock()
	if !recorded {
		t.Fatal("no rule_remove record for the blocked destination")
	}
}

// hold opens a CONNECT tunnel for sandbox's credential and keeps it open.
func (lp *liveProxy) hold(t *testing.T, e *harnessEnv, sandbox, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	e.m.mu.Lock()
	cred := e.m.boxes[sandbox].cred
	e.m.mu.Unlock()
	conn, err := net.DialTimeout("tcp", lp.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	auth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s = %v, %v", target, resp, err)
	}
	return conn, br
}

// closedSoon reports whether the proxy closes a held tunnel within wait.
func closedSoon(conn net.Conn, br *bufio.Reader, wait time.Duration) bool {
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, err := br.ReadByte()
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

// TestPolicyChangesCloseOpenTunnels pins that tightening a running
// sandbox's egress reaches its open proxy tunnels, not only new ones: a
// destination added to the block list, and a credential revoked when the
// sandbox's network mode becomes deny.
func TestPolicyChangesCloseOpenTunnels(t *testing.T) {
	e := newEnv(t, nil)
	proxy := startLiveProxy(t, e)
	e.create(sandboxapi.CreateRequest{Name: "tunnelbox"})
	blocked, blockedR := proxy.hold(t, e, "tunnelbox", "drop.example.org:443")
	kept, keptR := proxy.hold(t, e, "tunnelbox", "keep.example.org:443")
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"drop.example.org"} })
	e.m.refreshEgress()
	if !closedSoon(blocked, blockedR, 3*time.Second) {
		t.Fatal("the tunnel to the newly blocked destination is still open")
	}
	if closedSoon(kept, keptR, 300*time.Millisecond) {
		t.Fatal("a tunnel the policy still allows was closed")
	}
	// The administrator raises the floor to strict: no web egress at all.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = config.OpenShellProfileStrict })
	e.m.refreshEgress()
	if !closedSoon(kept, keptR, 3*time.Second) {
		t.Fatal("a tunnel survived the revocation of its sandbox's credential")
	}
}

// TestSandboxLargeUploadThresholdIsItsOwn pins that each sandbox's proxy
// credential carries its own pack's large-upload threshold, and follows a
// configuration change, instead of one process-wide value.
func TestSandboxLargeUploadThresholdIsItsOwn(t *testing.T) {
	dir := t.TempDir()
	pack := strings.Replace(teamPack, "name: team", "name: small", 1)
	pack = strings.Replace(pack, "ports: [443, 8443]", "ports: [443, 8443]\n  large_upload_mb: 7", 1)
	if err := os.MkdirAll(filepath.Join(dir, "small"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "small", "pack.yaml"), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = dir })
	e.create(sandboxapi.CreateRequest{Name: "smallbox", Pack: "small"})
	e.create(sandboxapi.CreateRequest{Name: "defaultbox", Project: e.otherProject("default")})
	threshold := func(name string) int64 {
		t.Helper()
		b, _ := e.store.Lookup(name)
		pr, ok := e.m.creds.Lookup(b.ID)
		if !ok {
			t.Fatalf("%s has no proxy credential", name)
		}
		return pr.LargeUploadBytes
	}
	if got := threshold("smallbox"); got != 7<<20 {
		t.Fatalf("smallbox threshold = %d, want its pack's 7 MiB", got)
	}
	base := threshold("defaultbox")
	if base <= 0 || base == 7<<20 {
		t.Fatalf("defaultbox threshold = %d, want the default pack's", base)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.LargeUploadMB = 3 })
	e.m.refreshEgress()
	if got := threshold("defaultbox"); got != 3<<20 {
		t.Fatalf("defaultbox threshold after the change = %d, want 3 MiB", got)
	}
}

// TestConfigChangeIsEnforcedAfterAnEgressRefresh pins that an
// administrator's tightening reaches approved rules even when a create or
// delete rebuilt the egress deciders from the new configuration before
// the config loop saw it.
func TestConfigChangeIsEnforcedAfterAnEgressRefresh(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	rule := approvedRule(t, e, "cfgbox", "gone.example.org")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"gone.example.org"} })
	// A create or delete finishing first refreshes the deciders.
	e.m.refreshEgress()
	deadline := time.Now().Add(6 * time.Second)
	for hasRule(e, "cfgbox", rule) {
		if time.Now().After(deadline) {
			t.Fatal("the admin-blocked rule survived the configuration change")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
