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

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestSandboxConfigPersister(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Gateway.Token = "test-token"
	cfg.Guardrail.Mode, cfg.Guardrail.ScannerMode = "observe", "local"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	bindTestConfigRuntime(t, api)
	p := sandboxConfigPersister{api: api}
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		if err := p.AllowAlways(ctx, "registry.example.org"); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.AllowAlways(ctx, "docs.example.org"); err != nil {
		t.Fatal(err)
	}
	if err := p.BlockAlways(ctx, "paste.example.net"); err != nil {
		t.Fatal(err)
	}
	live := api.runtimeConfigSnapshot()
	if !slices.Equal(live.OpenShell.Egress.Allow, []string{"registry.example.org", "docs.example.org"}) ||
		!slices.Equal(live.OpenShell.Egress.Block, []string{"paste.example.net"}) {
		t.Fatalf("persisted allow %v block %v", live.OpenShell.Egress.Allow, live.OpenShell.Egress.Block)
	}
	raw, err := os.ReadFile(configFilePathForSnapshot(live))
	if err != nil || !strings.Contains(string(raw), "registry.example.org") {
		t.Fatalf("config file = %s, %v", raw, err)
	}

	// An invalid entry is refused and the file restored.
	before, _ := os.ReadFile(configFilePathForSnapshot(live))
	if err := p.AllowAlways(ctx, "bad host name!"); err == nil {
		t.Fatal("invalid host persisted")
	}
	after, _ := os.ReadFile(configFilePathForSnapshot(live))
	if string(before) != string(after) {
		t.Fatal("config not restored after a refused patch")
	}
}

func TestSandboxConfigPersisterRefusals(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	if err := (sandboxConfigPersister{api: api}).AllowAlways(context.Background(), "a.example"); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("without a config runtime: %v", err)
	}
	api.SetConfigRuntime(func(context.Context, string) error { return nil }, func() *config.Config {
		return &config.Config{DeploymentMode: "managed_enterprise"}
	})
	if err := (sandboxConfigPersister{api: api}).AllowAlways(context.Background(), "a.example"); !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
		t.Fatalf("managed_enterprise: %v", err)
	}
}

func TestNewSandboxRuntimeDisabled(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	sc := &Sidecar{health: NewSidecarHealth(), logger: logger}
	sc.cfgCurrent.Store(cfg)
	api := NewAPIServer("127.0.0.1:0", sc.health, nil, store, logger, cfg)
	rt, err := sc.newSandboxRuntime(api)
	if err != nil || rt != nil {
		t.Fatalf("disabled runtime = %v, %v", rt, err)
	}
	if api.SandboxIngressAddr() != "" {
		t.Fatal("ingress configured while disabled")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestSandboxRuntimeServesListeners runs the sandbox subsystem without an
// OpenShell gateway: the ingress and the egress proxy still come up (hooks
// fail closed, egress needs a credential), and the API reports the
// subsystem as unavailable.
func TestSandboxRuntimeServesListeners(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("sandboxes run on Linux and macOS only")
	}
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Gateway.Token = "test-token"
	cfg.Gateway.APIPort = freePort(t)
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.IngressPort = freePort(t)
	cfg.OpenShell.EgressPort = freePort(t)
	cfg.OpenShell.Gateway.Name = "defenseclaw-test-missing"
	sc := &Sidecar{health: NewSidecarHealth(), logger: logger}
	sc.cfgCurrent.Store(cfg)
	api := NewAPIServer("127.0.0.1:0", sc.health, nil, store, logger, cfg)
	rt, err := sc.newSandboxRuntime(api)
	if err != nil || rt == nil {
		t.Fatalf("runtime = %v, %v", rt, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.run(ctx, func(ctx context.Context) error { <-ctx.Done(); return nil }) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	}()

	ingress := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.OpenShell.IngressPort))
	eventuallyTrue(t, func() bool {
		resp, err := http.Post(ingress+"/api/v1/claude-code/hook", "application/json", strings.NewReader("{}"))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusUnauthorized
	})
	egressAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.OpenShell.EgressPort))
	eventuallyTrue(t, func() bool {
		conn, err := net.DialTimeout("tcp", egressAddr, time.Second)
		if err != nil {
			return false
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
		line, _ := bufio.NewReader(conn).ReadString('\n')
		return strings.Contains(line, "407")
	})
	h := api.tokenAuth(api.apiCSRFProtect(api.sandboxAPIHandler()))
	w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathStatus, ""))
	var st sandboxapi.Status
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if w.Code != 200 || !st.Enabled || st.Available || st.Reason == "" {
		t.Fatalf("status = %d %+v", w.Code, st)
	}
	// The listeners run; the missing OpenShell gateway degrades the
	// subsystem and says why.
	eventuallyTrue(t, func() bool {
		snap := sc.health.Snapshot()
		return snap.Sandbox != nil && snap.Sandbox.State == StateDegraded && strings.Contains(snap.Sandbox.LastError, "openshell:")
	})
}
