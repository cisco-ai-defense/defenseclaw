// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func TestGAP0490SandboxReceiptCapacity(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	bindings, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(t.TempDir()), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := bindings.Mint(sandboxauth.Spec{
		SandboxName: "g490-sandbox", Connector: "claudecode", AgentVersion: "2.1.156",
		HookContractID: "claudecode-hooks-v1", PolicyProfile: "open",
		Routes:   []sandboxauth.Route{sandboxauth.RouteHook},
		Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: bindings}); err != nil {
		t.Fatal(err)
	}
	handler, err := f.api.SandboxIngressHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	post := func(body []byte, receipt bool) (int, []byte, error) {
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/claude-code/hook", bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
		if receipt {
			req.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		return resp.StatusCode, out, err
	}
	jobs := make(chan int, 400)
	for i := 0; i < 400; i++ {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	var mu sync.Mutex
	problems := make(map[string]int)
	for worker := 0; worker < 20; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				status, out, err := post([]byte(managedHookBody(fmt.Sprintf("g490-%d", i), "PreToolUse")), false)
				if err != nil || status != http.StatusOK {
					mu.Lock()
					problems[fmt.Sprintf("proposal %d %v", status, err)]++
					mu.Unlock()
					continue
				}
				var answer struct {
					Action          string `json:"action"`
					DeliveryReceipt string `json:"delivery_receipt"`
				}
				if err := json.Unmarshal(out, &answer); err != nil || answer.Action != "allow" || answer.DeliveryReceipt == "" {
					mu.Lock()
					problems[fmt.Sprintf("proposal body %s %v", out, err)]++
					mu.Unlock()
					continue
				}
				ack, _ := json.Marshal(map[string]string{"delivery_receipt": answer.DeliveryReceipt, "result": "ack"})
				status, _, err = post(ack, true)
				if err != nil || status != http.StatusOK {
					mu.Lock()
					problems[fmt.Sprintf("receipt %d %v", status, err)]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	if len(problems) != 0 {
		t.Fatalf("400 calls at 20 parallel: %v", problems)
	}
}
