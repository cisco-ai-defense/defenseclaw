// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
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
					problems[fmt.Sprintf("proposal %d %s %v", status, out, err)]++
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
				status, out, err = post(ack, true)
				if err != nil || status != http.StatusOK {
					mu.Lock()
					problems[fmt.Sprintf("receipt %d %s %v", status, out, err)]++
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

func TestGAP0490CanceledRelayFreesBindingAdmission(t *testing.T) {
	entered := make(chan struct{})
	finish := make(chan struct{})
	var calls atomic.Int32
	f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
		cfg.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{
			HookRPS: 1000, HookBurst: 1000, MaxInFlight: 1,
		})
		cfg.OnRequest = func(_ sandboxauth.Binding, route sandboxauth.Route) {
			if route == sandboxauth.RouteHook && calls.Add(1) == 1 {
				close(entered)
				<-finish
			}
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", bytes.NewBufferString(`{}`)).WithContext(ctx)
	first.RemoteAddr = "127.0.0.1:43210"
	first.Header.Set("Authorization", "Bearer "+f.claudeTok)
	first.Header.Set("Content-Type", "application/json")
	first.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.handler.ServeHTTP(httptest.NewRecorder(), first)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(finish)
		t.Fatal("first request was not admitted")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		second := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`)
		if second.Code != http.StatusTooManyRequests {
			break
		}
		if time.Now().After(deadline) {
			close(finish)
			t.Fatal("canceled relay retained the binding admission slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(finish)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("first handler did not finish")
	}
}
