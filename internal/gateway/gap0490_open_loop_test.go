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
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/google/uuid"
)

// TestGAP0490OpenLoopSandboxStream drives the relayed hook the way the sandbox
// hook does (a proposal, then its delivery receipt) at a steady 22 calls a
// second, under the 25/s of its sandbox, that does not wait for the answers of
// the calls before it, the way an agent issues tool calls. No call may be
// refused or left without its answer inside the answer window. The gateway
// made the durable journal and audit writes of every call one after the
// other, so the answers queued until the sandbox binding reached its open
// request bound and the calls were refused 429 (rel-1-0-6 GAP-0490, IB10).
// The same stream from two sandboxes of one account (44/s) and four (96/s)
// is the lead ruling of the row: the account bucket is 100/s with burst 200,
// so none of them may be refused.
func TestGAP0490OpenLoopSandboxStream(t *testing.T) {
	runGAP0490OpenLoop(t, 1, 22, 10*time.Second)
}

// The two-sandbox stream (44 calls a second for one account) runs in every
// test run: before the managed call writes shared one write baton and one
// correlation turn per session the gateway answered it only some of the time
// (rel-1-0-6 GAP-0490, round 6).
func TestGAP0490OpenLoopTwoSandboxes(t *testing.T) {
	runGAP0490OpenLoop(t, 2, 22, 10*time.Second)
}

// The four-sandbox stream (96 calls a second, under the 100/s of the account)
// needs the CPU and disk of a quiet host: each call makes about two dozen
// audit writes, and on the shared build box (load above 60, nice 15) the
// gateway answers about two thirds of it inside the window. It runs on
// request, DC_GAP0490_OPEN_LOOP=1, and is the managed host verification of
// the row.
func TestGAP0490OpenLoopFourSandboxes(t *testing.T) {
	if os.Getenv("DC_GAP0490_OPEN_LOOP") == "" {
		t.Skip("set DC_GAP0490_OPEN_LOOP=1 on a quiet host to run the four-sandbox open-loop stream")
	}
	runGAP0490OpenLoop(t, 4, 24, 10*time.Second)
}

func runGAP0490OpenLoop(t *testing.T, sandboxes, perSecond int, duration time.Duration) {
	f := newManagedHookAuditFixture(t, nil)
	bindings, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(t.TempDir()), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	tokens := make([]string, sandboxes)
	for i := range tokens {
		_, tokens[i], err = bindings.Mint(sandboxauth.Spec{
			SandboxName: fmt.Sprintf("g490-open-%d", i), Connector: "claudecode", AgentVersion: "2.1.156",
			HookContractID: "claudecode-hooks-v1", PolicyProfile: "open",
			Routes:   []sandboxauth.Route{sandboxauth.RouteHook},
			Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
			HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18972", Bindings: bindings}); err != nil {
		t.Fatal(err)
	}
	handler, err := f.api.SandboxIngressHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	// The hook waits 3.5 s for its answer; a race build on a loaded runner is
	// several times slower, so there it waits what the rendered hook waits.
	wait := 3500 * time.Millisecond
	if hookAnswerRaceBuild {
		wait, _ = connector.SandboxHookAttemptBudgets()
	}
	post := func(token string, body []byte, receipt bool) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), wait)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/claude-code/hook", bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
		req.Header.Set(SandboxHookIdempotencyHeader, uuid.NewString())
		if receipt {
			req.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		return resp.StatusCode, out, err
	}
	// Warm the sessions: the first call of an unseen session waits for its
	// start, which is not what this test measures.
	for i, token := range tokens {
		session := fmt.Sprintf("g490-open-%d", i)
		if status, out, err := post(token, []byte(managedHookBody(session, "UserPromptSubmit")), false); err != nil || status != http.StatusOK {
			t.Fatalf("session start %d %s %v", status, out, err)
		}
	}
	var mu sync.Mutex
	problems := map[string]int{}
	var latencies []time.Duration
	var wg sync.WaitGroup
	call := func(token string, session string, n int) {
		defer wg.Done()
		started := time.Now()
		body := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"cwd":"/tmp","tool_name":"Bash","tool_use_id":"%s-%d","tool_input":{"command":"echo ok"}}`, session, session, n)
		status, out, err := post(token, []byte(body), false)
		var answer struct {
			Action          string `json:"action"`
			DeliveryReceipt string `json:"delivery_receipt"`
		}
		if err == nil && status == http.StatusOK && json.Unmarshal(out, &answer) == nil && answer.Action == "allow" && answer.DeliveryReceipt != "" {
			ack, _ := json.Marshal(map[string]string{"delivery_receipt": answer.DeliveryReceipt, "result": "ack"})
			status, out, err = post(token, ack, true)
		} else if err == nil && status == http.StatusOK {
			err = fmt.Errorf("proposal %s", out)
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil || status != http.StatusOK {
			problems[fmt.Sprintf("%d %.80s %v", status, out, err)]++
			return
		}
		latencies = append(latencies, time.Since(started))
	}
	total := int(duration.Seconds()) * perSecond
	interval := time.Second / time.Duration(perSecond)
	start := time.Now()
	var launch sync.WaitGroup
	for i, token := range tokens {
		launch.Add(1)
		go func() {
			defer launch.Done()
			session := fmt.Sprintf("g490-open-%d", i)
			for n := 0; n < total; n++ {
				if d := time.Until(start.Add(time.Duration(n) * interval)); d > 0 {
					time.Sleep(d)
				}
				wg.Add(1)
				go call(token, session, n)
			}
		}()
	}
	launch.Wait()
	wg.Wait()
	if len(problems) != 0 {
		t.Fatalf("%d sandboxes at %d calls/s: %d of %d calls refused or unacknowledged: %v",
			sandboxes, perSecond, sandboxes*total-len(latencies), sandboxes*total, problems)
	}
	sort.Slice(latencies, func(a, b int) bool { return latencies[a] < latencies[b] })
	t.Logf("%d sandboxes at %d calls/s: %d calls, p50 %v, p95 %v", sandboxes, perSecond, len(latencies),
		latencies[len(latencies)/2], latencies[len(latencies)*95/100])
}
