// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build s7probe

package gateway

// Bench-only probe (rel-1-0-10 S7 S1-a): N tool calls through the real
// decision-model client (newDecisionModel, decide) against the configured
// endpoint. Run with -tags s7probe; inputs and settings come from S7PROBE_*.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type probeSlot struct {
	status int
	tokens int
	code   string
}

type probeSlotKey struct{}

type probeRT struct{ base http.RoundTripper }

func (p probeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.base.RoundTrip(req)
	slot, _ := req.Context().Value(probeSlotKey{}).(*probeSlot)
	if err != nil || slot == nil {
		return resp, err
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	slot.status = resp.StatusCode
	slot.code, slot.tokens = probeFacts(raw)
	return resp, nil
}

func probeFacts(raw []byte) (string, int) {
	var v struct {
		Error struct {
			Code json.RawMessage `json:"code"`
		} `json:"error"`
		Usage struct {
			Input int `json:"total_input_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(raw, &v)
	code := ""
	if len(v.Error.Code) > 0 {
		if json.Unmarshal(v.Error.Code, &code) != nil {
			code = string(v.Error.Code)
		}
	}
	return code, v.Usage.Input
}

func probeEnvInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

func TestS7SysOneProbe(t *testing.T) {
	in, outPath := os.Getenv("S7PROBE_IN"), os.Getenv("S7PROBE_OUT")
	if in == "" || outPath == "" {
		t.Skip("S7PROBE_IN and S7PROBE_OUT not set")
	}
	timeout, _ := strconv.ParseFloat(os.Getenv("S7PROBE_TIMEOUT"), 64)
	cfg := &config.Config{DecisionModel: config.DecisionModelConfig{
		Enabled: true, Model: os.Getenv("S7PROBE_MODEL"), BaseURL: os.Getenv("S7PROBE_URL"),
		Protocol: os.Getenv("S7PROBE_PROTOCOL"), Timeout: timeout,
	}}
	dm := newDecisionModel(cfg, "")
	if dm == nil {
		t.Fatal("decision model not built")
	}
	dm.client.Transport = probeRT{base: dm.client.Transport}
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	type pc struct {
		ID, Corpus, Tool, Args, Intent, Expected string
	}
	var cases []pc
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var c pc
		if json.Unmarshal(sc.Bytes(), &c) == nil {
			cases = append(cases, c)
		}
	}
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	var mu sync.Mutex
	// Phases: paced calls (interval S7PROBE_INTERVAL_MS, one at a time),
	// then the last S7PROBE_BURST cases at S7PROBE_BURST_CONC unpaced.
	interval := time.Duration(probeEnvInt("S7PROBE_INTERVAL_MS", 2000)) * time.Millisecond
	burst := probeEnvInt("S7PROBE_BURST", 0)
	conc := probeEnvInt("S7PROBE_BURST_CONC", 4)
	run := func(i int, c pc, phase string) {
		slot := &probeSlot{}
		ctx := context.WithValue(context.Background(), probeSlotKey{}, slot)
		state := decisionModelState{SessionUserIntent: c.Intent,
			CurrentToolCall: decisionModelToolCall{Tool: sanitizeToolName(c.Tool), Arguments: boundToolJudgeArguments(c.Args)}}
		t0 := time.Now()
		res := dm.decide(ctx, state)
		route := map[decisionRoute]string{decisionEscalate: "escalate", decisionAllow: "allow", decisionBlock: "block"}[res.route]
		row, _ := json.Marshal(map[string]any{"i": i, "phase": phase, "id": c.ID, "corpus": c.Corpus, "expected": c.Expected,
			"route": route, "choice": res.choice, "risk": res.risk, "latency_ms": time.Since(t0).Milliseconds(),
			"failure": string(res.failure), "cause": res.failureCause, "skipped": res.skipped,
			"status": slot.status, "input_tokens": slot.tokens, "error_code": slot.code})
		mu.Lock()
		_, _ = out.Write(append(row, '\n'))
		mu.Unlock()
	}
	paced := len(cases) - burst
	for i := 0; i < paced; i++ {
		next := time.Now().Add(interval)
		run(i, cases[i], "paced")
		time.Sleep(time.Until(next))
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i := paced; i < len(cases); i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			run(i, cases[i], "burst")
		}(i)
	}
	wg.Wait()
}
