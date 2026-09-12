// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrModeMismatch = errors.New("ACP runtime mode does not match central policy")

type Evaluation struct {
	Profile   string          `json:"profile"`
	Mode      Mode            `json:"mode"`
	AgentID   string          `json:"agent_id"`
	ClientID  string          `json:"client_id"`
	Direction Direction       `json:"direction"`
	Surface   Surface         `json:"surface"`
	Method    string          `json:"method,omitempty"`
	Payload   json.RawMessage `json:"payload"`
	Aggregate bool            `json:"aggregate,omitempty"`
}

type Verdict struct {
	Action     string `json:"action"`
	RawAction  string `json:"raw_action,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Reason     string `json:"reason,omitempty"`
	WouldBlock bool   `json:"would_block,omitempty"`
}

type Evaluator interface {
	Evaluate(context.Context, Evaluation) (Verdict, error)
}

type AllowEvaluator struct{}

func (AllowEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	return Verdict{Action: "allow", RawAction: "allow"}, nil
}

type HTTPEvaluator struct {
	endpoint string
	token    string
	client   *http.Client
}

func NewHTTPEvaluator(endpoint, token string) (*HTTPEvaluator, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil {
		return nil, errors.New("ACP evaluator endpoint must be an http loopback URL")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("ACP evaluator endpoint must use a literal loopback address")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/v1/acp/evaluate"
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The scoped token must never be delegated to an environment-configured
	// proxy, even when NO_PROXY is missing or malformed.
	transport.Proxy = nil
	return &HTTPEvaluator{
		endpoint: u.String(),
		token:    token,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (e *HTTPEvaluator) Evaluate(ctx context.Context, in Evaluation) (Verdict, error) {
	body, err := json.Marshal(in)
	if err != nil {
		return Verdict{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "defenseclaw-acp/1.0")
	if e.token != "" {
		req.Header.Set("Authorization", "Bearer "+e.token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, (64<<10)+1)
	if resp.StatusCode == http.StatusConflict {
		_, _ = io.Copy(io.Discard, limited)
		return Verdict{}, ErrModeMismatch
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, limited)
		return Verdict{}, fmt.Errorf("ACP evaluator returned HTTP %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(limited)
	if err != nil {
		return Verdict{}, fmt.Errorf("read ACP verdict: %w", err)
	}
	if len(payload) > 64<<10 {
		return Verdict{}, errors.New("ACP evaluator response is too large")
	}
	var verdict Verdict
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&verdict); err != nil {
		return Verdict{}, fmt.Errorf("decode ACP verdict: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Verdict{}, errors.New("decode ACP verdict: trailing JSON value")
	}
	if verdict.Action != "allow" && verdict.Action != "block" && verdict.Action != "confirm" && verdict.Action != "alert" {
		return Verdict{}, errors.New("ACP evaluator returned an invalid action")
	}
	return verdict, nil
}
