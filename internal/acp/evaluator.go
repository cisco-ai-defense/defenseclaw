// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"encoding/hex"
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
	endpoint          string
	challengeEndpoint string
	token             string
	client            *http.Client
}

type httpGatewayChallenge struct {
	ServerNonce string `json:"server_nonce"`
}

func NewHTTPEvaluator(endpoint, token string) (*HTTPEvaluator, error) {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("ACP evaluator endpoint must be an http loopback URL")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("ACP evaluator endpoint must use a literal loopback address")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/v1/acp/evaluate"
	}
	challengeURL := *u
	challengeURL.Path = "/api/v1/acp/challenge"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// The scoped token must never be delegated to an environment-configured
	// proxy, even when NO_PROXY is missing or malformed.
	transport.Proxy = nil
	return &HTTPEvaluator{
		endpoint:          u.String(),
		challengeEndpoint: challengeURL.String(),
		token:             token,
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
	keyID := HTTPAuthKeyID(e.token)
	challengeNonce, serverNonce, err := e.authenticateGateway(ctx, keyID)
	if err != nil {
		return Verdict{}, err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return Verdict{}, err
	}
	requestNonce, err := NewHTTPAuthNonce()
	if err != nil {
		return Verdict{}, fmt.Errorf("create ACP evaluator request nonce: %w", err)
	}
	evaluationURL, err := url.Parse(e.endpoint)
	if err != nil {
		return Verdict{}, err
	}
	ciphertext, err := SealHTTPPayload(
		e.token, keyID, challengeNonce, serverNonce, requestNonce,
		http.MethodPost, evaluationURL.Path, body,
	)
	if err != nil {
		return Verdict{}, fmt.Errorf("encrypt ACP evaluation: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(ciphertext))
	if err != nil {
		return Verdict{}, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-DefenseClaw-Client", "defenseclaw-acp/1.0")
	req.Header.Set(AuthKeyIDHeader, keyID)
	req.Header.Set(AuthNonceHeader, requestNonce)
	req.Header.Set(AuthChallengeNonceHeader, challengeNonce)
	req.Header.Set(AuthServerNonceHeader, serverNonce)
	req.Header.Set(AuthRequestMACHeader, HTTPRequestMAC(e.token, keyID, requestNonce, req.Method, req.URL.Path, ciphertext))
	resp, err := e.client.Do(req)
	if err != nil {
		return Verdict{}, err
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, (64<<10)+1)
	payload, err := io.ReadAll(limited)
	if err != nil {
		return Verdict{}, fmt.Errorf("read ACP verdict: %w", err)
	}
	if len(payload) > 64<<10 {
		return Verdict{}, errors.New("ACP evaluator response is too large")
	}
	if !VerifyHTTPResponseMAC(e.token, keyID, requestNonce, resp.StatusCode, payload, resp.Header.Get(AuthResponseMACHeader)) {
		return Verdict{}, errors.New("ACP evaluator response authentication failed")
	}
	if resp.StatusCode == http.StatusConflict {
		return Verdict{}, ErrModeMismatch
	}
	if resp.StatusCode != http.StatusOK {
		return Verdict{}, fmt.Errorf("ACP evaluator returned HTTP %d", resp.StatusCode)
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

func (e *HTTPEvaluator) authenticateGateway(ctx context.Context, keyID string) (string, string, error) {
	challengeNonce, err := NewHTTPAuthNonce()
	if err != nil {
		return "", "", fmt.Errorf("create ACP gateway challenge: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.challengeEndpoint, http.NoBody)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("X-DefenseClaw-Client", "defenseclaw-acp/1.0")
	req.Header.Set(AuthKeyIDHeader, keyID)
	req.Header.Set(AuthNonceHeader, challengeNonce)
	req.Header.Set(AuthRequestMACHeader, HTTPRequestMAC(e.token, keyID, challengeNonce, req.Method, req.URL.Path, nil))
	resp, err := e.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, (4<<10)+1))
	if err != nil {
		return "", "", fmt.Errorf("read ACP gateway challenge: %w", err)
	}
	if len(payload) > 4<<10 {
		return "", "", errors.New("ACP gateway challenge response is too large")
	}
	if !VerifyHTTPResponseMAC(e.token, keyID, challengeNonce, resp.StatusCode, payload, resp.Header.Get(AuthResponseMACHeader)) {
		return "", "", errors.New("ACP gateway challenge authentication failed")
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("ACP gateway challenge returned HTTP %d", resp.StatusCode)
	}
	var challenge httpGatewayChallenge
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&challenge); err != nil {
		return "", "", fmt.Errorf("decode ACP gateway challenge: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", "", errors.New("decode ACP gateway challenge: trailing JSON value")
	}
	if decoded, err := hex.DecodeString(challenge.ServerNonce); err != nil || len(decoded) != 32 {
		return "", "", errors.New("ACP gateway challenge nonce is malformed")
	}
	return challengeNonce, challenge.ServerNonce, nil
}
