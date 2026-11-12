// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

// RemoteRouterClient is the vllm_sr classifier: the pinned vLLM Semantic
// Router container or a remote classifier speaking its classify API. It
// returns only an alias; the routing engine resolves the alias to a
// gateway-owned backend, so credentials never reach the classifier.
type RemoteRouterClient struct {
	endpoint     string // e.g. "http://127.0.0.1:8080"
	timeout      time.Duration
	client       *http.Client
	healthClient *http.Client
}

const remoteRouterHealthTimeout = 2 * time.Second

// NewRemoteRouterClient creates the classifier for endpoint (timeoutMs <= 0
// means 100 ms).
func NewRemoteRouterClient(endpoint string, timeoutMs int) *RemoteRouterClient {
	timeout := time.Duration(timeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 100 * time.Millisecond
	}
	transport := &http.Transport{
		DialContext:         enterpriseEgressDialer{direct: &net.Dialer{}}.DialContext,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}
	checkRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &RemoteRouterClient{
		endpoint:     strings.TrimRight(endpoint, "/"),
		timeout:      timeout,
		client:       &http.Client{Timeout: timeout, CheckRedirect: checkRedirect, Transport: transport},
		healthClient: &http.Client{Timeout: remoteRouterHealthTimeout, CheckRedirect: checkRedirect, Transport: transport},
	}
}

type classifyRequest struct {
	Messages []classifyMessage `json:"messages"`
	Text     string            `json:"text,omitempty"`
	Options  *classifyOptions  `json:"options,omitempty"`
}

type classifyMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type classifyOptions struct {
	ReturnProbabilities bool `json:"return_probabilities,omitempty"`
}

type classifyResponse struct {
	RecommendedModel string                 `json:"recommended_model"`
	RoutingDecision  string                 `json:"routing_decision"`
	Classification   classifyClassification `json:"classification"`
}

type classifyClassification struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

// Name implements engine.Classifier.
func (c *RemoteRouterClient) Name() string { return engine.SourceVLLMSR }

func classifierErr(code string, err error) error {
	return &engine.ClassifierError{Code: code, Err: err}
}

// Classify implements engine.Classifier. Only the human text is sent.
func (c *RemoteRouterClient) Classify(ctx context.Context, in engine.ClassifyInput) (engine.ClassifyResult, error) {
	none := engine.ClassifyResult{Confidence: -1}
	if c == nil || c.endpoint == "" {
		return none, classifierErr(engine.FailureConfig, errors.New("no classifier endpoint"))
	}
	body, err := json.Marshal(classifyRequest{
		Messages: []classifyMessage{{Role: "user", Content: in.Text}},
		Options:  &classifyOptions{ReturnProbabilities: true},
	})
	if err != nil {
		return none, classifierErr(engine.FailureConfig, err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint+"/api/v1/classify/intent", bytes.NewReader(body))
	if err != nil {
		return none, classifierErr(engine.FailureConfig, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || reqCtx.Err() != nil {
			return none, classifierErr(engine.FailureTimeout, err)
		}
		return none, classifierErr(engine.FailureConfig, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		return none, classifierErr(engine.FailureUpstreamStatus, fmt.Errorf("classifier returned HTTP %d", resp.StatusCode))
	}
	var out classifyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&out); err != nil {
		return none, classifierErr(engine.FailureDecode, err)
	}
	alias := boundedRouterLabel(out.RecommendedModel, 128)
	if alias == "" {
		return none, classifierErr(engine.FailureDecode, errors.New("classifier returned no model"))
	}
	res := engine.ClassifyResult{
		Aliases:    []string{alias},
		Category:   boundedRouterLabel(out.Classification.Category, 64),
		RuleID:     boundedRouterLabel(out.RoutingDecision, 64),
		Confidence: -1,
	}
	if out.Classification.Confidence > 0 && out.Classification.Confidence <= 1 {
		res.Confidence = out.Classification.Confidence
	}
	return res, nil
}

func boundedRouterLabel(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || limit <= 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len()+len(string(r)) > limit {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

var _ engine.Classifier = (*RemoteRouterClient)(nil)

// Healthy checks if the SR service is reachable.
func (c *RemoteRouterClient) Healthy(ctx context.Context) bool {
	if c == nil || c.healthClient == nil {
		return false
	}
	reqCtx, cancel := context.WithTimeout(ctx, remoteRouterHealthTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.healthClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
