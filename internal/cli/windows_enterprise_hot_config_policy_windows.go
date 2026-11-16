// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Read the gateway's live policy without executing the installed CLI. The
// token comes from protected managed host state. The gateway service must own
// the connected socket before the token is sent and before its answer counts:
// a listener check before the dial could pass while the service releases the
// port to another account (GAP-0962 class).
var windowsEnterpriseHotConfigGatewayPolicy = func(ctx context.Context, layout managed.StandaloneLayout) (gateway.PolicyHealth, error) {
	base, token, managedHost, err := managedScanGatewayEndpoint()
	if err != nil || !managedHost || token == "" {
		return gateway.PolicyHealth{}, errors.New("cannot read the managed gateway endpoint and token")
	}
	expectedBase, err := managedWindowsGatewayBase(layout)
	if err != nil || base != expectedBase {
		return gateway.PolicyHealth{}, errors.New("the managed gateway endpoint does not match the installed config")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.User != nil || parsed.Path != "" {
		return gateway.PolicyHealth{}, errors.New("the managed gateway endpoint is not loopback HTTP")
	}
	client, err := managedGatewayClientFactory(2*time.Second, parsed.Host, managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return gateway.PolicyHealth{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/health", nil)
	if err != nil {
		return gateway.PolicyHealth{}, err
	}
	req.Header.Set("X-DefenseClaw-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return gateway.PolicyHealth{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gateway.PolicyHealth{}, fmt.Errorf("gateway health returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return gateway.PolicyHealth{}, err
	}
	if len(body) > 1<<20 {
		return gateway.PolicyHealth{}, errors.New("gateway health response is too large")
	}
	var health struct {
		Policy *gateway.PolicyHealth `json:"policy"`
	}
	if err := json.Unmarshal(body, &health); err != nil || health.Policy == nil {
		return gateway.PolicyHealth{}, errors.New("gateway health did not report its policy")
	}
	return *health.Policy, nil
}

func windowsEnterpriseHotConfigPriorPolicyLive(ctx context.Context, layout managed.StandaloneLayout, prior policyDigestReport) bool {
	health, err := windowsEnterpriseHotConfigGatewayPolicy(ctx, layout)
	return err == nil && prior.Digest != "" && health.EffectiveDigest == prior.Digest &&
		health.BundleID == prior.GatewayReportedBundleID && health.BundleVersion == prior.GatewayReportedBundleVersion
}

func windowsEnterpriseHotConfigWaitForPriorPolicy(ctx context.Context, layout managed.StandaloneLayout, prior policyDigestReport, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if windowsEnterpriseHotConfigPriorPolicyLive(ctx, layout, prior) {
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(windowsEnterpriseHotConfigPoll):
		}
	}
}
