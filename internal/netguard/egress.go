// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

// EgressProxy is an administrator's outbound proxy for a managed deployment
// (config enterprise.network). The zero value means "no enterprise proxy":
// outbound clients keep the process-environment proxy behavior they had
// before.
type EgressProxy struct {
	// HTTPSProxy is the proxy URL (http or https scheme, host[:port], no
	// credentials, path, query or fragment).
	HTTPSProxy string
	// NoProxy is a NO_PROXY-style list of hosts, domains and CIDRs that
	// connect directly.
	NoProxy string
}

// ParseEgressProxyURL validates an enterprise.network.https_proxy value.
// Credentials are refused because the managed config is readable by every
// user on the device; an authenticating proxy must accept the device's
// identity by other means (for example IP allowlisting or Kerberos).
func ParseEgressProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("proxy URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy URL is malformed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("proxy URL scheme %q must be http or https", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("proxy URL has no host")
	}
	if u.User != nil {
		return nil, errors.New("proxy URL must not carry credentials")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("proxy URL must be scheme://host[:port] only")
	}
	return u, nil
}

// ProxyFunc returns the proxy selector for outbound requests: the
// administrator's proxy with its NO_PROXY exclusions when one is configured,
// otherwise http.ProxyFromEnvironment. Loopback destinations always connect
// directly.
func (p EgressProxy) ProxyFunc() (func(*http.Request) (*url.URL, error), error) {
	if strings.TrimSpace(p.HTTPSProxy) == "" {
		return http.ProxyFromEnvironment, nil
	}
	proxyURL, err := ParseEgressProxyURL(p.HTTPSProxy)
	if err != nil {
		return nil, err
	}
	selector := (&httpproxy.Config{
		HTTPProxy:  proxyURL.String(),
		HTTPSProxy: proxyURL.String(),
		NoProxy:    strings.TrimSpace(p.NoProxy),
	}).ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return selector(req.URL)
	}, nil
}

// Environment returns the proxy variables that send environment-driven
// outbound clients (http.ProxyFromEnvironment, gRPC dialers) through the
// administrator's proxy: HTTPS_PROXY/https_proxy when a proxy is set and
// NO_PROXY/no_proxy when exclusions are set. The zero value returns none.
func (p EgressProxy) Environment() map[string]string {
	env := map[string]string{}
	if proxy := strings.TrimSpace(p.HTTPSProxy); proxy != "" {
		env["HTTPS_PROXY"] = proxy
		env["https_proxy"] = proxy
	}
	if noProxy := strings.TrimSpace(p.NoProxy); noProxy != "" {
		env["NO_PROXY"] = noProxy
		env["no_proxy"] = noProxy
	}
	return env
}

// Transport returns a clone of http.DefaultTransport that selects the proxy
// with ProxyFunc, for outbound clients that otherwise use the default
// transport.
func (p EgressProxy) Transport() (*http.Transport, error) {
	proxy, err := p.ProxyFunc()
	if err != nil {
		return nil, err
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport is not an *http.Transport")
	}
	transport := base.Clone()
	transport.Proxy = proxy
	return transport, nil
}
