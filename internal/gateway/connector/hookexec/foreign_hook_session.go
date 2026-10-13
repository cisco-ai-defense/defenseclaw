// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const foreignHookSessionPathPrefix = "/api/v1/foreign-hook-session/"

// ExchangeForeignHookSession asks the standalone gateway to apply one scan to
// its protected session record. An unavailable or malformed answer is an
// error; the caller must deny the hook invocation in that case.
func ExchangeForeignHookSession(ctx context.Context, opts Options, connector string, payload []byte) ([]byte, error) {
	if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" {
		return nil, errors.New("managed hook runtime unavailable")
	}
	remaining, ok := ctx.Deadline()
	timeout := defaultHookRequestTimeout
	if ok {
		timeout = time.Until(remaining)
		if timeout <= 0 {
			return nil, context.DeadlineExceeded
		}
	}
	client := opts.HTTPClient
	if client == nil {
		var err error
		if opts.ManagedStandalone {
			client, err = managedStandaloneHTTPClient(timeout, opts.ManagedUnixSocket, opts.ManagedServiceUID)
		} else {
			client, err = managedEnterpriseHTTPClient(timeout, opts.APIAddr, opts.ManagedGatewayServiceName)
		}
		if err != nil {
			return nil, err
		}
	}
	token := ""
	if !opts.ManagedStandalone {
		if opts.AuthenticatedManagedToken == nil {
			return nil, errors.New("authenticated managed hook token unavailable")
		}
		token = strings.TrimSpace(*opts.AuthenticatedManagedToken)
		if token == "" {
			return nil, errors.New("authenticated managed hook token empty")
		}
	}
	addr := opts.APIAddr
	if opts.ManagedStandalone && addr == "" {
		addr = "127.0.0.1:1" // the Unix transport dials the socket
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+addr+foreignHookSessionPathPrefix+url.PathEscape(connector), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	setUserIdentityHeaders(req, opts)
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session gateway returned HTTP %d", response.StatusCode)
	}
	return io.ReadAll(io.LimitReader(response.Body, 64<<10))
}
