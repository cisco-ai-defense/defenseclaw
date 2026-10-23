// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package hookexec

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A Secure Client hook on macOS uses this managed TCP transport. A process
// holding its port must not see any bearer or event before it proves it is
// the administrator's gateway service. Linux runs this test for the same
// connected-socket ownership rule even though Secure Client is unavailable.
func TestManagedTCPClientRefusesAnUnverifiedListenerBeforeHTTPBytes(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		received.Add(1)
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	client, err := managedEnterpriseHTTPClient(time.Second, addr, "")
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/opencode/hook", bytes.NewBufferString(`{"tool_name":"Bash"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer fixture-token")
	response, err := client.Do(request)
	if response != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, errManagedGatewayPeerUnverified) {
		t.Errorf("unverified listener error = %v, want managed peer refusal", err)
	}
	if count := received.Load(); count != 0 {
		t.Errorf("unverified listener received %d requests", count)
	}
}
