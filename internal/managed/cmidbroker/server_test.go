// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

type testProvider struct {
	mu          sync.Mutex
	token       string
	refreshErr  error
	invalidated int
}

func (provider *testProvider) Token(context.Context) (string, error) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.token, nil
}

func (provider *testProvider) Refresh(context.Context) error {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return provider.refreshErr
}

func (provider *testProvider) Invalidate() {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.invalidated++
}

func TestServerProcessesOnlyNarrowLifecycle(t *testing.T) {
	key := make([]byte, AuthKeyBytes)
	provider := &testProvider{token: "fixture-token"}
	server, err := NewServer(ServerConfig{
		PipeName:           `\\.\pipe\DefenseClawCMIDBroker`,
		BrokerServiceName:  "DefenseClawCMIDBroker",
		GatewayServiceName: "DefenseClawGateway",
	}, provider, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{OperationToken, OperationRefresh, OperationInvalidate} {
		request, err := NewRequest(operation)
		if err != nil {
			t.Fatal(err)
		}
		message, err := EncodeRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := server.processMessage(context.Background(), message)
		if err != nil {
			t.Fatalf("%s: %v", operation, err)
		}
		response, err := DecodeResponse(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyResponse(key, request, response); err != nil {
			t.Fatal(err)
		}
		if !response.OK || operation == OperationToken && response.Token != "fixture-token" {
			t.Fatalf("%s response = %#v", operation, response)
		}
	}
	if provider.invalidated != 1 {
		t.Fatalf("invalidate calls = %d", provider.invalidated)
	}
}

func TestServerRejectsReplayBeforeProviderOperation(t *testing.T) {
	key := make([]byte, AuthKeyBytes)
	provider := &testProvider{token: "fixture-token"}
	server, err := NewServer(ServerConfig{
		PipeName: `\\.\pipe\DefenseClawCMIDBroker`, BrokerServiceName: "DefenseClawCMIDBroker",
		GatewayServiceName: "DefenseClawGateway",
	}, provider, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewRequest(OperationInvalidate)
	message, _ := EncodeRequest(request)
	if _, err := server.processMessage(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if _, err := server.processMessage(context.Background(), message); !errors.Is(err, ErrProtocol) {
		t.Fatalf("replay error = %v", err)
	}
	if provider.invalidated != 1 {
		t.Fatalf("replayed operation reached provider %d times", provider.invalidated)
	}
}

func TestServerReturnsOnlySanitizedProviderCategory(t *testing.T) {
	key := make([]byte, AuthKeyBytes)
	provider := &testProvider{refreshErr: errors.New("native detail containing credential-shaped material")}
	server, err := NewServer(ServerConfig{
		PipeName: `\\.\pipe\DefenseClawCMIDBroker`, BrokerServiceName: "DefenseClawCMIDBroker",
		GatewayServiceName: "DefenseClawGateway",
	}, provider, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := NewRequest(OperationRefresh)
	message, _ := EncodeRequest(request)
	encoded, err := server.processMessage(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Error != "provider_refresh_failed" ||
		strings.Contains(response.Error, "native") {
		t.Fatalf("unsafe failure response = %#v", response)
	}
}
