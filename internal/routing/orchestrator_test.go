// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"strings"
	"testing"
)

func TestValidateRemoteEndpointTransportPolicy(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  string
	}{
		{name: "IPv4 loopback HTTP", endpoint: "http://127.0.0.1:8080"},
		{name: "IPv4 loopback range HTTP", endpoint: "http://127.7.8.9:8080"},
		{name: "IPv6 loopback HTTP", endpoint: "http://[::1]:8080"},
		{name: "localhost HTTP", endpoint: "http://localhost:8080"},
		{name: "localhost trailing dot HTTP", endpoint: "http://localhost.:8080"},
		{name: "private IPv4 HTTPS", endpoint: "https://192.168.1.20:8080"},
		{name: "private IPv6 HTTPS", endpoint: "https://[fd00::20]:8080"},
		{name: "public HTTPS", endpoint: "https://router.example.test"},
		{name: "private IPv4 HTTP", endpoint: "http://192.168.1.20:8080", wantErr: "non-loopback endpoints must use https"},
		{name: "private IPv6 HTTP", endpoint: "http://[fd00::20]:8080", wantErr: "non-loopback endpoints must use https"},
		{name: "Docker host HTTP", endpoint: "http://host.docker.internal:8080", wantErr: "non-loopback endpoints must use https"},
		{name: "Docker gateway HTTP", endpoint: "http://gateway.docker.internal:8080", wantErr: "non-loopback endpoints must use https"},
		{name: "public HTTP", endpoint: "http://router.example.test", wantErr: "non-loopback endpoints must use https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemoteEndpoint(tt.endpoint)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRemoteEndpoint() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRemoteEndpoint() = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
