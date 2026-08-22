// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cmidbroker

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func TestResponseMACBindsEveryField(t *testing.T) {
	key := make([]byte, AuthKeyBytes)
	for index := range key {
		key[index] = byte(index + 1)
	}
	request, err := NewRequest(OperationToken)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{
		Version: ProtocolVersion,
		OK:      true,
		Token:   "fixture-token",
		Nonce:   request.Nonce,
	}
	if err := SignResponse(key, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.MAC) != sha256.Size*2 {
		t.Fatalf("MAC length = %d", len(response.MAC))
	}
	if err := VerifyResponse(key, request, response); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	mutations := []func(*Response){
		func(value *Response) { value.Version++ },
		func(value *Response) { value.OK = false; value.Token = ""; value.Error = "provider_failed" },
		func(value *Response) { value.Nonce = strings.Repeat("a", 64) },
		func(value *Response) { value.Token = "other" },
	}
	for index, mutate := range mutations {
		changed := response
		mutate(&changed)
		if err := VerifyResponse(key, request, changed); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("mutation %d verification error = %v", index, err)
		}
	}
}

func TestProtocolRejectsUnknownAndExtraJSON(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	for _, message := range []string{
		`{"version":1,"op":"token","nonce":"` + nonce + `","unknown":true}`,
		`{"version":1,"op":"token","nonce":"` + nonce + `"}{}`,
		`{"version":1,"op":"ping","nonce":"` + nonce + `"}`,
		`{"version":1,"op":"token","nonce":"` + strings.Repeat("A", 64) + `"}`,
	} {
		if _, err := DecodeRequest([]byte(message)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("DecodeRequest(%q) error = %v", message, err)
		}
	}
}

func TestResponseBoundsAndShape(t *testing.T) {
	nonce := strings.Repeat("a", 64)
	cases := []Response{
		{Version: 1, OK: true, Token: strings.Repeat("x", MaxTokenBytes+1), Nonce: nonce},
		{Version: 1, OK: true, Error: "unexpected", Nonce: nonce},
		{Version: 1, OK: false, Nonce: nonce},
		{Version: 1, OK: false, Token: "secret", Error: "failed", Nonce: nonce},
	}
	key := make([]byte, AuthKeyBytes)
	for index, response := range cases {
		if err := SignResponse(key, &response); !errors.Is(err, ErrProtocol) {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestConfigFromEnvironmentAllOrNone(t *testing.T) {
	values := map[string]string{}
	lookup := func(name string) string { return values[name] }
	if _, enabled, err := ConfigFromEnvironment(lookup); enabled || err != nil {
		t.Fatalf("empty configuration = enabled:%v error:%v", enabled, err)
	}
	values[PipeEnv] = `\\.\pipe\DefenseClawCMIDBroker`
	if _, enabled, err := ConfigFromEnvironment(lookup); !enabled || !errors.Is(err, ErrIncompleteConfiguration) {
		t.Fatalf("partial configuration = enabled:%v error:%v", enabled, err)
	}
	values[BrokerServiceEnv] = "DefenseClawCMIDBroker"
	values[AuthKeyEnv] = `C:\ProgramData\Cisco\broker-auth.key`
	values[GatewayServiceEnv] = "DefenseClawGateway"
	cfg, enabled, err := ConfigFromEnvironment(lookup)
	if err != nil || !enabled || cfg.GatewayServiceName != "DefenseClawGateway" {
		t.Fatalf("complete configuration = %#v enabled:%v error:%v", cfg, enabled, err)
	}
}
