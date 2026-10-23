// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// #1202 (GAP-0713, GAP-0705): a keep-on-exit stop failure printed
// "Cancelled: grpc: the client connection is closing", and a delete after a
// gateway loss "wait for sandbox r5r deletion failed: ... grpc: the client
// connection is closing". Raw gRPC transport text is put in words; the
// recovery steps around it stay, and other reasons are left alone.
func TestGatewayTransportTextHidesRawGRPC(t *testing.T) {
	for _, raw := range []string{
		"Cancelled: grpc: the client connection is closing",
		"OpenShell: wait for sandbox r5r deletion failed: rpc error: code = Canceled desc = grpc: the client connection is closing",
		"rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing\"",
		"rpc error: code = Unavailable desc = error reading from server: EOF",
	} {
		if got := gatewayTransportText(raw); got != "the connection to the OpenShell gateway closed" {
			t.Fatalf("%q -> %q", raw, got)
		}
	}
	// The OpenShell CLI's chain when nothing listens on the gateway port: a
	// delete's work check printed it (#1202).
	for _, raw := range []string{
		"workspace: inspect the sandbox copy (exit 1): Error:   × transport error |   ├─▶ tcp connect error |   ├─▶ tcp connect error: Connection refused (os error 111)",
	} {
		if got := gatewayTransportText(raw); got != "the OpenShell gateway does not answer" {
			t.Fatalf("%q -> %q", raw, got)
		}
	}
	for _, plain := range []string{"sandbox r5r is not running", "the sandbox's MicroVM disk is full"} {
		if got := gatewayTransportText(plain); got != plain {
			t.Fatalf("%q changed to %q", plain, got)
		}
	}
	msg := (&sessionDeleteError{name: "r5r", err: errors.New("OpenShell: wait for sandbox r5r deletion failed: grpc: the client connection is closing")}).Error()
	if strings.Contains(msg, "grpc") || !strings.Contains(msg, "the connection to the OpenShell gateway closed") ||
		!strings.Contains(msg, "retry `defenseclaw sandbox delete r5r`") {
		t.Fatalf("delete failure = %q", msg)
	}
}

func TestManagedDeleteTransportErrorHasRecoveryText(t *testing.T) {
	err := &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "OpenShell: wait for sandbox r5r deletion failed",
		Detail: "Cancelled: grpc: the client connection is closing"}
	text, ok := managedErrorText(err, nil)
	if !ok || strings.Contains(text, "grpc") || !strings.Contains(text, "sandbox doctor") || !strings.Contains(text, "retry") {
		t.Fatalf("managed transport error = %q, %v", text, ok)
	}
}
