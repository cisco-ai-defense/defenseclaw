// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"testing"
	"time"
)

// A prompt capability signal already identifies the accepted request. It
// must not add a separate health request to every ordinary tool call.
func TestGAP0370PromptCapabilitySkipsPeerProbe(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	probed := make(chan struct{}, 1)
	payload := []byte("tool call")
	req, delivery := prepareHookDeliveryRequest(req, payload, time.Second, nil,
		func(context.Context, net.Conn) bool {
			probed <- struct{}{}
			return true
		})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	delivery.setConnection(client)
	defer delivery.close()
	close(delivery.ready)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(req.Body, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("request body = %q, want %q", got, payload)
	}
	<-delivery.payloadDone
	select {
	case <-probed:
		t.Fatal("promptly advertised receipt started an unnecessary peer check")
	case <-time.After(hookDeliveryCapabilityWait):
	}
}

// Peer verification has its own HTTP trace, but remains bounded by the
// accepted request's lifetime.
func TestGAP0370PeerProbeSeparatesTraceAndFollowsRequestCancel(t *testing.T) {
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://localhost/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	probeContext := make(chan context.Context, 1)
	req, delivery := prepareHookDeliveryRequest(req, []byte("call"), time.Second, nil,
		func(ctx context.Context, _ net.Conn) bool {
			probeContext <- ctx
			<-ctx.Done()
			return false
		})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	delivery.setConnection(client)
	defer delivery.close()
	if _, err := io.ReadFull(req.Body, make([]byte, len("call"))); err != nil {
		t.Fatal(err)
	}
	select {
	case ctx := <-probeContext:
		if httptrace.ContextClientTrace(ctx) != nil {
			t.Fatal("peer probe inherited the POST's capability trace")
		}
		cancelRequest()
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("peer probe remained active after the request ended")
		}
	case <-time.After(time.Second):
		t.Fatal("peer probe did not start during the compatibility window")
	}
}
