// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestManagedHookAdvertisesReceiptWhileWaitingForCallerRunSlot(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	f.api.hookCallerLimits.running = 1
	const path = "/api/v1/claude-code/hook"
	_, releaseFirst := f.api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil), "same-uid", path)
	if releaseFirst == nil {
		t.Fatal("first hook did not acquire the caller run slot")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, release := f.api.admitHookCaller(w, r, "same-uid", path)
		if release != nil {
			defer release()
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer func() {
		if releaseFirst != nil {
			releaseFirst()
		}
		server.Close()
	}()

	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(hookexec.HookDeliveryReceiptHeader, "1")
	req.Header.Set(hookexec.HookDeliveryPayloadBytesHeader, "2")
	advertised := make(chan struct{}, 1)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			if code == http.StatusEarlyHints {
				advertised <- struct{}{}
			}
			return nil
		},
	}))
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, _ := server.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
	}()
	if _, err := io.WriteString(writer, "{}"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-advertised:
	case <-ctx.Done():
		t.Fatal("receipt capability was not advertised before the caller run slot became free")
	}
	releaseFirst()
	releaseFirst = nil
	_ = writer.Close()
	cancel()
	<-done
}
