// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// The accepted POST's own 103 keeps its body available for the committed
// watchdog decision, even after the compatibility window.
func TestGAP0370Post103CarriesReceiptAfterCompatibilityWindow(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, delivery := prepareHookDeliveryRequest(req, []byte("call"), 10*time.Millisecond, nil, true)
	defer delivery.close()
	if _, err := io.ReadFull(req.Body, make([]byte, len("call"))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	close(delivery.ready)
	wrote := make(chan bool, 1)
	go func() { wrote <- delivery.deadline(true) }()
	line := make([]byte, len(HookDeliveryReceiptLate))
	if _, err := io.ReadFull(req.Body, line); err != nil || string(line) != HookDeliveryReceiptLate {
		t.Fatalf("accepted POST receipt = %q, %v", line, err)
	}
	if !<-wrote {
		t.Fatal("the accepted POST lost its deadline receipt")
	}
}

// The accepted legacy POST's 100 ends the body promptly so its ordinary
// response can arrive before the answer deadline.
func TestGAP0370LegacyReadSignalReleasesBody(t *testing.T) {
	req, err := http.NewRequest(http.MethodPost, "http://localhost/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, delivery := prepareHookDeliveryRequest(req, []byte("call"), time.Second, nil, true)
	defer delivery.close()
	if _, err := io.ReadFull(req.Body, make([]byte, len("call"))); err != nil {
		t.Fatal(err)
	}
	close(delivery.reading)
	line := make([]byte, len(HookDeliveryReleased))
	if _, err := io.ReadFull(req.Body, line); err != nil || string(line) != HookDeliveryReleased {
		t.Fatalf("legacy POST body end = %q, %v", line, err)
	}
}

// A request that ends before either POST signal cannot hold its body open.
func TestGAP0370CanceledPostEndsUnadvertisedBody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/hook", nil)
	if err != nil {
		t.Fatal(err)
	}
	req, delivery := prepareHookDeliveryRequest(req, []byte("call"), time.Second, nil, true)
	defer delivery.close()
	if _, err := io.ReadFull(req.Body, make([]byte, len("call"))); err != nil {
		t.Fatal(err)
	}
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, req.Body)
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled POST body stayed open")
	}
}
