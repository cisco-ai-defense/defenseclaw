// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

const gap1133PeerClientEnv = "DC_GAP1133_PEER_CLIENT"

// rel-1-0-10:GAP-1133, native Windows: the OSS route-only peer lookup names
// the token user SID of the client process of a real loopback connection
// (another process of this account), and refuses a connection it cannot
// prove (here: the gateway process itself as the client).
func TestRouteOSSPeerSIDNamesThisAccountsClientProcess(t *testing.T) {
	if os.Getenv(gap1133PeerClientEnv) != "" {
		t.Skip("helper process")
	}
	want, err := peercred.CurrentProcessSID()
	if err != nil {
		t.Fatal(err)
	}
	type answer struct {
		sid string
		err error
	}
	answers := make(chan answer, 4)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sid, err := routeOSSPeerSID(r)
		answers <- answer{sid, err}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^TestGAP1133PeerClientHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), gap1133PeerClientEnv+"="+ln.Addr().String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("client process: %v\n%s", err, out)
	}
	select {
	case a := <-answers:
		if a.err != nil {
			t.Fatalf("this account's client process was not identified: %v", a.err)
		}
		if !strings.EqualFold(a.sid, want) {
			t.Fatalf("peer SID = %s, want this account %s", a.sid, want)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("no request from the client process")
	}

	// The gateway process itself is never an answer: fail closed.
	resp, err := http.Get("http://" + ln.Addr().String() + "/r/claudecode/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if a := <-answers; a.err == nil {
		t.Fatalf("an in-process client was identified as %s; the lookup must refuse it", a.sid)
	}
}

// TestGAP1133PeerClientHelper is the client process of the test above.
func TestGAP1133PeerClientHelper(t *testing.T) {
	addr := os.Getenv(gap1133PeerClientEnv)
	if addr == "" {
		t.Skip("helper process only")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get("http://" + addr + "/r/claudecode/v1/messages")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}
