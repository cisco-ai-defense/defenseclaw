// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mcpasuser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// W2B-G-enum review loop 3: a refresh that could not publish one user's
// Claude Code record answered as a failed refresh, so the gateway refused
// every MCP tool call of every user and connector, Kiro calls whose records
// were published included. The answer now names what it did not publish,
// and only those calls are refused.
func TestIncompleteRefreshNamesOnlyTheRecordsItDidNotPublish(t *testing.T) {
	const alice, bob = `C:\Users\alice`, `C:\Users\bob`
	refresh := func(context.Context) error {
		return &RefreshIncomplete{
			Records: []RefreshRecord{{Connector: "claudecode", SID: "S-1-5-21-1-1001", Home: alice}},
			Detail:  "publish Claude Code MCP servers: S-1-5-21-1-1001.json not updated: there is not enough space on the disk",
		}
	}
	gatewayConn, serverConn := net.Pipe()
	served := make(chan error, 1)
	go func() {
		_, err := ServeConn(context.Background(), serverConn, refresh, nil, time.Minute)
		_ = serverConn.Close()
		served <- err
	}()
	err := RequestRefresh(gatewayConn, "DefenseClawGateway")
	_ = gatewayConn.Close()
	if serveErr := <-served; serveErr == nil {
		t.Fatal("the enumerator side reported a complete refresh")
	}
	var incomplete *RefreshIncomplete
	if !errors.As(err, &incomplete) {
		t.Fatalf("RequestRefresh = %T %v, want *RefreshIncomplete", err, err)
	}
	for _, tc := range []struct {
		connector, home string
		refused         bool
	}{
		{"claudecode", alice, true},
		{"claudecode", alice + `\`, true},
		{"claudecode", `c:\users\ALICE`, true},
		{"claudecode", bob, false},
		{"kiro", alice, false},
		{"kiro", bob, false},
		{"claudecode", "", true}, // a caller whose home is not known
		{"kiro", "", false},
	} {
		if got := incomplete.Refuses(tc.connector, tc.home); got != tc.refused {
			t.Errorf("Refuses(%s, %q) = %v, want %v", tc.connector, tc.home, got, tc.refused)
		}
	}

	// A connector whose folder could not be written refuses all its calls,
	// and a record that names no home refuses every call of its connector.
	whole := &RefreshIncomplete{Connectors: []string{"kiro"}, Records: []RefreshRecord{{Connector: "claudecode", SID: "S-1-5-21-1-1002"}}}
	if !whole.Refuses("kiro", bob) || !whole.Refuses("claudecode", bob) {
		t.Fatal("a failed folder or a record without a home must refuse every call of its connector")
	}
	var none *RefreshIncomplete
	if none.Refuses("claudecode", alice) {
		t.Fatal("a nil incomplete refresh refused")
	}
	if !(&RefreshIncomplete{Detail: "something failed"}).Refuses("kiro", bob) {
		t.Fatal("an incomplete refresh that names nothing must refuse every call")
	}

	// Past the record bound the answer names the connectors instead, so it
	// fits a frame and still refuses every call it cannot confirm.
	many := &RefreshIncomplete{}
	for i := 0; i <= maxRefreshRecords; i++ {
		many.Records = append(many.Records, RefreshRecord{Connector: "claudecode", SID: fmt.Sprintf("S-1-5-21-1-%d", 2000+i), Home: fmt.Sprintf(`C:\Users\u%d`, i)})
	}
	bounded := many.bounded()
	if len(bounded.Records) != 0 || !bounded.Refuses("claudecode", bob) || bounded.Refuses("kiro", bob) {
		t.Fatalf("bounded = %+v, want every claudecode call refused and no kiro call", bounded)
	}
}

// A plain refusal, as an enumerator before this change sends, stays a
// refusal of every call, and the answer of an incomplete refresh is not OK,
// so a gateway before this change refuses every call: closed both ways.
func TestIncompleteRefreshIsRefusedByAGatewayThatDoesNotKnowIt(t *testing.T) {
	gatewayConn, serverConn := net.Pipe()
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, func(context.Context) error { return errors.New("manifest unreadable") }, nil, time.Minute)
		_ = serverConn.Close()
	}()
	err := RequestRefresh(gatewayConn, "DefenseClawGateway")
	_ = gatewayConn.Close()
	var incomplete *RefreshIncomplete
	var refused *RefusedError
	if errors.As(err, &incomplete) || !errors.As(err, &refused) {
		t.Fatalf("plain failure = %T %v, want a refusal", err, err)
	}

	gateway2, server2 := net.Pipe()
	go func() {
		_, _ = ServeConn(context.Background(), server2, func(context.Context) error {
			return &RefreshIncomplete{Records: []RefreshRecord{{Connector: "claudecode", SID: "S-1-5-21-1-1001", Home: `C:\Users\alice`}}}
		}, nil, time.Minute)
		_ = server2.Close()
	}()
	if err := writeJSONFrame(gateway2, FrameRefresh, RefreshRequest{Version: ProtocolVersion, GatewayService: "DefenseClawGateway"}); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := ReadFrame(gateway2)
	_ = gateway2.Close()
	if err != nil || kind != FrameAnswer {
		t.Fatalf("answer %q, %v", kind, err)
	}
	var answer struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(payload, &answer); err != nil || answer.OK {
		t.Fatalf("answer %s: an older gateway would read it as published", payload)
	}
}
