// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GAP-0414: through the gateway's attach route every request carries a new
// session token (a new jti) for the same person. A long-poll attachment must
// take the reads and writes that follow its open; before the fix every one
// was 404 and the launcher reopened until the per-person cap answered 429,
// which it showed as "The cluster is full".
func TestGAP0414LongPollTakesFreshTokensOfTheSamePerson(t *testing.T) {
	needLinux(t)
	s, _, ec := testServer(t, []string{"sh", "-c", `while read l; do echo "lp:$l"; done`})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	fresh := func() string { return ec.token(t, claims(time.Now(), nil), TokenType) }
	do := func(method, path string, body []byte) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+fresh())
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := do("POST", "/dcrelay/1/poll?cols=80&rows=24", nil)
	var open struct{ ID string }
	_ = json.NewDecoder(resp.Body).Decode(&open)
	resp.Body.Close()
	if open.ID == "" {
		t.Fatalf("open %d", resp.StatusCode)
	}
	in := AppendStream(nil, Encode(FrameData, []byte("hello\r")))
	if r := do("POST", "/dcrelay/1/poll/"+open.ID, in); r.StatusCode != http.StatusNoContent {
		t.Fatalf("write with the next request's token: %d (the attachment is bound to the token that opened it)", r.StatusCode)
	}
	cursor := "0"
	var screen strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(screen.String(), "lp:hello") {
		r := do("GET", "/dcrelay/1/poll/"+open.ID+"?cursor="+cursor, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("read with a fresh token: %d", r.StatusCode)
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(r.Body)
		r.Body.Close()
		cursor = r.Header.Get("X-Dcrelay-Cursor")
		frames, err := SplitStream(b.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range frames {
			if ft, p, _ := Decode(f); ft == FrameData {
				screen.Write(p)
			}
		}
	}
	if !strings.Contains(screen.String(), "lp:hello") {
		t.Fatalf("screen %q", screen.String())
	}
	// Still bound to the person: another person's token sees nothing.
	other := ec.token(t, claims(time.Now(), func(c map[string]any) { c["sub"] = "bob@example.test" }), TokenType)
	req, _ := http.NewRequest("GET", srv.URL+"/dcrelay/1/poll/"+open.ID+"?cursor=0", nil)
	req.Header.Set("Authorization", "Bearer "+other)
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("another person's read: %d", r.StatusCode)
	}
	if r := do("DELETE", "/dcrelay/1/poll/"+open.ID, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("delete %d", r.StatusCode)
	}
}
