// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// substrate-1:GAP-0606 (review 3). The leader decoded a post with
// leader.Typed, which refuses unknown fields, so a Record field a newer
// callout or controller adds would turn every batch into a bad_request the
// poster drops while the two versions differ in an upgrade. Posts now ignore
// unknown fields; the records keep the fields this leader knows.
func TestGAP0606PostsIgnoreRecordFieldsANewerPosterAdds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	srv := &leader.Server{IsLeader: func() bool { return true }, Now: func() time.Time { return now }}
	s := &Store{}
	Serve(srv, s)
	for _, c := range []struct{ method, rec string }{
		{MethodPostEgress, `{"kind":"egress","atespace":"eng-web","actor":"job-1","host":"pypi.org","decision":"allow","added_in_1_0_11":{"x":1}}`},
		{MethodPostCounts, `{"kind":"count","metric":"idle_suspends","value":2,"added_in_1_0_11":"x"}`},
	} {
		body := `{"request_id":"req-gap0606-` + c.method + `","body":{"records":[` + c.rec + `],"batch_note":"newer"}}`
		req := httptest.NewRequest(http.MethodPost, leader.PathPrefix+c.method, strings.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s with a field this leader does not know: %d %s", c.method, rec.Code, rec.Body.String())
		}
	}
	out, _ := s.Take(context.Background(), TakeRequest{})
	var egress, count bool
	for _, r := range out.Records {
		egress = egress || (r.Kind == KindEgress && r.Host == "pypi.org")
		count = count || (r.Kind == KindCount && r.Metric == MetricIdleSuspends && r.Value == 2)
	}
	if len(out.Records) != 2 || !egress || !count {
		t.Fatalf("take = %+v, want the egress record and the count", out.Records)
	}
}
