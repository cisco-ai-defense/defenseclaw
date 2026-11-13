// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
)

func TestDecisionModelCallIsRecordedWithoutTokensOrCost(t *testing.T) {
	sink := judgeUsageSink{ch: make(chan modelusage.Record, 4)}
	engine := modelusage.NewEngine(sink)
	engine.Apply(config.TokenomicsConfig{Enabled: true}, config.PricingConfig{})
	processModelUsage.Store(engine)
	defer func() {
		processModelUsage.Store(nil)
		engine.Apply(config.TokenomicsConfig{}, config.PricingConfig{})
	}()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"answers":{"disposition":{"type":"choice","choice":"allow","probabilities":{"allow":0.9,"confirm":0.05,"block":0.05}}}}`)
	}))
	defer srv.Close()
	dm := newDecisionModel(&config.Config{DecisionModel: config.DecisionModelConfig{Enabled: true, Model: "dm-1", BaseURL: srv.URL}}, "")
	if dm == nil {
		t.Fatal("no decision model")
	}
	_, _, _ = dm.call(context.Background(), decisionModelState{})
	select {
	case rec := <-sink.ch:
		if rec.Facts.CallRole != modelusage.RoleDecisionModel || rec.Facts.SelectedModel != "dm-1" || rec.Status != 200 {
			t.Fatalf("%+v", rec)
		}
		if rec.Usage.Has != 0 || rec.Cost.USD != nil {
			t.Fatalf("the decision model reports no tokens and has no price: %+v %+v", rec.Usage, rec.Cost)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the decision model call was not recorded")
	}
}
