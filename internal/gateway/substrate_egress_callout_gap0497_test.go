// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0497 (J32 doctor-explains, actors-with-other): with another callout in
// Substrate's egress slot the launcher's doctor and status said "ready for
// agents", because /info had nothing about the callout. At base /info has no
// egress_callout member. Now it names the state class, the fail mode and the
// checks that are off, never the other callout (no sign-in); the
// administrators' doctor row names it.
func TestSubstrateEgressCalloutInfoGAP0497(t *testing.T) {
	cs := controller.CalloutStatus{Known: true, Holder: "default/other-callout:9443", FailMode: controller.CalloutFailClosed,
		Since: time.Date(2026, 11, 17, 19, 31, 0, 0, time.UTC)}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Info = map[string]any{"sign_in": "oidc"}
		c.EgressCallout = func(context.Context) (controller.CalloutStatus, bool) { return cs, true }
	})
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", "")
	var info struct {
		EgressCallout *SubstrateEgressCallout `json:"egress_callout"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil || rec.Code != 200 || info.EgressCallout == nil {
		t.Fatalf("info %d %s", rec.Code, rec.Body)
	}
	e := info.EgressCallout
	if e.State != EgressCalloutOther || e.FailMode != controller.CalloutFailClosed || e.Since != "2026-11-17T19:31:00Z" ||
		strings.Join(e.ChecksOff, ",") != strings.Join(controller.CalloutChecks, ",") {
		t.Fatalf("egress_callout = %+v", e)
	}
	for _, want := range []string{"ask hosts", "URL rules", "secret and DLP scans", "body and MCP inspection"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("/info does not say %q is off: %s", want, rec.Body)
		}
	}
	if strings.Contains(rec.Body.String(), "other-callout") {
		t.Fatalf("/info names the other callout without a sign-in: %s", rec.Body)
	}

	// The administrators' row names what holds the slot and how to fix it.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/doctor", "p-admin", "")
	var doc struct {
		Checks []SubstrateCheck `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil || rec.Code != 200 {
		t.Fatalf("doctor %d %s", rec.Code, rec.Body)
	}
	var row *SubstrateCheck
	for i := range doc.Checks {
		if doc.Checks[i].ID == "substrate.egress_callout" {
			row = &doc.Checks[i]
		}
	}
	if row == nil || row.Status != "fail" || !strings.Contains(row.Detail, "default/other-callout:9443") ||
		!strings.Contains(row.Detail, "fail closed") || !strings.Contains(row.Fix, "ate-setup deploy") {
		t.Fatalf("doctor row %+v", row)
	}

	// Ours: the class only, nothing off; unknown says so.
	cs = controller.CalloutStatus{Known: true, Ours: true, Holder: "defenseclaw-system/defenseclaw-callout:9443", FailMode: controller.CalloutFailClosed}
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", "")
	if !strings.Contains(rec.Body.String(), `"egress_callout":{"state":"defenseclaw","fail_mode":"closed"}`) {
		t.Fatalf("ours: %s", rec.Body)
	}
	if m := SubstrateEgressCalloutOf(controller.CalloutStatus{Err: "forbidden"}); m.State != EgressCalloutUnknown || len(m.ChecksOff) != 0 {
		t.Fatalf("unknown: %+v", m)
	}
	if m := SubstrateEgressCalloutOf(controller.CalloutStatus{Known: true}); m.State != EgressCalloutNone || len(m.ChecksOff) == 0 {
		t.Fatalf("none: %+v", m)
	}
}
