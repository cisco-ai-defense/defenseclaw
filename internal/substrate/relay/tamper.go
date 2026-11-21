// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// TamperReportPath is the actor listener route a relay reports a guard trip
// to (GAP-0120): the gateway writes a HIGH audit row, so the trip reaches
// the alert views and not only the relay's log.
const TamperReportPath = "/api/v1/substrate/relay/tamper"

// TamperReport is the body of a guard trip report.
type TamperReport struct {
	Connector string `json:"connector"`
	Reason    string `json:"reason"`
}

// reportTamper sends a guard trip with the task-end report's retries.
func reportTamper(ctx context.Context, send func(context.Context, string, string) error, connector, reason string) error {
	return ReportTaskEnd(ctx, func(ctx context.Context, _ TaskEnd) error { return send(ctx, connector, reason) }, TaskEnd{})
}

// GatewayTamper posts a guard trip to the gateway over the kit transport.
func GatewayTamper(t *kit.Transport) func(context.Context, string, string) error {
	return func(ctx context.Context, connector, reason string) error {
		body, _ := json.Marshal(TamperReport{Connector: connector, Reason: reason})
		resp, err := t.Post(ctx, kit.Request{Path: TamperReportPath, Body: body})
		switch {
		case err != nil:
			return err
		case resp.Status >= 200 && resp.Status < 300:
			return nil
		case resp.Status >= 500 || resp.Status == http.StatusTooManyRequests:
			return &reportLater{status: resp.Status, after: retryAfter(resp.RetryAfter)}
		}
		return fmt.Errorf("%w (status %d)", errReportRefused, resp.Status)
	}
}
