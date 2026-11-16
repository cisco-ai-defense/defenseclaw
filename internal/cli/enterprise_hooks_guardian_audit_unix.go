//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const enterpriseHookGuardianRepairAuditPath = "/api/v1/managed/guardian-repair"

// The HTTP report includes the account uid. The lifecycle repair record has
// its own stable user/connector shape and is not sent to the gateway.
type enterpriseHookGuardianAuditReport struct {
	User      string `json:"user"`
	UID       int    `json:"uid"`
	Connector string `json:"connector"`
	// Element names the protected element the guardian put back; empty for
	// a repair of a target as a whole.
	Element string `json:"element,omitempty"`
	// Change says what happened to the element (deleted, appended or edited);
	// empty where the guardian could not read it.
	Change string `json:"change,omitempty"`
}

var guardianAuditClientFactory = hookexec.NewManagedStandaloneHookSocketHTTPClient

// guardianAuditReportTimeout bounds one audit report to the gateway.
const guardianAuditReportTimeout = 5 * time.Second

// guardianAuditReportContext is the context of one audit report. The report
// says what the guardian already put back, so a later watch event that cancels
// the pass must not drop it (the next pass sees matching files and cannot
// rebuild the row); the report keeps the pass values and has its own bound
// (GAP-0754).
func guardianAuditReportContext(pass context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(pass), guardianAuditReportTimeout)
}

func reportEnterpriseHookGuardianRepairs(ctx context.Context, socket string, repaired []enterpriseHookGuardianAuditReport) {
	if socket == "" || len(repaired) == 0 {
		return
	}
	trustedSocket, serviceUID, err := enterpriseHookStandaloneHookTransport()
	if err != nil || trustedSocket != socket {
		return
	}
	client, err := guardianAuditClientFactory(2*time.Second, socket, serviceUID)
	if err != nil {
		return
	}
	if transport, ok := client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	for _, repair := range repaired {
		body, err := json.Marshal(repair)
		if err != nil {
			continue
		}
		reportCtx, cancel := guardianAuditReportContext(ctx)
		request, err := http.NewRequestWithContext(reportCtx, http.MethodPost,
			"http://defenseclaw-hook"+enterpriseHookGuardianRepairAuditPath, bytes.NewReader(body))
		if err != nil {
			cancel()
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
		response, err := client.Do(request)
		if err != nil {
			cancel()
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: report hook repair for %s to audit: %v\n", firstNonEmpty(repair.Element, repair.Connector), err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		cancel()
		if response.StatusCode != http.StatusNoContent {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: report hook repair for %s to audit: HTTP %d\n", firstNonEmpty(repair.Element, repair.Connector), response.StatusCode)
		}
	}
}
