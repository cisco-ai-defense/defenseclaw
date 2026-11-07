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
)

const enterpriseHookGuardianRemovedAuditPath = "/api/v1/managed/guardian-account-removed"

type enterpriseHookGuardianRemovedAuditReport struct {
	User      string `json:"user"`
	UID       *int   `json:"uid,omitempty"`
	Connector string `json:"connector"`
}

func reportEnterpriseHookGuardianRemoved(ctx context.Context, socket string, removed []enterpriseHookReconcileRow) {
	if socket == "" || len(removed) == 0 {
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
	for _, row := range removed {
		if !row.Removed {
			continue
		}
		report := enterpriseHookGuardianRemovedAuditReport{User: row.User, Connector: row.Connector}
		if row.UID > 0 {
			uid := row.UID
			report.UID = &uid
		}
		body, err := json.Marshal(report)
		if err != nil {
			continue
		}
		reportCtx, cancel := guardianAuditReportContext(ctx)
		request, err := http.NewRequestWithContext(reportCtx, http.MethodPost,
			"http://defenseclaw-hook"+enterpriseHookGuardianRemovedAuditPath, bytes.NewReader(body))
		if err != nil {
			cancel()
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
		response, err := client.Do(request)
		if err != nil {
			cancel()
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: report account removal for %s to audit: %v\n", row.Connector, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		cancel()
		if response.StatusCode != http.StatusNoContent {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: report account removal for %s to audit: HTTP %d\n", row.Connector, response.StatusCode)
		}
	}
}
