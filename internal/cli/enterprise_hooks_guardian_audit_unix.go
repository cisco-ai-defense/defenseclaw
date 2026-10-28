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
}

var guardianAuditClientFactory = hookexec.NewManagedStandaloneHookSocketHTTPClient

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
		request, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"http://defenseclaw-hook"+enterpriseHookGuardianRepairAuditPath, bytes.NewReader(body))
		if err != nil {
			continue
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "hook-guardian")
		response, err := client.Do(request)
		if err != nil {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: report hook repair for %s to audit: %v\n", repair.Connector, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			fmt.Fprintf(enterpriseHookWorkerLog, "[hook-guardian] warn: report hook repair for %s to audit: HTTP %d\n", repair.Connector, response.StatusCode)
		}
	}
}
