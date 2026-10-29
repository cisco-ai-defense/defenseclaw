// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// managedWindowsGatewayProvenance reads the provenance of the running
// managed standalone gateway on Windows from its administrator /status, with
// the gateway token only an administrator can read and a listener check of
// the protected service, the route enterprise windows status uses. A
// short-lived CLI has no applied config of its own, so provenance show printed
// generation 0 on managed Windows while status reported the advancing
// config generation (GAP-0391). Off a managed standalone host it reports
// present false and the caller keeps its other paths.
func managedWindowsGatewayProvenance(ctx context.Context) (version.Provenance, bool, error) {
	base, token, present, err := managedScanGatewayEndpoint()
	if !present {
		return version.Provenance{}, false, nil
	}
	const next = "defenseclaw-gateway enterprise windows status"
	if err != nil {
		if err.Error() == managedScanAdministratorOnly {
			return version.Provenance{}, true, errors.New("the managed gateway's provenance needs administrator access; run defenseclaw-gateway provenance show from an elevated Administrator prompt, or ask your administrator to run it")
		}
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed gateway's provenance: %w; check it with: %s", err, next)
	}
	client, err := managedGatewayClientFactory(5*time.Second, strings.TrimPrefix(base, "http://"), managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed gateway's provenance: %w; check it with: %s", err, next)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/status", nil)
	if err != nil {
		return version.Provenance{}, true, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed gateway's provenance: %w; check it with: %s", err, next)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed gateway's provenance: gateway status returned HTTP %d; check it with: %s", resp.StatusCode, next)
	}
	var answer struct {
		Provenance *version.Provenance `json:"provenance"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&answer); err != nil {
		return version.Provenance{}, true, fmt.Errorf("cannot read the managed gateway's provenance: %w; check it with: %s", err, next)
	}
	if err := validManagedProvenance(answer.Provenance, next); err != nil {
		return version.Provenance{}, true, err
	}
	return *answer.Provenance, true, nil
}
