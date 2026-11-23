// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// hookGuardianRouteOnlyProofFile records, per target, the RouteOnlyProof of
// the Windows route-only render the guardian read back exact as the account
// in the pass that wrote the guardian state with the same updated_at
// (GAP-1975). Setup readiness runs as an elevated administrator, which
// cannot read those account-only files, and compares it instead. It is its
// own file because the guardian state and authorization keep the schema a
// prior binary reads strictly (1.0.9 and earlier have no route_only).
const hookGuardianRouteOnlyProofFile = "hook_guardian_route_only.json"

type enterpriseHookRouteOnlyProof struct {
	SID       string `json:"sid"`
	Connector string `json:"connector"`
	Proof     string `json:"proof"`
}

type enterpriseHookRouteOnlyProofRecord struct {
	Version        int                            `json:"version"`
	StateUpdatedAt string                         `json:"state_updated_at"`
	Targets        []enterpriseHookRouteOnlyProof `json:"targets"`
}

// takeEnterpriseHookRouteOnlyProofs returns rows with every route-only proof
// moved out of their results (copied, the caller's rows are unchanged) and
// the proofs of the protected rows, for hookGuardianRouteOnlyProofFile.
func takeEnterpriseHookRouteOnlyProofs(rows []enterpriseHookReconcileRow) ([]enterpriseHookReconcileRow, []enterpriseHookRouteOnlyProof) {
	out := append([]enterpriseHookReconcileRow(nil), rows...)
	var proofs []enterpriseHookRouteOnlyProof
	for i, row := range out {
		if row.Result == nil || row.Result.RouteOnly == "" || row.Result.RouteOnly == enterprisehooks.RouteOnlyUnverified {
			continue
		}
		result := *row.Result
		proof := result.RouteOnly
		result.RouteOnly = ""
		out[i].Result = &result
		if row.OK && !row.Pending && enterpriseHookProtectedTargetKey(row) != "" {
			proofs = append(proofs, enterpriseHookRouteOnlyProof{SID: row.SID, Connector: row.Connector, Proof: proof})
		}
	}
	sort.Slice(proofs, func(i, j int) bool {
		if proofs[i].SID != proofs[j].SID {
			return proofs[i].SID < proofs[j].SID
		}
		return proofs[i].Connector < proofs[j].Connector
	})
	return out, proofs
}

// writeEnterpriseHookRouteOnlyProofs publishes the proofs of the pass whose
// state carries stateUpdatedAt, or removes the record when it has none. The
// caller holds the guardian state lock and writes the state after it.
func writeEnterpriseHookRouteOnlyProofs(dataDir, stateUpdatedAt string, proofs []enterpriseHookRouteOnlyProof) error {
	path := filepath.Join(strings.TrimSpace(dataDir), hookGuardianRouteOnlyProofFile)
	if len(proofs) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	data, err := json.MarshalIndent(enterpriseHookRouteOnlyProofRecord{Version: 1, StateUpdatedAt: stateUpdatedAt, Targets: proofs}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeEnterpriseHookProtectedFile(path, append(data, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		return fmt.Errorf("make hook guardian route-only proofs readable: %w", err)
	}
	if err := enterpriseHookAuthorizationOwnershipSetter(path); err != nil {
		return fmt.Errorf("set hook guardian route-only proofs ownership: %w", err)
	}
	return nil
}

// readEnterpriseHookRouteOnlyProofs returns the proofs by target key of the
// guardian pass that wrote the state with stateUpdatedAt; nil for a record
// that is missing, untrusted, malformed or from another pass.
func readEnterpriseHookRouteOnlyProofs(dataDir, stateUpdatedAt string) map[string]string {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(stateUpdatedAt) == "" {
		return nil
	}
	path := filepath.Join(strings.TrimSpace(dataDir), hookGuardianRouteOnlyProofFile)
	var trust func(string) error
	if cfg != nil && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		trust = enterpriseHookGuardianStateFileTrustCheck
	}
	data, exists, err := readEnterpriseHookPublishedRecord(path, "hook guardian route-only proofs", enterpriseHookGuardianStateMaxBytes, trust)
	if err != nil || !exists {
		return nil
	}
	var record enterpriseHookRouteOnlyProofRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || record.Version != 1 || record.StateUpdatedAt != stateUpdatedAt {
		return nil
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil
	}
	proofs := map[string]string{}
	for _, target := range record.Targets {
		if key := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{SID: target.SID, Connector: target.Connector}); key != "" && target.Proof != "" {
			proofs[key] = target.Proof
		}
	}
	return proofs
}

// enterpriseHookRouteOnlyGuardianVerified reports a row whose route-only
// render this token could not read (RouteOnlyUnverified) while the guardian
// recorded the same target protected, with the RouteOnlyProof of exactly the
// render expected now, in the pass of the state verify compares: the
// guardian, as LocalSystem, read that render back as the account. A failed or
// pending record, a proof of another config, endpoint or credential epoch,
// and a pass that recorded no proof do not cover it (GAP-1975).
func enterpriseHookRouteOnlyGuardianVerified(result enterprisehooks.InstallResult, recorded enterpriseHookReconcileRow, recordedProof string, expected *connector.RouteOnlySetup) bool {
	if result.RouteOnly != enterprisehooks.RouteOnlyUnverified || !recorded.OK || recorded.Pending {
		return false
	}
	proof := enterprisehooks.RouteOnlyProof(expected)
	return proof != "" && recordedProof == proof
}
