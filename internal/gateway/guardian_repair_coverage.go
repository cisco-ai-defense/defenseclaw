// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type managedGuardianCurrentTarget struct {
	managedGuardianAuthorizationTarget
	Pending bool `json:"pending,omitempty"`
}

// Projection of the v1 state and activation records. Retained ProtectedTargets
// are enrollment history; Results contains the current dispositions.
type managedGuardianCoverageProof struct {
	Version          int                                  `json:"version"`
	UpdatedAt        string                               `json:"updated_at"`
	Manifest         string                               `json:"manifest"`
	OK               bool                                 `json:"ok"`
	TargetCount      int                                  `json:"target_count"`
	SuccessCount     int                                  `json:"success_count"`
	PendingCount     int                                  `json:"pending_count,omitempty"`
	FailureCount     int                                  `json:"failure_count"`
	ReconcileID      string                               `json:"reconcile_id,omitempty"`
	ManifestSHA256   string                               `json:"manifest_sha256,omitempty"`
	Results          []managedGuardianCurrentTarget       `json:"results,omitempty"`
	ProtectedTargets []managedGuardianAuthorizationTarget `json:"protected_targets,omitempty"`
}

func readManagedGuardianCoverageProof(path string) (managedGuardianCoverageProof, error) {
	var proof managedGuardianCoverageProof
	if err := validateManagedGuardianAuthorization(path, "Guardian repair-pending proof"); err != nil {
		return proof, err
	}
	file, err := os.Open(path)
	if err != nil {
		return proof, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return proof, err
	}
	if !info.Mode().IsRegular() || info.Size() > managedGuardianAuthorizationMaxBytes {
		return proof, fmt.Errorf("invalid Guardian proof file")
	}
	current, err := os.Lstat(path)
	if err != nil {
		return proof, err
	}
	if !current.Mode().IsRegular() || !os.SameFile(info, current) {
		return proof, fmt.Errorf("Guardian proof changed before read")
	}
	decoder := json.NewDecoder(io.LimitReader(file, managedGuardianAuthorizationMaxBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return proof, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return proof, fmt.Errorf("Guardian proof has trailing content")
	}
	return proof, nil
}

// Called only when the ledger has historical entries beyond current successes.
// An arbitrary larger ledger is insufficient: the fresh state and activation
// must prove every additional entry is a current repair-pending target.
func validateManagedGuardianRepairCoverage(dataDir string, authorization managedGuardianAuthorization) error {
	state, err := readManagedGuardianCoverageProof(filepath.Join(dataDir, "hook_guardian_state.json"))
	if err != nil {
		return fmt.Errorf("read Guardian current dispositions: %w", err)
	}
	activation, err := readManagedGuardianCoverageProof(filepath.Join(managed.HookGuardianAuthorizationDir(dataDir), "activation.json"))
	if err != nil {
		return fmt.Errorf("read Guardian activation: %w", err)
	}
	for _, proof := range []managedGuardianCoverageProof{state, activation} {
		if proof.Version != 1 || !proof.OK || proof.FailureCount != 0 ||
			proof.UpdatedAt != authorization.UpdatedAt || proof.TargetCount != authorization.TargetCount ||
			proof.SuccessCount != authorization.SuccessCount || proof.PendingCount != authorization.PendingCount {
			return fmt.Errorf("Guardian repair-pending records do not bind the same current reconcile")
		}
	}
	id, idErr := hex.DecodeString(activation.ReconcileID)
	digest, digestErr := hex.DecodeString(activation.ManifestSHA256)
	if idErr != nil || len(id) != 16 || digestErr != nil || len(digest) != 32 ||
		strings.TrimSpace(state.Manifest) == "" || !filepath.IsAbs(state.Manifest) ||
		!strings.EqualFold(filepath.Clean(state.Manifest), filepath.Clean(activation.Manifest)) ||
		!reflect.DeepEqual(activation.ProtectedTargets, authorization.ProtectedTargets) {
		return fmt.Errorf("Guardian repair-pending activation has invalid manifest or enrollment bindings")
	}
	current := make([]guardianstate.CoverageTarget, 0, len(state.Results))
	for _, row := range state.Results {
		name := strings.ToLower(strings.TrimSpace(row.Connector))
		current = append(current, guardianstate.CoverageTarget{Key: managedGuardianTargetKey(row.managedGuardianAuthorizationTarget, name), Home: row.UserHome, OK: row.OK, Pending: row.Pending, Error: row.Error, HasResult: row.Result != nil})
	}
	retained := make([]guardianstate.CoverageTarget, 0, len(authorization.ProtectedTargets))
	for _, row := range authorization.ProtectedTargets {
		name := strings.ToLower(strings.TrimSpace(row.Connector))
		retained = append(retained, guardianstate.CoverageTarget{Key: managedGuardianTargetKey(row, name), Home: row.UserHome, OK: row.OK, Error: row.Error, HasResult: row.Result != nil})
	}
	if len(current) != authorization.TargetCount {
		return fmt.Errorf("Guardian repair-pending state does not cover every enabled target")
	}
	_, err = guardianstate.ValidateCoverage(current, retained, authorization.SuccessCount, authorization.PendingCount)
	return err
}
