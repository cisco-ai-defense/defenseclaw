// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/spf13/cobra"
)

const (
	windowsManagedHookContractCleanupReceiptSchema = 1
	windowsManagedHookContractCleanupReportSchema  = 1
	windowsManagedHookContractCleanupPrepared      = "prepared"
	windowsManagedHookContractCleanupFinalized     = "finalized"
)

type windowsManagedHookContractCleanupReceipt struct {
	SchemaVersion          int                                                `json:"schema_version"`
	Phase                  string                                             `json:"phase"`
	IdentitySHA256         string                                             `json:"identity_sha256"`
	ScopeSHA256            string                                             `json:"scope_sha256"`
	ManifestSHA256         string                                             `json:"manifest_sha256"`
	ManifestFingerprint    string                                             `json:"manifest_fingerprint"`
	DeploymentGenerationID string                                             `json:"deployment_generation_id"`
	GatewayServiceName     string                                             `json:"gateway_service_name"`
	Claims                 []connector.WindowsManagedHookContractCleanupClaim `json:"claims"`
}

// windowsManagedHookContractCleanupIdentity contains only the immutable,
// secretless authority in a cleanup receipt. The mutable receipt phase and
// per-claim progress bits are deliberately excluded, so an interrupted native
// cleanup can be resumed without changing the identity pinned by the purge
// intent.
type windowsManagedHookContractCleanupIdentity struct {
	SchemaVersion          int                                              `json:"schema_version"`
	ScopeSHA256            string                                           `json:"scope_sha256"`
	ManifestSHA256         string                                           `json:"manifest_sha256"`
	ManifestFingerprint    string                                           `json:"manifest_fingerprint"`
	DeploymentGenerationID string                                           `json:"deployment_generation_id"`
	GatewayServiceName     string                                           `json:"gateway_service_name"`
	Claims                 []windowsManagedHookContractCleanupIdentityClaim `json:"claims"`
}

type windowsManagedHookContractCleanupIdentityClaim struct {
	SchemaVersion      int    `json:"schema_version"`
	Connector          string `json:"connector"`
	SID                string `json:"sid"`
	DataDir            string `json:"data_dir"`
	GatewayServiceName string `json:"gateway_service_name"`
	EntryPresent       bool   `json:"entry_present"`
	EntrySHA256        string `json:"entry_sha256"`
	Superseded         bool   `json:"superseded,omitempty"`
}

type windowsManagedHookContractCleanupReport struct {
	SchemaVersion      int    `json:"schema_version"`
	OK                 bool   `json:"ok"`
	ScopeSHA256        string `json:"scope_sha256"`
	Phase              string `json:"phase"`
	TargetCount        int    `json:"target_count"`
	RemovedCount       int    `json:"removed_count"`
	AlreadyAbsentCount int    `json:"already_absent_count"`
	SupersededCount    int    `json:"superseded_count"`
	Error              string `json:"error"`
}

type windowsManagedHookContractCleanupOptions struct {
	receipt                string
	output                 string
	scopeSHA256            string
	manifestSHA256         string
	deploymentGenerationID string
	gatewayServiceName     string
}

func newWindowsManagedHookContractCleanupCommand() *cobra.Command {
	opts := &windowsManagedHookContractCleanupOptions{}
	command := &cobra.Command{
		Use:          "managed-hook-contract-cleanup",
		Short:        "Apply one authenticated retired-scope hook-contract receipt",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runWindowsManagedHookContractCleanup(opts)
		},
	}
	flags := command.Flags()
	flags.StringVar(&opts.receipt, "receipt", "", "protected retired-scope cleanup receipt")
	flags.StringVar(&opts.output, "output", "", "pre-created protected AdminFile report path")
	flags.StringVar(&opts.scopeSHA256, "scope-sha256", "", "exact lifecycle scope SHA-256")
	flags.StringVar(&opts.manifestSHA256, "manifest-sha256", "", "authenticated retired manifest SHA-256")
	flags.StringVar(&opts.deploymentGenerationID, "deployment-generation-id", "", "authenticated retired deployment generation")
	flags.StringVar(&opts.gatewayServiceName, "gateway-service-name", "", "exact retired gateway service name")
	return command
}

func runWindowsManagedHookContractCleanup(opts *windowsManagedHookContractCleanupOptions) error {
	if opts == nil {
		return errors.New("managed hook contract cleanup options are required")
	}
	if err := enterpriseHooksNativePlatformPreflight(); err != nil {
		return err
	}
	receiptPath, err := requireWindowsTargetRuntimeProtectedPath(
		opts.receipt,
		"managed hook contract cleanup receipt",
	)
	if err != nil {
		return err
	}
	outputPath, err := requireWindowsTargetRuntimeProtectedPath(
		opts.output,
		"managed hook contract cleanup output",
	)
	if err != nil {
		return err
	}
	if sameWindowsEnterprisePathCLI(receiptPath, outputPath) {
		return errors.New("managed hook contract cleanup receipt and output must be distinct")
	}
	receipt, err := readWindowsManagedHookContractCleanupReceipt(receiptPath)
	if err == nil {
		err = validateWindowsManagedHookContractCleanupExpected(
			receipt,
			opts.scopeSHA256,
			opts.manifestSHA256,
			opts.deploymentGenerationID,
			opts.gatewayServiceName,
		)
	}
	report := windowsManagedHookContractCleanupReport{
		SchemaVersion: windowsManagedHookContractCleanupReportSchema,
		ScopeSHA256:   strings.TrimSpace(opts.scopeSHA256),
	}
	if err == nil {
		report.TargetCount = len(receipt.Claims)
		report.RemovedCount, report.AlreadyAbsentCount,
			report.SupersededCount, err =
			applyWindowsManagedHookContractCleanupReceipt(receiptPath, receipt)
		report.Phase = windowsManagedHookContractCleanupFinalized
	}
	report.OK = err == nil
	if err != nil {
		report.Error = err.Error()
	}
	if writeErr := writeWindowsTargetRuntimeProtectedJSON(outputPath, report); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return errors.New("managed hook contract cleanup failed; inspect the protected report")
	}
	return nil
}

func captureWindowsManagedHookContractCleanupReceipt(
	identity windowsManagedHooksTeardownJournal,
	scopeSHA256 string,
) (windowsManagedHookContractCleanupReceipt, error) {
	receipt := windowsManagedHookContractCleanupReceipt{
		SchemaVersion:          windowsManagedHookContractCleanupReceiptSchema,
		Phase:                  windowsManagedHookContractCleanupPrepared,
		ScopeSHA256:            strings.TrimSpace(scopeSHA256),
		ManifestSHA256:         identity.ManifestSHA256,
		ManifestFingerprint:    identity.ManifestFingerprint,
		DeploymentGenerationID: identity.DeploymentGenerationID,
		GatewayServiceName:     identity.GatewayServiceName,
		Claims:                 make([]connector.WindowsManagedHookContractCleanupClaim, 0, len(identity.Targets)),
	}
	if !validWindowsManagedHookContractCleanupScope(receipt.ScopeSHA256) {
		return receipt, errors.New("managed hook contract cleanup scope is invalid")
	}
	for _, target := range identity.Targets {
		var claim connector.WindowsManagedHookContractCleanupClaim
		err := enterprisehooks.RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
			var captureErr error
			claim, captureErr = connector.CaptureManagedHookContractCleanupClaimForOwner(
				target.DataDir,
				target.Connector,
				target.SID,
				identity.GatewayServiceName,
			)
			return captureErr
		})
		if err != nil {
			return receipt, fmt.Errorf(
				"capture %s managed hook contract cleanup claim for %s: %w",
				target.Connector,
				target.SID,
				err,
			)
		}
		receipt.Claims = append(receipt.Claims, claim)
	}
	identitySHA256, err := windowsManagedHookContractCleanupIdentitySHA256(receipt)
	if err != nil {
		return receipt, err
	}
	receipt.IdentitySHA256 = identitySHA256
	if err := validateWindowsManagedHookContractCleanupReceiptBinding(
		receipt,
		identity,
		receipt.ScopeSHA256,
	); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func readWindowsManagedHookContractCleanupReceipt(
	path string,
) (windowsManagedHookContractCleanupReceipt, error) {
	var receipt windowsManagedHookContractCleanupReceipt
	if err := readWindowsTargetRuntimeProtectedJSON(path, &receipt); err != nil {
		return receipt, fmt.Errorf("read protected managed hook contract cleanup receipt: %w", err)
	}
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		return receipt, err
	}
	return receipt, nil
}

func writeWindowsManagedHookContractCleanupReceipt(
	path string,
	receipt windowsManagedHookContractCleanupReceipt,
) error {
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		return err
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("marshal managed hook contract cleanup receipt: %w", err)
	}
	body = append(body, '\n')
	if len(body) > windowsTargetRuntimeJSONMaxBytes {
		return errors.New("managed hook contract cleanup receipt exceeds protected output bound")
	}
	// Unlike a one-shot helper report, this receipt is durable crash-recovery
	// authority. Publish each one-way progress transition through a protected
	// same-directory replacement so power loss leaves either the previous or
	// next complete JSON document, never a truncated sole receipt.
	if err := validateWindowsManagedHookContractCleanupReceiptDestination(path, true); err != nil {
		return err
	}
	if err := writeEnterpriseHookProtectedFile(path, body); err != nil {
		return fmt.Errorf("write protected managed hook contract cleanup receipt: %w", err)
	}
	if err := windowsTargetRuntimeAdminValidate(path); err != nil {
		return fmt.Errorf("validate published managed hook contract cleanup receipt: %w", err)
	}
	stored, err := readWindowsManagedHookContractCleanupReceipt(path)
	if err != nil {
		return err
	}
	if err := validateWindowsManagedHookContractCleanupExpected(
		stored,
		receipt.ScopeSHA256,
		receipt.ManifestSHA256,
		receipt.DeploymentGenerationID,
		receipt.GatewayServiceName,
	); err != nil {
		return err
	}
	if stored.Phase != receipt.Phase || len(stored.Claims) != len(receipt.Claims) {
		return errors.New("managed hook contract cleanup receipt changed during publication")
	}
	for index := range receipt.Claims {
		if stored.Claims[index] != receipt.Claims[index] {
			return errors.New("managed hook contract cleanup claims changed during publication")
		}
	}
	return nil
}

func requireWindowsManagedHookContractCleanupReceiptPath(
	raw, label string,
	allowMissing bool,
) (string, error) {
	path, err := requireWindowsTargetRuntimeAbsolutePath(raw, label)
	if err != nil {
		return "", err
	}
	if err := validateWindowsManagedHookContractCleanupReceiptDestination(
		path,
		allowMissing,
	); err != nil {
		return "", err
	}
	return path, nil
}

func validateWindowsManagedHookContractCleanupReceiptDestination(
	path string,
	allowMissing bool,
) error {
	if _, err := os.Lstat(path); err == nil {
		if err := windowsTargetRuntimeRequestTrust(path, "managed hook contract cleanup receipt"); err != nil {
			return err
		}
		return windowsTargetRuntimeAdminValidate(path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect managed hook contract cleanup receipt: %w", err)
	} else if !allowMissing {
		return fmt.Errorf("managed hook contract cleanup receipt is missing: %w", err)
	}
	parent := filepath.Dir(path)
	if err := managed.ValidateTrustedRuntimeDir(
		parent,
		"managed hook contract cleanup receipt parent",
	); err != nil {
		return err
	}
	return nil
}

func applyWindowsManagedHookContractCleanupReceipt(
	path string,
	receipt windowsManagedHookContractCleanupReceipt,
) (removed int, alreadyAbsent int, superseded int, err error) {
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		return 0, 0, 0, err
	}
	if receipt.Phase == windowsManagedHookContractCleanupFinalized {
		for _, claim := range receipt.Claims {
			if claim.Superseded {
				superseded++
			} else {
				alreadyAbsent++
			}
		}
		return 0, alreadyAbsent, superseded, nil
	}
	for index := range receipt.Claims {
		claim := receipt.Claims[index]
		if claim.Completed {
			alreadyAbsent++
			continue
		}
		var result connector.WindowsManagedHookContractCleanupResult
		barrier := func() error { return nil }
		if claim.EntryPresent && !claim.ApplicationStarted {
			barrier = func() error {
				receipt.Claims[index].ApplicationStarted = true
				return writeWindowsManagedHookContractCleanupReceipt(path, receipt)
			}
		}
		err := enterprisehooks.RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
			var applyErr error
			result, applyErr = connector.ApplyManagedHookContractCleanupClaimForOwnerWithBarrier(
				claim,
				barrier,
			)
			return applyErr
		})
		if err != nil {
			if receipt.Claims[index].ApplicationStarted && errors.Is(
				err,
				connector.ErrWindowsManagedHookContractCleanupSuperseded,
			) {
				// The mutation barrier was persisted while the old connector
				// lock was held. A later mismatch can therefore only be state
				// published after that crash boundary; preserve it as a newer
				// owner and retire this old claim without touching its bytes.
				receipt.Claims[index].Completed = true
				if writeErr := writeWindowsManagedHookContractCleanupReceipt(path, receipt); writeErr != nil {
					return removed, alreadyAbsent, superseded, writeErr
				}
				superseded++
				continue
			}
			return removed, alreadyAbsent, superseded, fmt.Errorf(
				"apply %s managed hook contract cleanup claim for %s: %w",
				claim.Connector,
				claim.SID,
				err,
			)
		}
		if result.Removed {
			removed++
		}
		if result.AlreadyAbsent {
			alreadyAbsent++
		}
		if result.Superseded {
			superseded++
		}
		completeWindowsManagedHookContractCleanupClaim(
			&receipt.Claims[index],
			result,
		)
		if writeErr := writeWindowsManagedHookContractCleanupReceipt(path, receipt); writeErr != nil {
			return removed, alreadyAbsent, superseded, writeErr
		}
	}
	receipt.Phase = windowsManagedHookContractCleanupFinalized
	if err := writeWindowsManagedHookContractCleanupReceipt(path, receipt); err != nil {
		return removed, alreadyAbsent, superseded, err
	}
	return removed, alreadyAbsent, superseded, nil
}

func completeWindowsManagedHookContractCleanupClaim(
	claim *connector.WindowsManagedHookContractCleanupClaim,
	result connector.WindowsManagedHookContractCleanupResult,
) {
	if claim == nil {
		return
	}
	// The connector layer returns AlreadyAbsent for a captured-present entry
	// only after ApplicationStarted was durably persisted while the matching
	// entry lock was held. Never fabricate that barrier here: without it, a
	// temporarily hidden lock/entry could be mistaken for completed cleanup and
	// restored after this receipt is finalized.
	claim.Completed = true
}

func validateWindowsManagedHookContractCleanupReceiptBinding(
	receipt windowsManagedHookContractCleanupReceipt,
	identity windowsManagedHooksTeardownJournal,
	scopeSHA256 string,
) error {
	if err := validateWindowsManagedHookContractCleanupExpected(
		receipt,
		scopeSHA256,
		identity.ManifestSHA256,
		identity.DeploymentGenerationID,
		identity.GatewayServiceName,
	); err != nil {
		return err
	}
	if receipt.ManifestFingerprint != identity.ManifestFingerprint ||
		len(receipt.Claims) != len(identity.Targets) {
		return errors.New("managed hook contract cleanup receipt does not match the teardown manifest")
	}
	for index, target := range identity.Targets {
		claim := receipt.Claims[index]
		if claim.Connector != target.Connector || claim.SID != target.SID ||
			!sameWindowsEnterprisePathCLI(claim.DataDir, target.DataDir) {
			return errors.New("managed hook contract cleanup claim does not match the teardown target")
		}
	}
	return nil
}

func validateWindowsManagedHookContractCleanupExpected(
	receipt windowsManagedHookContractCleanupReceipt,
	scopeSHA256, manifestSHA256, deploymentGenerationID, gatewayServiceName string,
) error {
	if err := validateWindowsManagedHookContractCleanupReceipt(receipt); err != nil {
		return err
	}
	if receipt.ScopeSHA256 != strings.TrimSpace(scopeSHA256) ||
		receipt.ManifestSHA256 != strings.TrimSpace(manifestSHA256) ||
		receipt.DeploymentGenerationID != strings.TrimSpace(deploymentGenerationID) ||
		!strings.EqualFold(
			receipt.GatewayServiceName,
			strings.TrimSpace(gatewayServiceName),
		) {
		return errors.New("managed hook contract cleanup receipt does not match the authenticated retired scope")
	}
	return nil
}

func validateWindowsManagedHookContractCleanupReceipt(
	receipt windowsManagedHookContractCleanupReceipt,
) error {
	if receipt.SchemaVersion != windowsManagedHookContractCleanupReceiptSchema ||
		(receipt.Phase != windowsManagedHookContractCleanupPrepared &&
			receipt.Phase != windowsManagedHookContractCleanupFinalized) ||
		!validWindowsManagedHookContractCleanupScope(receipt.ScopeSHA256) ||
		!validEnterpriseHookHex(receipt.ManifestSHA256, 32) ||
		!windowsManagedHooksValidSHA256(receipt.ManifestFingerprint) ||
		!validEnterpriseHookHex(receipt.DeploymentGenerationID, 16) ||
		strings.TrimSpace(receipt.GatewayServiceName) == "" ||
		strings.TrimSpace(receipt.GatewayServiceName) != receipt.GatewayServiceName ||
		strings.ContainsAny(receipt.GatewayServiceName, "\x00\r\n") ||
		len(receipt.GatewayServiceName) > 256 ||
		len(receipt.Claims) > windowsManagedHooksTeardownTargetMax {
		return errors.New("managed hook contract cleanup receipt has invalid scope or identity")
	}
	seen := make(map[string]struct{}, len(receipt.Claims))
	previous := ""
	for _, claim := range receipt.Claims {
		if claim.SchemaVersion != connector.WindowsManagedHookContractCleanupClaimSchema ||
			(claim.Connector != "claudecode" && claim.Connector != "codex" && claim.Connector != "cursor") ||
			claim.SID == "" || strings.ToUpper(claim.SID) != claim.SID ||
			!filepath.IsAbs(claim.DataDir) || filepath.Clean(claim.DataDir) != claim.DataDir ||
			!strings.EqualFold(filepath.Base(claim.DataDir), ".defenseclaw") ||
			!strings.EqualFold(claim.GatewayServiceName, receipt.GatewayServiceName) ||
			(claim.EntryPresent && !windowsManagedHooksValidSHA256(claim.EntrySHA256)) ||
			(!claim.EntryPresent && claim.EntrySHA256 != "") ||
			(!claim.EntryPresent && claim.ApplicationStarted) ||
			(claim.Superseded && (claim.EntryPresent || claim.ApplicationStarted)) {
			return errors.New("managed hook contract cleanup receipt contains an invalid claim")
		}
		if claim.EntryPresent && claim.Completed && !claim.ApplicationStarted {
			return errors.New("completed managed hook contract cleanup claim has no mutation barrier")
		}
		key := claim.Connector + "\x00" + claim.SID
		if _, duplicate := seen[key]; duplicate {
			return errors.New("managed hook contract cleanup receipt contains a duplicate claim")
		}
		if previous != "" && strings.Compare(previous, key) >= 0 {
			return errors.New("managed hook contract cleanup receipt claims are not canonically ordered")
		}
		seen[key] = struct{}{}
		previous = key
	}
	if receipt.Phase == windowsManagedHookContractCleanupFinalized {
		for _, claim := range receipt.Claims {
			if !claim.Completed {
				return errors.New("finalized managed hook contract cleanup receipt contains an incomplete claim")
			}
		}
	}
	identitySHA256, err := windowsManagedHookContractCleanupIdentitySHA256(receipt)
	if err != nil {
		return err
	}
	if receipt.IdentitySHA256 != identitySHA256 {
		return errors.New("managed hook contract cleanup receipt immutable identity changed")
	}
	return nil
}

func windowsManagedHookContractCleanupIdentitySHA256(
	receipt windowsManagedHookContractCleanupReceipt,
) (string, error) {
	identity := windowsManagedHookContractCleanupIdentity{
		SchemaVersion:          receipt.SchemaVersion,
		ScopeSHA256:            receipt.ScopeSHA256,
		ManifestSHA256:         receipt.ManifestSHA256,
		ManifestFingerprint:    receipt.ManifestFingerprint,
		DeploymentGenerationID: receipt.DeploymentGenerationID,
		GatewayServiceName:     receipt.GatewayServiceName,
		Claims:                 make([]windowsManagedHookContractCleanupIdentityClaim, 0, len(receipt.Claims)),
	}
	for _, claim := range receipt.Claims {
		identity.Claims = append(identity.Claims, windowsManagedHookContractCleanupIdentityClaim{
			SchemaVersion:      claim.SchemaVersion,
			Connector:          claim.Connector,
			SID:                claim.SID,
			DataDir:            claim.DataDir,
			GatewayServiceName: claim.GatewayServiceName,
			EntryPresent:       claim.EntryPresent,
			EntrySHA256:        claim.EntrySHA256,
			Superseded:         claim.Superseded,
		})
	}
	body, err := json.Marshal(identity)
	if err != nil {
		return "", fmt.Errorf("marshal managed hook contract cleanup identity: %w", err)
	}
	digest := sha256.Sum256(body)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func validWindowsManagedHookContractCleanupScope(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
