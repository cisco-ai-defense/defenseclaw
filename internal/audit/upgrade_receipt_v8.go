// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

var upgradeReceiptVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// UpgradeReceiptInput is the bounded, secret-free terminal state handed from
// the old updater to the newly bootstrapped v8 sidecar. ReceiptID is reused as
// the canonical record ID, making a retry after persistence idempotent.
type UpgradeReceiptInput struct {
	ReceiptID         string
	CompletedAt       time.Time
	FromVersion       string
	TargetVersion     string
	Status            string
	MigrationStatus   string
	MigrationCount    *int64
	ArtifactsVerified bool
	FailureCode       string
}

// LogUpgradeReceipt records one terminal upgrade result through the mandatory
// compliance.activity compatibility family. It never accepts config content,
// paths, endpoints, environment values, or arbitrary error text.
func (l *Logger) LogUpgradeReceipt(ctx context.Context, input UpgradeReceiptInput) error {
	if l == nil {
		return fmt.Errorf("audit: upgrade receipt logger is unavailable")
	}
	outcome, severity, err := validateUpgradeReceiptInput(input)
	if err != nil {
		return err
	}
	migrationCount := "unknown"
	if input.MigrationCount != nil {
		migrationCount = fmt.Sprintf("%d", *input.MigrationCount)
	}
	details := strings.Join([]string{
		"status=" + input.Status,
		"from_version=" + input.FromVersion,
		"target_version=" + input.TargetVersion,
		"migration_status=" + input.MigrationStatus,
		"migration_count=" + migrationCount,
		fmt.Sprintf("artifacts_verified=%t", input.ArtifactsVerified),
		"failure_code=" + input.FailureCode,
	}, " ")
	event := Event{
		ID: input.ReceiptID, Timestamp: input.CompletedAt.UTC(),
		Action: string(ActionUpgrade), Target: "defenseclaw", Actor: "cli:upgrade",
		Details: details, Severity: severity,
		Structured: map[string]any{
			"receipt_id": input.ReceiptID, "status": input.Status,
			"from_version": input.FromVersion, "target_version": input.TargetVersion,
			"migration_status": input.MigrationStatus, "migration_count": input.MigrationCount,
			"artifacts_verified": input.ArtifactsVerified, "failure_code": input.FailureCode,
		},
	}
	return l.logEventWithV8(ctx, event, func(ctx context.Context, stamped Event) (auditV8Disposition, error) {
		return l.emitCompatibilityAuditV8(ctx, stamped, compatibilityAuditV8Options{
			classification: observability.ClassificationContext{
				MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
			},
			source: observability.SourceCLI, phase: "upgrade", outcome: outcome,
		})
	})
}

func validateUpgradeReceiptInput(input UpgradeReceiptInput) (observability.Outcome, string, error) {
	parsed, err := uuid.Parse(input.ReceiptID)
	if err != nil || parsed.String() != input.ReceiptID || input.CompletedAt.IsZero() ||
		len(input.FromVersion) > 32 || len(input.TargetVersion) > 32 ||
		!upgradeReceiptVersionPattern.MatchString(input.FromVersion) ||
		!upgradeReceiptVersionPattern.MatchString(input.TargetVersion) {
		return "", "", fmt.Errorf("audit: invalid upgrade receipt identity")
	}
	if input.MigrationStatus != "pending" && input.MigrationStatus != "completed" &&
		input.MigrationStatus != "degraded" {
		return "", "", fmt.Errorf("audit: invalid upgrade receipt migration state")
	}
	if input.MigrationCount != nil && (*input.MigrationCount < 0 || *input.MigrationCount > 10_000) {
		return "", "", fmt.Errorf("audit: invalid upgrade receipt migration count")
	}
	if !validUpgradeReceiptFailureCode(input.FailureCode) {
		return "", "", fmt.Errorf("audit: invalid upgrade receipt failure code")
	}
	switch input.Status {
	case "succeeded":
		if input.FailureCode != "" || input.MigrationStatus == "degraded" {
			return "", "", fmt.Errorf("audit: inconsistent successful upgrade receipt")
		}
		return observability.OutcomeApplied, "INFO", nil
	case "partial":
		if input.FailureCode != "" {
			return "", "", fmt.Errorf("audit: inconsistent partial upgrade receipt")
		}
		return observability.OutcomePartial, "MEDIUM", nil
	case "failed":
		if input.FailureCode == "" {
			return "", "", fmt.Errorf("audit: incomplete failed upgrade receipt")
		}
		return observability.OutcomeFailed, "MEDIUM", nil
	case "rolled_back":
		if input.FailureCode == "" {
			return "", "", fmt.Errorf("audit: incomplete rollback upgrade receipt")
		}
		return observability.OutcomeRevoked, "MEDIUM", nil
	default:
		return "", "", fmt.Errorf("audit: upgrade receipt is not terminal")
	}
}

func validUpgradeReceiptFailureCode(value string) bool {
	switch value {
	case "", "install_failed", "migration_failed", "required_migration_failed",
		"local_observability_failed", "startup_failed", "health_check_failed",
		"interrupted", "rollback_detected":
		return true
	default:
		return false
	}
}
