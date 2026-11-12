// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"
)

// A link at a connector's machine vendor folder (ProgramData\OpenAI\Codex,
// ProgramData\Cursor, Program Files\ClaudeCode) is never followed, changed or
// removed. The enrollment pre-pass used to fail the whole reconcile pass on it,
// so no row was written, the new manifest was never activated, and an
// uninstall that came after a manifest republish stopped with 1603 (GAP-0879).
// The pre-pass now reports such a link as a typed failure of that connector;
// the pass goes on for the others, writes a failed row for each target of the
// connector, and activates the manifest. The connector stays fail-closed: its
// rows fail, nothing is written through the link, and the next pass retries.

// enterpriseHookVendorFolderLinkRow is the error of a failed row: the refusal
// to write through the link, in the wording the Setup adoption gate matches
// (GuardianMachineFolderLinkPattern in DefenseClawEnterprise.psm1): an optional
// prefix, the refusal, the path of the link, and nothing after it.
const enterpriseHookVendorFolderLinkRow = "enterprise hooks: reconcile %s machine policy: reparse points are not allowed in %s machine path: %s"

// enterpriseHookConnectorLabels name the connectors a vendor folder link can
// fail, as the refusal text spells them.
var enterpriseHookConnectorLabels = map[string]string{
	"codex":      "Codex",
	"cursor":     "Cursor",
	"claudecode": "Claude Code",
}

// enterpriseHookConnectorLinkFailure is one connector whose vendor folder a
// link keeps, with the error its step returned.
type enterpriseHookConnectorLinkFailure struct {
	Connector string
	Link      string
	Cause     error
}

// rowError is the error text of a failed row of this connector.
func (failure enterpriseHookConnectorLinkFailure) rowError() string {
	label := enterpriseHookConnectorLabels[failure.Connector]
	if label == "" {
		label = failure.Connector
	}
	return fmt.Sprintf(enterpriseHookVendorFolderLinkRow, label, label, failure.Link)
}

// enterpriseHookConnectorLinkFailures is the error of an enrollment pre-pass
// whose only failures are vendor folder links.
type enterpriseHookConnectorLinkFailures struct {
	Failures []enterpriseHookConnectorLinkFailure
}

func (failures *enterpriseHookConnectorLinkFailures) Error() string {
	messages := make([]string, 0, len(failures.Failures))
	for _, failure := range failures.Failures {
		messages = append(messages, failure.Cause.Error())
	}
	return strings.Join(messages, "; ")
}

func (failures *enterpriseHookConnectorLinkFailures) Unwrap() []error {
	causes := make([]error, 0, len(failures.Failures))
	for _, failure := range failures.Failures {
		causes = append(causes, failure.Cause)
	}
	return causes
}

// coveredBy reports whether every connector named here already has a failed
// row text in rows (the pre-pass of this run failed its targets).
func (failures *enterpriseHookConnectorLinkFailures) coveredBy(rows map[string]string) bool {
	for _, failure := range failures.Failures {
		if _, ok := rows[failure.Connector]; !ok {
			return false
		}
	}
	return len(failures.Failures) > 0
}

// causeLine is the guardian log line for a link failure: the link, the fix and
// the cause, the same for every connector.
func (failure enterpriseHookConnectorLinkFailure) causeLine() string {
	return fmt.Sprintf("[hook-guardian] the %s machine folder is a link (%s); its targets fail and the others go on. "+
		"Fix: as an administrator, run cmd /c rmdir \"%s\" (it removes the link only, not its target). Cause: %s\n",
		failure.Connector, failure.Link, failure.Link, failure.Cause)
}

// rowErrors maps each failed connector to the error text of its rows.
func (failures *enterpriseHookConnectorLinkFailures) rowErrors() map[string]string {
	rows := make(map[string]string, len(failures.Failures))
	for _, failure := range failures.Failures {
		rows[failure.Connector] = failure.rowError()
	}
	return rows
}

// enterpriseHookLinkFailures returns the typed failures inside err, nil when
// err is not (only) vendor folder links.
func enterpriseHookLinkFailures(err error) *enterpriseHookConnectorLinkFailures {
	var failures *enterpriseHookConnectorLinkFailures
	if errors.As(err, &failures) {
		return failures
	}
	return nil
}

// classifyEnterpriseHookConnectorErrors turns the errors of the connector
// steps of the enrollment pre-pass (by connector name) and any pass-level
// error into the one error the pass returns. A connector whose step failed
// while a link keeps its vendor folder (found now, without following it) is a
// link failure; the pass fails as a whole only when something else failed.
func classifyEnterpriseHookConnectorErrors(link func(connectorName string) string, steps []enterpriseHookConnectorStepError, passErr error) error {
	var links []enterpriseHookConnectorLinkFailure
	var hard []error
	if passErr != nil {
		hard = append(hard, passErr)
	}
	for _, step := range steps {
		if step.Err == nil {
			continue
		}
		if linkPath := link(step.Connector); linkPath != "" {
			links = append(links, enterpriseHookConnectorLinkFailure{Connector: step.Connector, Link: linkPath, Cause: step.Err})
			continue
		}
		hard = append(hard, step.Err)
	}
	switch {
	case len(hard) == 0 && len(links) == 0:
		return nil
	case len(hard) == 0:
		return &enterpriseHookConnectorLinkFailures{Failures: links}
	}
	for _, failure := range links {
		hard = append(hard, failure.Cause)
	}
	if len(hard) == 1 {
		return hard[0]
	}
	return errors.Join(hard...)
}

// enterpriseHookConnectorStepError is the error of one connector step.
type enterpriseHookConnectorStepError struct {
	Connector string
	Err       error
}
