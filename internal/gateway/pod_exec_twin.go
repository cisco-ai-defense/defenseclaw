// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// podExecTwinRequests are the readings of the commands a kubectl, oc or k
// exec runs in a container (actionfacts.PodExecTwinCommands): a SQL client
// there asks the database server what it asks from the agent's host, so
// psql -c "COPY ... PROGRAM ..." through kubectl exec is read as the client
// call (rel-1-0-10:GAP-1925). The pod exec call itself stays partial and
// keeps its own verdict; a reading is never read for pod execs again.
func podExecTwinRequests(request trustedActionRequest, facts actionfacts.Facts) []trustedActionRequest {
	if request.podExecReading {
		return nil
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known {
		return nil
	}
	texts := actionfacts.PodExecTwinCommands(facts)
	twins := make([]trustedActionRequest, 0, len(texts))
	for _, text := range texts {
		twin := bashReadingRequest(request, command, text)
		twin.podExecReading = true
		twins = append(twins, twin)
	}
	return twins
}

// withPodExecReadingFindings joins to the call the database rule findings of
// a pod exec reading, and only those: a path, file or process rule of the
// reading names the container's file system and processes, not the agent's
// host, so it must not raise the call (raise-only, no new benign finding).
func withPodExecReadingFindings(findings, reading []RuleFinding) []RuleFinding {
	reading = slices.DeleteFunc(reading, func(finding RuleFinding) bool {
		_, database := semanticDatabaseOwners[strings.TrimSpace(finding.RuleID)]
		return !database
	})
	if len(reading) == 0 {
		return findings
	}
	return withHostTwinFindings(findings, reading)
}
