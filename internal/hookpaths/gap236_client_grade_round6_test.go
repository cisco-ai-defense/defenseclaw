// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestGAP236PossibleClientDecisionEnvelope(t *testing.T) {
	for _, grade := range []string{PossibleTargetDecision, ProtectedTargetDecision} {
		data, err := json.Marshal(map[string]string{CWDKey: "/tmp/project", ActionDecisionKey: grade})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(base64.RawURLEncoding.EncodeToString(data))
		if !ok || targets[ActionDecisionKey] != grade {
			t.Fatalf("client decision %q did not retain its grade", grade)
		}
	}
}
