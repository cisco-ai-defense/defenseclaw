// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"strings"
	"testing"
)

// GAP-0474: the delete output says how many snapshots went with the agent.
func TestGAP0474DeleteOutputNamesThePurgedSnapshots(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET actors": jsonReply(sampleActors()),
		"DELETE actors/eng-web/fix-tests-1": jsonReply(map[string]any{
			"atespace": "eng-web", "name": "fix-tests-1", "deleted": true, "snapshots": 3,
		}),
	}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateDeleteCmd(), "fix-tests-1", "--yes")
	if err != nil || !strings.Contains(out, "Deleted eng-web/fix-tests-1: the agent, 3 snapshots and the checkpoints saved inside it") {
		t.Fatalf("delete = %q, %v", out, err)
	}
}
