// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// One user whose Devin version had no verified hook contract left 3 of 18
// guardian targets failed, and the gateway reported the guardrail as
// "starting" with enforcement off for every user.
// In the standalone profile per-user failures are reported, not fatal; the
// Secure Client view keeps requiring a complete record.
func TestStandaloneGuardianCoverageIsolatesPerUserFailures(t *testing.T) {
	authorizationDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authorizationDir)
	oldValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(_, _ string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate })
	path := managed.HookGuardianAuthorizationPath(t.TempDir())
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fresh := time.Now().UTC().Format(time.RFC3339)
	// Rows carry a SID as well as a POSIX identity: Windows keys guardian
	// targets strictly by SID, so rows without one are incomplete there.
	write(fmt.Sprintf(`{
		"version":1,
		"updated_at":%q,
		"ok":false,
		"target_count":3,
		"success_count":1,
		"failure_count":1,
		"pending_count":1,
		"protected_targets":[{"user":"bob","sid":"S-1-5-21-1-2-3-1002","user_home":"/home/bob","connector":"claudecode","ok":true,"uid":1002}]
	}`, fresh))

	if ok, _ := managedGuardianCoversConnectors("unused", []string{"claudecode"}); ok {
		t.Fatal("the Secure Client view accepted an incomplete record")
	}
	ok, status := managedGuardianStandaloneCoverage("unused")
	if !ok {
		t.Fatalf("one user failure disabled the standalone guardrail: %s", status)
	}
	if !strings.Contains(status, "2 of 3 guardian targets need attention") {
		t.Fatalf("status = %q", status)
	}

	// A target whose current repair failed keeps its last successful row
	// (user A made a home group-writable); that must not flip the host.
	write(fmt.Sprintf(`{
		"version":1,
		"updated_at":%q,
		"ok":false,
		"target_count":2,
		"success_count":1,
		"failure_count":1,
		"protected_targets":[
			{"user":"alice","sid":"S-1-5-21-1-2-3-1001","user_home":"/home/alice","connector":"amp","ok":true,"uid":1001},
			{"user":"bob","sid":"S-1-5-21-1-2-3-1002","user_home":"/home/bob","connector":"amp","ok":true,"uid":1002}
		]
	}`, fresh))
	if ok, status := managedGuardianStandaloneCoverage("unused"); !ok {
		t.Fatalf("a carried-over protected row disabled the standalone guardrail: %s", status)
	}

	// A previously protected target whose repair now fails stays in the
	// ledger (the user cannot unenroll by breaking their own home); that
	// must not disable the guardrail for everyone else.
	write(fmt.Sprintf(`{
		"version":1,
		"updated_at":%q,
		"ok":false,
		"target_count":2,
		"success_count":1,
		"failure_count":1,
		"protected_targets":[
			{"user":"alice","sid":"S-1-5-21-1-2-3-1001","user_home":"/home/alice","connector":"claudecode","ok":true,"uid":1001},
			{"user":"bob","sid":"S-1-5-21-1-2-3-1002","user_home":"/home/bob","connector":"claudecode","ok":true,"uid":1002}
		]
	}`, fresh))
	if ok, status := managedGuardianStandaloneCoverage("unused"); !ok || !strings.Contains(status, "1 of 2 guardian targets need attention") {
		t.Fatalf("retained protected row after a repair failure = %v %q", ok, status)
	}

	// A connector with no enrolled user is not a standalone gap.
	write(fmt.Sprintf(`{"version":1,"updated_at":%q,"ok":true,"target_count":0,"success_count":0,"failure_count":0,"protected_targets":[]}`, fresh))
	if ok, status := managedGuardianStandaloneCoverage("unused"); !ok || status != "" {
		t.Fatalf("empty standalone record = %v %q", ok, status)
	}

	// Structural problems still fail closed.
	for name, body := range map[string]string{
		"stale":               `{"version":1,"updated_at":"2020-01-01T00:00:00Z","ok":true,"target_count":0,"success_count":0,"failure_count":0,"protected_targets":[]}`,
		"inconsistent counts": fmt.Sprintf(`{"version":1,"updated_at":%q,"ok":true,"target_count":5,"success_count":1,"failure_count":1,"protected_targets":[{"user":"bob","sid":"S-1-5-21-1-2-3-1002","user_home":"/home/bob","connector":"codex","ok":true}]}`, fresh),
		"more protected rows than successes and failures": fmt.Sprintf(`{"version":1,"updated_at":%q,"ok":true,"target_count":1,"success_count":1,"failure_count":0,"protected_targets":[{"user":"bob","sid":"S-1-5-21-1-2-3-1002","user_home":"/home/bob","connector":"codex","ok":true},{"user":"eve","sid":"S-1-5-21-1-2-3-1003","user_home":"/home/eve","connector":"codex","ok":true}]}`, fresh),
		"failed protected row":                            fmt.Sprintf(`{"version":1,"updated_at":%q,"ok":true,"target_count":1,"success_count":1,"failure_count":0,"protected_targets":[{"user":"bob","sid":"S-1-5-21-1-2-3-1002","user_home":"/home/bob","connector":"codex","ok":false}]}`, fresh),
	} {
		write(body)
		if ok, _ := managedGuardianStandaloneCoverage("unused"); ok {
			t.Fatalf("%s: standalone coverage accepted a broken record", name)
		}
	}
}
