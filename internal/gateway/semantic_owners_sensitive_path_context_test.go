// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestEnvironmentFileOwnerDistinguishesReadWriteAndReference(t *testing.T) {
	t.Parallel()

	owner := semanticOwnerForRule("PATH-ENV-FILE")
	assertSensitivePathOwnerContext(
		t,
		owner,
		actionfacts.Input{Tool: "shell", Command: "cat /repo/.env", CWD: "/repo"},
		true,
		false,
	)
	assertSensitivePathOwnerContext(
		t,
		owner,
		actionfacts.Input{Tool: "shell", Command: "printf secret > /repo/.env", CWD: "/repo"},
		false,
		false,
	)
	assertSensitivePathOwnerContext(
		t,
		owner,
		actionfacts.Input{Tool: "shell", Command: "printf '%s\\n' '.env'", CWD: "/repo"},
		false,
		true,
	)
	assertSensitivePathOwnerContext(
		t,
		owner,
		actionfacts.Input{Tool: "shell", Command: "cat /repo/testdata/.env", CWD: "/repo"},
		false,
		true,
	)
}

func TestSSHPrivateKeyOwnerDistinguishesReadWriteAndReference(t *testing.T) {
	t.Parallel()

	owner := semanticOwnerForRule("PATH-SSH-KEY")
	context := func(command string) actionfacts.Input {
		return actionfacts.Input{
			Tool:       "shell",
			Command:    command,
			CWD:        "/repo",
			ActiveHome: "/home/alice",
		}
	}
	assertSensitivePathOwnerContext(
		t,
		owner,
		context("cat /home/alice/.ssh/id_ed25519"),
		true,
		false,
	)
	assertSensitivePathOwnerContext(
		t,
		owner,
		context("printf key > /home/alice/.ssh/id_ed25519"),
		false,
		false,
	)
	assertSensitivePathOwnerContext(
		t,
		owner,
		context("printf '%s\\n' '/home/alice/.ssh/id_ed25519'"),
		false,
		true,
	)
	assertSensitivePathOwnerContext(
		t,
		owner,
		context("cat /home/bob/.ssh/id_ed25519"),
		false,
		false,
	)
}

func assertSensitivePathOwnerContext(
	t *testing.T,
	owner semanticOwner,
	input actionfacts.Input,
	wantRead bool,
	wantSafeNegative bool,
) {
	t.Helper()
	facts := actionfacts.Analyze(input)
	if !facts.Authoritative() {
		t.Fatalf("input is not authoritative: %+v", facts)
	}
	if got := owner.prerequisite(facts); got != wantRead {
		t.Fatalf("read prerequisite=%t, want %t; facts=%+v", got, wantRead, facts)
	}
	if !wantRead {
		if got := owner.suppressFallback(facts); got != wantSafeNegative {
			t.Fatalf(
				"safe negative=%t, want %t; facts=%+v",
				got,
				wantSafeNegative,
				facts,
			)
		}
	}
}
