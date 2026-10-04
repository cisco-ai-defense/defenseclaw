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

package cli

import (
	"strings"
	"testing"
)

// GAP-1735: the purge result names the binaries it removed, or says there
// were none, instead of always claiming per-user binaries.
func TestWindowsEnterprisePurgedUserStateNamesWhatWent(t *testing.T) {
	const account = `dcw-std1 (S-1-5-21-1-2-3-1017): C:\Users\dcw-std1\.defenseclaw`
	none := windowsEnterprisePurgedUserStateChange(windowsManagedHooksPurgedLabel(account, nil))
	if !strings.HasPrefix(none, "removed all DefenseClaw per-user data of "+account+" (") ||
		!strings.HasSuffix(none, `; its %USERPROFILE%\.local\bin held no DefenseClaw binaries`) {
		t.Fatalf("no binaries: %q", none)
	}
	some := windowsEnterprisePurgedUserStateChange(windowsManagedHooksPurgedLabel(account, []string{
		`C:\Users\dcw-std1\.local\bin\defenseclaw.cmd`,
		`C:\Users\dcw-std1\.local\bin\defenseclaw-gateway.exe`,
		`C:\Users\dcw-std1\.local\bin`,
		`Path entry C:\Users\dcw-std1\.local\bin`,
	}))
	if !strings.HasSuffix(some, `from its %USERPROFILE%\.local\bin: defenseclaw.cmd, defenseclaw-gateway.exe, the emptied folder, its user Path entry`) {
		t.Fatalf("binaries: %q", some)
	}
	if old := windowsEnterprisePurgedUserStateChange(account); !strings.Contains(old, "and any DefenseClaw per-user binaries") {
		t.Fatalf("entry without the marker: %q", old)
	}
}

// GAP-1756 and GAP-1720: the remedies name an active (connected) session,
// and a standard user's status is a refusal with the administrator's step,
// not installer internals.
func TestWindowsEnterpriseSessionAndStandardUserWording(t *testing.T) {
	remedy := windowsEnterpriseLocalSystemRemedy("/uninstall")
	if strings.Contains(remedy, "while the accounts are signed in") || !strings.Contains(remedy, "active (connected) session") {
		t.Fatalf("remedy = %q", remedy)
	}
	restore := managedHostCurrentAccount
	t.Cleanup(func() { managedHostCurrentAccount = restore })
	managedHostCurrentAccount = func() string { return `HOST\dcw-std1` }
	answer := windowsEnterpriseStandardUserInspectionAnswer("status")
	// GAP-2262: the account is named as the discovery view names it.
	for _, want := range []string{"needs an elevated prompt", "enterprise windows status --profile standalone", "--user dcw-std1`", "Nothing was changed."} {
		if !strings.Contains(answer, want) {
			t.Fatalf("answer lacks %q: %q", want, answer)
		}
	}
	if !strings.HasSuffix(answer, "Nothing was changed.") {
		t.Fatalf("answer does not end as a sentence: %q", answer)
	}
	if strings.Contains(answer, "AllowUnsigned") || strings.Contains(answer, "Authenticode") {
		t.Fatalf("answer leaks installer internals: %q", answer)
	}
}

// GAP-2011: the administrator's command keeps the attestation the standard
// user asked for, so running it makes security_complete true.
func TestWindowsEnterpriseStandardUserMutationAnswerKeepsAttestation(t *testing.T) {
	answer := windowsEnterpriseStandardUserMutationAnswer("repair", "--attest-claude-effective-policy")
	if !strings.Contains(answer, "enterprise windows repair --profile standalone --attest-claude-effective-policy`. Nothing was changed.") {
		t.Fatalf("answer = %q", answer)
	}
	if plain := windowsEnterpriseStandardUserMutationAnswer("repair"); !strings.Contains(plain, "repair --profile standalone`. Nothing") {
		t.Fatalf("plain answer = %q", plain)
	}
}
