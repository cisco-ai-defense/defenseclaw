// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package accountjoin

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// vectorSecret is the published test secret: the bytes 0x00..0x1f.
func vectorSecret() []byte {
	b := make([]byte, SecretBytes)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func vectorSecretText() []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(vectorSecret()))
}

func mustKey(t *testing.T, gen uint32, tenant, c string) string {
	t.Helper()
	key, err := Key(vectorSecret(), gen, tenant, c)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The published vectors (docs-site enterprise/account-join-key.mdx). The
// cloud implementation must give the same keys.
func TestPublishedVectors(t *testing.T) {
	for _, v := range []struct {
		gen             uint32
		tenant, c, want string
	}{
		{1, "contoso-prod", "sid:S-1-5-21-1004336348-1177238915-682003330-1105", vectorSID},
		{1, "contoso-prod", "upn:alice@contoso.com", vectorUPN},
		{2, "contoso-prod", "upn:alice@contoso.com", vectorUPNGen2},
	} {
		if got := mustKey(t, v.gen, v.tenant, v.c); got != v.want {
			t.Errorf("Key(gen %d, %q, %q) = %q, want %q", v.gen, v.tenant, v.c, got, v.want)
		}
	}
}

const (
	vectorSID     = "ak1:1:fc6093568064ee498f85407a3a3afa63"
	vectorUPN     = "ak1:1:a2f018c3bbe491743da16cc799c63d0b"
	vectorUPNGen2 = "ak1:2:ed70fcab4483d61004b5768ff3db16b3"
)

// The same identifier gives the same key on every OS: canonicalization
// removes the renderings that differ.
func TestSameIdentifierSameKeyAcrossRenderings(t *testing.T) {
	sids := []string{"S-1-5-21-1004336348-1177238915-682003330-1105", "s-1-5-21-1004336348-1177238915-682003330-1105", "S-1-5-21-01004336348-1177238915-0682003330-01105"}
	upns := []string{"alice@contoso.com", "Alice@Contoso.COM", "ALICE@CONTOSO.COM"}
	for _, group := range [][]Account{
		{{SID: sids[0]}, {SID: sids[1]}, {SID: sids[2]}},
		{{UPN: upns[0]}, {UPN: upns[1]}, {UPN: upns[2]}},
		{{UPN: "josé@contoso.com"}, {UPN: "josé@contoso.com"}, {UPN: "JOSÉ@CONTOSO.COM"}},
	} {
		want := ""
		for _, account := range group {
			c, err := Canonical(account)
			if err != nil {
				t.Fatalf("%+v: %v", account, err)
			}
			if key := mustKey(t, 1, "contoso-prod", c); want == "" {
				want = key
			} else if key != want {
				t.Fatalf("%+v: %s, want %s", account, key, want)
			}
		}
	}
}

func TestInputIsUnambiguous(t *testing.T) {
	if mustKey(t, 1, "ab", "upn:c@d") == mustKey(t, 1, "a", "bupn:c@d") {
		t.Fatal("a different split of the same bytes must give another key")
	}
	if mustKey(t, 1, "t", "sid:S-1-5-21-1-2-3-1000") == mustKey(t, 1, "t", "upn:S-1-5-21-1-2-3-1000") {
		t.Fatal("the sid: and upn: tags must give other keys")
	}
	if mustKey(t, 1, "t", "upn:a@b") == mustKey(t, 2, "t", "upn:a@b") {
		t.Fatal("generations must give other keys")
	}
	other := vectorSecret()
	other[0] ^= 1
	k2, _ := Key(other, 1, "t", "upn:a@b")
	if k2 == mustKey(t, 1, "t", "upn:a@b") {
		t.Fatal("another tenant secret must give another key")
	}
	if !strings.HasPrefix(mustKey(t, 7, "t", "upn:a@b"), "ak1:7:") || len(mustKey(t, 7, "t", "upn:a@b")) != len("ak1:7:")+32 {
		t.Fatal("key format")
	}
}

func TestCanonicalization(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"Alice@Contoso.com", "alice@contoso.com"},
		// U+0130 has only a full and a Turkic folding: unchanged.
		{"İSTANBUL@contoso.com", "İstanbul@contoso.com"},
		// U+0131 (dotless i) has no folding.
		{"ı@contoso.com", "ı@contoso.com"},
		// Kelvin sign and long s fold to k and s; final sigma to sigma.
		{"Kelvinſ@contoso.com", "kelvins@contoso.com"},
		{"Σς@contoso.com", "σσ@contoso.com"},
		// Decomposed e + combining acute is composed first.
		{"José@contoso.com", "josé@contoso.com"},
	} {
		got, err := CanonicalUPN(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("CanonicalUPN(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "alice", "@contoso.com", "alice@", "a@b@c", "al ice@contoso.com", "a\x00@b", "\xff@b"} {
		if _, err := CanonicalUPN(bad); err == nil || ReasonOf(err) != ReasonCanonicalizationFailed {
			t.Errorf("CanonicalUPN(%q) must fail with canonicalization_failed, got %v", bad, err)
		}
	}
	if got, err := CanonicalSID("s-1-5-21-001-02-3-01000"); err != nil || got != "S-1-5-21-1-2-3-1000" {
		t.Fatalf("CanonicalSID: %q %v", got, err)
	}
	for _, bad := range []string{"S-1-5-32-544", "S-1-5-18", "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3", "S-1-5-21-1-2-3-4-1000", "S-2-5-21-1-2-3-1000",
		"S-1-5-21-1-2-3-x", "S-1-5-21-1-2-3-99999999999", "S-1-5-21-1-2-3-+1000", "X-1-5-21-1-2-3-1000"} {
		if _, err := CanonicalSID(bad); err == nil {
			t.Errorf("CanonicalSID(%q) must fail", bad)
		}
	}
}

func TestNoDirectoryIdentifierGivesNoKey(t *testing.T) {
	if _, err := Canonical(Account{}); ReasonOf(err) != ReasonNoDirectoryID {
		t.Fatalf("an account with neither identifier: %v", err)
	}
	if c, err := Canonical(Account{SID: "S-1-5-21-1-2-3-1000", UPN: "a@b"}); err != nil || !strings.HasPrefix(c, "sid:") {
		t.Fatalf("the SID comes first: %q %v", c, err)
	}
}

func TestSecretFormat(t *testing.T) {
	if secret, err := ParseSecret(vectorSecretText()); err != nil || hex.EncodeToString(secret) != hex.EncodeToString(vectorSecret()) {
		t.Fatalf("valid secret: %v", err)
	}
	padded := []byte(base64.URLEncoding.EncodeToString(vectorSecret()) + "\n")
	if _, err := ParseSecret(padded); err != nil {
		t.Fatalf("padded secret with a newline: %v", err)
	}
	for name, value := range map[string][]byte{
		"short":        []byte(base64.RawURLEncoding.EncodeToString(vectorSecret()[:31])),
		"long":         []byte(base64.RawURLEncoding.EncodeToString(append(vectorSecret(), 0))),
		"std alphabet": []byte(base64.StdEncoding.EncodeToString(append([]byte{0xfb, 0xff}, vectorSecret()[:30]...))),
		"not base64":   []byte("not a secret value at all, not even close!!"),
		"hex":          []byte(hex.EncodeToString(vectorSecret())),
	} {
		if _, err := ParseSecret(value); err == nil || ReasonOf(err) != ReasonSecretMalformed {
			t.Errorf("%s: want secret_malformed, got %v", name, err)
		}
	}
	if _, err := ParseSecret(nil); ReasonOf(err) != ReasonSecretMissing {
		t.Fatalf("empty: %v", err)
	}
}

func generations(now time.Time) Generations {
	return Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Highest: 3}
}

func sha(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func TestRotationStateMachine(t *testing.T) {
	now := time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC)
	nextSecret := func() []byte {
		b := vectorSecret()
		b[31] = 0xee
		return []byte(base64.RawURLEncoding.EncodeToString(b))
	}
	gens := func(slots []Slot) []uint32 {
		out := []uint32{}
		for _, s := range slots {
			out = append(out, s.Generation)
		}
		return out
	}
	for _, tc := range []struct {
		name        string
		g           Generations
		want        []uint32
		reasons     string
		wantHighest uint32
	}{
		{"current only", generations(now), []uint32{3}, "", 3},
		{"overlap", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Next: 4, NextSecret: nextSecret(), NextSHA256: sha(nextSecret()), NextNotAfter: now.Add(24 * time.Hour), Highest: 3}, []uint32{3, 4}, "", 3},
		{"promotion", Generations{Current: 4, CurrentSecret: nextSecret(), CurrentSHA256: sha(nextSecret()), Highest: 3}, []uint32{4}, "", 4},
		{"next removed without promotion", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Next: 4, Highest: 3}, []uint32{3}, "", 3},
		{"next expired", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Next: 4, NextSecret: nextSecret(), NextSHA256: sha(nextSecret()), NextNotAfter: now, Highest: 3}, []uint32{3}, ReasonNextGenerationExpired, 3},
		{"next overlap beyond 30 days", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Next: 4, NextSecret: nextSecret(), NextSHA256: sha(nextSecret()), NextNotAfter: now.Add(31 * 24 * time.Hour), Highest: 3}, []uint32{3}, ReasonGenerationInvalid, 3},
		{"next not above current", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Next: 3, NextSecret: nextSecret(), NextSHA256: sha(nextSecret()), NextNotAfter: now.Add(time.Hour), Highest: 3}, []uint32{3}, ReasonGenerationInvalid, 3},
		{"lower generation refused", Generations{Current: 2, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Highest: 3}, []uint32{}, ReasonGenerationRollback, 3},
		{"missing secret", Generations{Current: 3, Highest: 3}, []uint32{}, ReasonSecretMissing, 3},
		{"malformed secret, no fallback to next", Generations{Current: 3, CurrentSecret: []byte("short"), CurrentSHA256: sha([]byte("short")), Next: 4, NextSecret: nextSecret(), NextSHA256: sha(nextSecret()), NextNotAfter: now.Add(time.Hour)}, []uint32{4}, ReasonSecretMalformed, 0},
		{"no generation", Generations{CurrentSecret: vectorSecretText()}, []uint32{}, ReasonGenerationInvalid, 0},
		{"current secret is not the signed value", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(nextSecret()), Highest: 3}, []uint32{}, ReasonSecretMismatch, 3},
		{"half-applied promotion: config at 4, old secret stored", Generations{Current: 4, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(nextSecret()), Highest: 3}, []uint32{}, ReasonSecretMismatch, 3},
		{"next secret is not the signed value", Generations{Current: 3, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText()), Next: 4, NextSecret: nextSecret(), NextSHA256: sha(vectorSecretText()), NextNotAfter: now.Add(time.Hour), Highest: 3}, []uint32{3}, ReasonSecretMismatch, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			slots, reasons, highest := Plan(tc.g, now)
			if got := gens(slots); strings.Join(strings.Fields(strings.Trim(strings.Replace(jsonText(got), ",", " ", -1), "[]")), ",") != strings.Join(strings.Fields(strings.Trim(strings.Replace(jsonText(tc.want), ",", " ", -1), "[]")), ",") {
				t.Fatalf("generations %v, want %v", got, tc.want)
			}
			if strings.Join(reasons, ",") != tc.reasons {
				t.Fatalf("reasons %v, want %q", reasons, tc.reasons)
			}
			if highest != tc.wantHighest {
				t.Fatalf("highest %d, want %d", highest, tc.wantHighest)
			}
		})
	}
}

func jsonText(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

func TestComputeOffSecureClientAndRetention(t *testing.T) {
	now := time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC)
	accounts := []Account{{UPN: "alice@contoso.com", LastSeen: now.Add(-time.Hour)}}
	for _, in := range []Input{
		{On: false, Tenant: "t", Generations: generations(now), Accounts: accounts, Now: now},
		{On: true, SecureClient: true, Tenant: "t", Generations: generations(now), Accounts: accounts, Now: now},
	} {
		report, _ := Compute(in)
		if report.State != "off" || len(report.Generations) != 0 || jsonText(report.ReasonCodes) != `["feature_off"]` {
			t.Fatalf("off: %+v", report)
		}
	}
	// Enrollment: a new account that ran an agent gets a key; refresh: one
	// not seen for 30 days drops out; a local account (no identifier) counts
	// without a key.
	report, highest := Compute(Input{On: true, Tenant: "Contoso-Prod", Generations: generations(now), Now: now, Accounts: []Account{
		{UPN: "alice@contoso.com", LastSeen: now.Add(-time.Hour)},
		{SID: "S-1-5-21-1-2-3-1000", LastSeen: now.Add(-2 * time.Hour)},
		{UPN: "old@contoso.com", LastSeen: now.Add(-Retention - time.Minute)},
		{LastSeen: now},
	}})
	if report.State != "on" || len(report.Generations) != 1 || len(report.Generations[0].AccountKeys) != 2 || report.AccountsWithoutKey != 1 ||
		jsonText(report.ReasonCodes) != `["no_directory_id"]` || highest != 3 {
		t.Fatalf("report: %+v highest %d", report, highest)
	}
	want, _ := Key(vectorSecret(), 3, "contoso-prod", "upn:alice@contoso.com")
	if !strings.Contains(jsonText(report), want) {
		t.Fatalf("alice's key %s missing from %s", want, jsonText(report))
	}
	// The cap keeps the most recently seen.
	var many []Account
	for i := 0; i < MaxAccounts+5; i++ {
		many = append(many, Account{UPN: "u" + strings.Repeat("x", i) + "@contoso.com", LastSeen: now.Add(-time.Duration(i) * time.Minute)})
	}
	report, _ = Compute(Input{On: true, Tenant: "t", Generations: generations(now), Accounts: many, Now: now})
	if len(report.Generations[0].AccountKeys) != MaxAccounts || !strings.Contains(jsonText(report.ReasonCodes), ReasonAccountCap) {
		t.Fatalf("cap: %d keys, %v", len(report.Generations[0].AccountKeys), report.ReasonCodes)
	}
	if report, _ := Compute(Input{On: true, Tenant: "", Generations: generations(now), Accounts: accounts, Now: now}); report.State != "unavailable" || jsonText(report.ReasonCodes) != `["tenant_missing"]` {
		t.Fatalf("no tenant: %+v", report)
	}
}

// No report, error or reason carries the secret (raw, hex or base64), the
// identifiers or the canonical input.
func TestNothingEchoesTheSecretOrTheInput(t *testing.T) {
	now := time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC)
	canarySID := "S-1-5-21-424242-434343-444444-4545"
	canaryUPN := "canary.person@canary-domain.example"
	canaries := []string{string(vectorSecretText()), hex.EncodeToString(vectorSecret()), base64.StdEncoding.EncodeToString(vectorSecret()),
		canarySID, "424242", canaryUPN, "canary.person", "canary-domain", "canary-tenant"}
	var outputs []string
	report, _ := Compute(Input{On: true, Tenant: "canary-tenant", Generations: Generations{Current: 1, CurrentSecret: vectorSecretText(), CurrentSHA256: sha(vectorSecretText())}, Now: now,
		Accounts: []Account{{SID: canarySID, LastSeen: now}, {UPN: canaryUPN, LastSeen: now}, {UPN: "bad " + canaryUPN, LastSeen: now}, {SID: canarySID + "-x", LastSeen: now}}})
	outputs = append(outputs, jsonText(report))
	for _, value := range []string{canaryUPN + "@x", "bad " + canaryUPN} {
		_, err := CanonicalUPN(value)
		outputs = append(outputs, err.Error())
	}
	_, err := CanonicalSID(canarySID + "-1")
	outputs = append(outputs, err.Error())
	_, err = ParseSecret(append(vectorSecretText(), 'A', 'A'))
	outputs = append(outputs, err.Error())
	_, err = CanonicalTenant("canary-tenant!")
	outputs = append(outputs, err.Error())
	for _, out := range outputs {
		for _, canary := range canaries {
			if strings.Contains(out, canary) {
				t.Fatalf("output %q carries %q", out, canary)
			}
		}
	}
}

func TestSummaryCarriesNoKey(t *testing.T) {
	now := time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC)
	report, _ := Compute(Input{On: true, Tenant: "t", Generations: generations(now), Now: now, Accounts: []Account{{UPN: "a@b", LastSeen: now}}})
	summary := jsonText(report.Summary())
	if strings.Contains(summary, "ak1:") || !strings.Contains(summary, `"key_count":1`) {
		t.Fatalf("summary: %s", summary)
	}
}
