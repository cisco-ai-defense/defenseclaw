// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package devicekeys

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/accountjoin"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func secretText(last byte) []byte {
	b := make([]byte, accountjoin.SecretBytes)
	for i := range b {
		b[i] = byte(i)
	}
	b[31] = last
	return []byte(base64.RawURLEncoding.EncodeToString(b))
}

type device struct {
	t       *testing.T
	spool   string
	state   string
	secrets map[string][]byte
	cfg     config.EnterpriseAccountJoinConfig
	now     time.Time
	goos    string
}

func newDevice(t *testing.T) *device {
	t.Helper()
	root := t.TempDir()
	d := &device{t: t, spool: filepath.Join(root, "spool"), state: filepath.Join(root, StateFileName),
		secrets: map[string][]byte{accountjoin.SecretName: secretText(0x1f)},
		cfg:     config.EnterpriseAccountJoinConfig{Mode: config.AccountJoinOn, Generation: 1},
		now:     time.Date(2026, 10, 31, 22, 0, 0, 0, time.UTC), goos: "linux"}
	if err := os.MkdirAll(d.spool, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// enroll writes the identity spool record the guardian writes for an
// account that ran an agent.
func (d *device) enroll(key, upn, upnSource, sid string, seen time.Time) {
	d.t.Helper()
	data, err := enterprisehooks.MarshalIdentitySpoolRecord(enterprisehooks.IdentitySpoolRecord{
		Version: 1, Key: key, UpdatedAt: seen, UPNSource: upnSource, AccountSID: sid,
		Facts: useridentity.DirectoryFacts{UPN: upn},
	})
	if err != nil {
		d.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.spool, key+".json"), data, 0o600); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) report() *accountjoin.Report {
	return Report(Sources{
		Config: d.cfg,
		Tenant: func() (string, error) { return "Contoso-Prod", nil },
		ReadSecret: func(name string) ([]byte, error) {
			value, ok := d.secrets[name]
			if !ok {
				return nil, managed.ErrNoServiceCredential
			}
			if value == nil {
				return nil, errors.New("access denied")
			}
			return append([]byte(nil), value...), nil
		},
		SpoolDir: d.spool, SpoolTrust: func(string, string) error { return nil },
		StatePath: d.state, GOOS: d.goos, Now: d.now,
	})
}

func keyOf(t *testing.T, gen uint32, c string, last byte) string {
	t.Helper()
	secret, err := accountjoin.ParseSecret(secretText(last))
	if err != nil {
		t.Fatal(err)
	}
	key, err := accountjoin.Key(secret, gen, "contoso-prod", c)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func text(v any) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// Enrollment: an account the guardian recorded gets its key at the next
// status, from its verified SID first, else its verified UPN; a derived UPN
// gives none.
func TestEnrolledAccountsGetKeys(t *testing.T) {
	d := newDevice(t)
	if report := d.report(); report == nil || report.State != "on" || len(report.Generations[0].AccountKeys) != 0 {
		t.Fatalf("no accounts yet: %s", text(report))
	}
	d.enroll("1001", "alice@contoso.com", enterprisehooks.UPNSourceInfoPipe, "S-1-5-21-1-2-3-1105", d.now.Add(-time.Hour))
	d.enroll("1002", "bob@contoso.com", enterprisehooks.UPNSourceInfoPipe, "", d.now.Add(-time.Hour))
	d.enroll("1003", "carol@CONTOSO.COM", enterprisehooks.UPNSourceDerived, "", d.now.Add(-time.Hour))
	report := d.report()
	got := text(report)
	for _, want := range []string{keyOf(t, 1, "sid:S-1-5-21-1-2-3-1105", 0x1f), keyOf(t, 1, "upn:bob@contoso.com", 0x1f)} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing key %s in %s", want, got)
		}
	}
	if report.AccountsWithoutKey != 1 || text(report.ReasonCodes) != `["no_directory_id"]` {
		t.Fatalf("a derived UPN gets no key: %s", got)
	}
	for _, canary := range []string{"alice", "bob", "carol", "contoso.com", "S-1-5-21", "1001", string(secretText(0x1f))} {
		if strings.Contains(got, canary) {
			t.Fatalf("the block carries %q: %s", canary, got)
		}
	}
}

// Refresh: each status recomputes the keys; an account unseen for 30 days
// drops out, a rotation reports both generations within its overlap, and a
// lower generation than one reported before is refused.
func TestRefreshRetentionRotationAndRollback(t *testing.T) {
	d := newDevice(t)
	d.enroll("1001", "alice@contoso.com", enterprisehooks.UPNSourceInfoPipe, "", d.now.Add(-time.Hour))
	d.enroll("1002", "old@contoso.com", enterprisehooks.UPNSourceInfoPipe, "", d.now.Add(-accountjoin.Retention-time.Hour))
	if report := d.report(); len(report.Generations[0].AccountKeys) != 1 || !strings.Contains(text(report), keyOf(t, 1, "upn:alice@contoso.com", 0x1f)) {
		t.Fatalf("retention: %s", text(report))
	}
	d.secrets[accountjoin.NextSecretName] = secretText(0xee)
	d.cfg.NextGeneration, d.cfg.NextNotAfter = 2, d.now.Add(7*24*time.Hour).Format(time.RFC3339)
	report := d.report()
	if len(report.Generations) != 2 || report.Generations[1].Generation != 2 ||
		report.Generations[1].AccountKeys[0] != keyOf(t, 2, "upn:alice@contoso.com", 0xee) {
		t.Fatalf("overlap: %s", text(report))
	}
	// Promotion: the next secret becomes the current one.
	d.secrets[accountjoin.SecretName] = secretText(0xee)
	delete(d.secrets, accountjoin.NextSecretName)
	d.cfg = config.EnterpriseAccountJoinConfig{Mode: config.AccountJoinOn, Generation: 2}
	if report := d.report(); len(report.Generations) != 1 || report.Generations[0].Generation != 2 {
		t.Fatalf("promotion: %s", text(report))
	}
	// Going back to generation 1 is refused.
	d.secrets[accountjoin.SecretName] = secretText(0x1f)
	d.cfg.Generation = 1
	if report := d.report(); report.State != "unavailable" || len(report.Generations) != 0 || text(report.ReasonCodes) != `["generation_rollback"]` {
		t.Fatalf("rollback: %s", text(report))
	}
}

func TestOffMissingAndUnreadableSecrets(t *testing.T) {
	d := newDevice(t)
	d.enroll("1001", "alice@contoso.com", enterprisehooks.UPNSourceInfoPipe, "", d.now)
	for _, mode := range []string{"", config.AccountJoinOff} {
		d.cfg.Mode = mode
		if report := d.report(); report != nil {
			t.Fatalf("mode %q: the block must be omitted: %s", mode, text(report))
		}
	}
	d.cfg.Mode = config.AccountJoinOn
	if report := Report(Sources{Config: d.cfg, SecureClient: true}); report != nil {
		t.Fatal("Secure Client: the block must be omitted")
	}
	delete(d.secrets, accountjoin.SecretName)
	if report := d.report(); report.State != "unavailable" || text(report.ReasonCodes) != `["secret_missing"]` {
		t.Fatalf("missing: %s", text(report))
	}
	d.secrets[accountjoin.SecretName] = nil
	if report := d.report(); report.State != "unavailable" || !strings.Contains(text(report.ReasonCodes), "secret_unreadable") {
		t.Fatalf("unreadable: %s", text(report))
	}
	d.secrets[accountjoin.SecretName] = []byte("short")
	if report := d.report(); report.State != "unavailable" || text(report.ReasonCodes) != `["secret_malformed"]` {
		t.Fatalf("malformed: %s", text(report))
	}
}

// On Windows a record's SID is used only for a domain account (its UPN came
// from the directory's name translation); a local account gets no key.
func TestWindowsUsesTheSIDOfADomainAccountOnly(t *testing.T) {
	d := newDevice(t)
	d.goos = "windows"
	d.enroll("S-1-5-21-1-2-3-1105", "alice@contoso.com", enterprisehooks.UPNSourceTranslateName, "", d.now)
	d.enroll("S-1-5-21-9-9-9-1001", "", "", "", d.now)
	report := d.report()
	if len(report.Generations[0].AccountKeys) != 1 || report.Generations[0].AccountKeys[0] != keyOf(t, 1, "sid:S-1-5-21-1-2-3-1105", 0x1f) || report.AccountsWithoutKey != 1 {
		t.Fatalf("windows: %s", text(report))
	}
}
