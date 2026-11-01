// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// managedExplainView makes the explain route the managed administrator view
// for a test that explains made-up accounts.
func managedExplainView(t *testing.T) {
	t.Helper()
	prev := profileExplainGatewayOwner
	profileExplainGatewayOwner = func() (string, string, bool) { return "", "", false }
	t.Cleanup(func() { profileExplainGatewayOwner = prev })
}

type explainAccountStub struct{ id, name string }

func explainAs(t *testing.T, ownerID, ownerName string, perUser bool, accounts map[string]explainAccountStub, user string) (map[string]any, []string) {
	t.Helper()
	stubProfileSources(t)
	prevLookup, prevOwner, prevAccount := profileExplainSubjectLookup, profileExplainGatewayOwner, profileExplainAccount
	t.Cleanup(func() {
		profileExplainSubjectLookup, profileExplainGatewayOwner, profileExplainAccount = prevLookup, prevOwner, prevAccount
	})
	var looked []string
	profileExplainAccount = func(name string) (string, string, error) {
		if account, ok := accounts[name]; ok {
			return account.id, account.name, nil
		}
		return "", "", errors.New("no account named " + strconv.Quote(name) + " (holder dcm-secret-holder)")
	}
	profileExplainSubjectLookup = func(name string) (profileSubject, error) {
		looked = append(looked, name)
		account, ok := accounts[name]
		if !ok {
			return profileSubject{UserName: name}, errors.New("no account named " + strconv.Quote(name))
		}
		return profileSubject{UserID: account.id, IDKind: useridentity.KindPOSIXUID, UserName: account.name, Groups: []string{"staff", "grp-of-" + account.name}}, nil
	}
	profileExplainGatewayOwner = func() (string, string, bool) { return ownerID, ownerName, perUser }
	api := NewAPIServer("127.0.0.1:0", nil, nil, nil, nil, profileSecurityConfig())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/guardrail/profiles/resolve?user="+url.QueryEscape(user)+"&connector=codex", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	rec := httptest.NewRecorder()
	api.handleGuardrailProfileResolve(rec, req)
	var out map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
	}
	return out, looked
}

// rel-1-0-6:GAP-0328: a per-user gateway explains only the account it runs
// as. Another account, by name, uid or a qualified spelling, and a name no
// account has, are refused before explain's own lookup: lookup_error, no
// user id and no groups (the CLI exits 1, as on Linux), and nothing of the
// account in the answer. The owner's uid, name and a spelling that resolves
// to its uid still resolve (GAP-0269); the owner's own failed lookup keeps
// its own error. A root or managed gateway explains every account.
func TestPerUserProfileExplainRefusesAnotherAccount(t *testing.T) {
	accounts := map[string]explainAccountStub{
		"dcm-own": {"511", "dcm-own"}, "511": {"511", "dcm-own"}, "dcm-own@corp.example.com": {"511", "dcm-own"},
		"dcm-other": {"517", "dcm-other"}, "517": {"517", "dcm-other"}, "CORP\\dcm-other": {"517", "dcm-other"},
	}
	for _, user := range []string{"dcm-other", "517", "CORP\\dcm-other", "nobody-here"} {
		out, looked := explainAs(t, "511", "dcm-own", true, accounts, user)
		subject, _ := out["subject"].(map[string]any)
		lookupErr, _ := out["lookup_error"].(string)
		if !strings.Contains(lookupErr, "only your own account") || subject["user_id"] != "" || subject["group_count"] != float64(0) || subject["user_name"] != user {
			t.Fatalf("--user %s: %v", user, out)
		}
		if len(looked) != 0 {
			t.Errorf("--user %s: explain looked the account up (%v) before refusing it", user, looked)
		}
		body, _ := json.Marshal(out)
		for _, fact := range []string{"grp-of-", "dcm-secret-holder", "\"517\""} {
			if strings.Contains(string(body), fact) && !(fact == "\"517\"" && user == "517") {
				t.Errorf("--user %s: the answer carries %s: %s", user, fact, body)
			}
		}
	}
	for _, user := range []string{"dcm-own", "511", "dcm-own@corp.example.com"} {
		out, _ := explainAs(t, "511", "dcm-own", true, accounts, user)
		if subject, _ := out["subject"].(map[string]any); out["lookup_error"] != nil || subject["user_id"] != "511" {
			t.Fatalf("own account --user %s: %v", user, out)
		}
	}
	// The owner's own name whose lookup fails reports that lookup's error.
	out, looked := explainAs(t, "511", "dcm-own-renamed", true, accounts, "dcm-own-renamed")
	if lookupErr, _ := out["lookup_error"].(string); strings.Contains(lookupErr, "only your own account") || len(looked) != 1 {
		t.Fatalf("own failed lookup: %v, looked %v", out, looked)
	}
	// A per-user gateway that cannot name its own account explains none.
	if out, _ := explainAs(t, "", "", true, accounts, "dcm-own"); out["lookup_error"] == nil {
		t.Fatalf("no gateway owner: %v", out)
	}
	// Root and managed gateways explain every account.
	if out, _ := explainAs(t, "", "", false, accounts, "dcm-other"); out["lookup_error"] != nil {
		t.Fatalf("administrator view: %v", out)
	}
}

// The production owner: the kernel uid on Linux and macOS (no os/user
// lookup, which fails for an SSSD account without cgo), none for root, and
// none on a managed gateway.
func TestProfileExplainGatewayOwnerIsTheProcessAccount(t *testing.T) {
	prev := managedServiceHosted.Load()
	t.Cleanup(func() { setManagedServiceHosted(prev) })
	setManagedServiceHosted(false)
	id, _, perUser := profileExplainGatewayOwner()
	switch {
	case runtime.GOOS == "windows":
		if !perUser || !strings.HasPrefix(id, "S-1-") {
			t.Fatalf("Windows per-user owner %q, %v", id, perUser)
		}
	case os.Getuid() == 0:
		if perUser {
			t.Fatal("a root gateway reported a per-user owner")
		}
	default:
		if !perUser || id != strconv.Itoa(os.Getuid()) {
			t.Fatalf("per-user owner %q, %v; want uid %d", id, perUser, os.Getuid())
		}
	}
	setManagedServiceHosted(true)
	if _, _, perUser := profileExplainGatewayOwner(); perUser {
		t.Fatal("a managed gateway reported a per-user owner")
	}
}
