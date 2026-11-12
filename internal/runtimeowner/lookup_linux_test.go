//go:build linux

package runtimeowner

import (
	"errors"
	"os/user"
	"strings"
	"testing"
)

const sssdEntry = "operator@dclab.test:*:1180000501:1180000513:Op Erator:/home/operator@dclab.test:/bin/bash\n"

// GAP-0714: a sudo invoker that only NSS (SSSD, LDAP, winbind) knows is
// recognised like a local account. The static gateway's os/user reads
// /etc/passwd only, so the account was unknown and a root start was refused.
func TestGAP0714SudoInvokerKnownOnlyToNSSIsTrusted(t *testing.T) {
	var asked []string
	run := func(args ...string) (int, []byte, error) {
		asked = args
		return 0, []byte(sssdEntry), nil
	}
	nssOnly := func(name string) (*user.User, error) {
		if account, ok := getentAccount(name, run); ok {
			return account, nil
		}
		return nil, user.UnknownUserError(name)
	}
	env := map[string]string{
		"SUDO_UID": "1180000501", "SUDO_GID": "1180000513", "SUDO_USER": "operator@dclab.test",
	}
	getenv := func(key string) string { return env[key] }
	if !trusted(1180000501, 0, 0, getenv, nssOnly) {
		t.Fatal("SSSD account named by sudo was not trusted")
	}
	if got := strings.Join(asked, " "); got != "passwd -- operator@dclab.test" {
		t.Fatalf("getent asked %q", got)
	}
	// Twins that stay refused: another uid, another gid, a uid NSS maps elsewhere.
	if trusted(1180000502, 0, 0, getenv, nssOnly) {
		t.Fatal("an unrelated uid was trusted")
	}
	env["SUDO_GID"] = "20"
	if trusted(1180000501, 0, 0, getenv, nssOnly) {
		t.Fatal("a mismatched gid was trusted")
	}
	env["SUDO_GID"] = "1180000513"
	env["SUDO_UID"] = "1180000999"
	if trusted(1180000999, 0, 0, getenv, nssOnly) {
		t.Fatal("a uid that NSS maps to another account was trusted")
	}
}

func TestGetentAccountRefusesUnsafeOrIncompleteAnswers(t *testing.T) {
	answer := func(code int, body string, err error) func(...string) (int, []byte, error) {
		return func(...string) (int, []byte, error) { return code, []byte(body), err }
	}
	for name, tc := range map[string]struct {
		user string
		run  func(...string) (int, []byte, error)
	}{
		"not found":       {"operator", answer(2, "", nil)},
		"tool failure":    {"operator", answer(0, "", errors.New("no getent"))},
		"short entry":     {"operator", answer(0, "operator:*:501:20\n", nil)},
		"two entries":     {"operator", answer(0, sssdEntry+sssdEntry, nil)},
		"option name":     {"-s", answer(0, sssdEntry, nil)},
		"colon name":      {"a:b", answer(0, sssdEntry, nil)},
		"empty name":      {"", answer(0, sssdEntry, nil)},
		"empty uid field": {"operator", answer(0, "operator:*::20:x:/h:/bin/sh\n", nil)},
	} {
		if account, ok := getentAccount(tc.user, tc.run); ok {
			t.Errorf("%s: accepted %+v", name, account)
		}
	}
	account, ok := getentAccount("operator@dclab.test", answer(0, sssdEntry, nil))
	if !ok || account.Uid != "1180000501" || account.Gid != "1180000513" || account.HomeDir != "/home/operator@dclab.test" {
		t.Fatalf("complete entry = %+v, %v", account, ok)
	}
}

// A name neither os/user nor NSS knows is still unknown.
func TestLookupAccountUnknownNameStaysUnknown(t *testing.T) {
	if account, err := lookupAccount("no-such-account-gap0714"); err == nil {
		t.Fatalf("unknown account resolved to %+v", account)
	}
}
