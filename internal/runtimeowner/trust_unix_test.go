//go:build !windows

package runtimeowner

import (
	"errors"
	"os/user"
	"testing"
)

func TestValidatedSudoUIDRequiresMatchingAccount(t *testing.T) {
	env := map[string]string{"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "operator"}
	getenv := func(key string) string { return env[key] }
	lookup := func(string) (*user.User, error) {
		return &user.User{Username: "operator", Uid: "501", Gid: "20"}, nil
	}
	uid, ok := validatedSudoUID(getenv, lookup)
	if !ok || uid != 501 {
		t.Fatalf("validatedSudoUID() = (%d, %v), want (501, true)", uid, ok)
	}
	env["SUDO_GID"] = "21"
	if _, ok := validatedSudoUID(getenv, lookup); ok {
		t.Fatal("mismatched sudo account metadata was trusted")
	}
	if _, ok := validatedSudoUID(getenv, func(string) (*user.User, error) {
		return nil, errors.New("missing")
	}); ok {
		t.Fatal("missing sudo account was trusted")
	}
}

func TestTrustedRootRejectsUnrelatedOwner(t *testing.T) {
	env := map[string]string{"SUDO_UID": "501", "SUDO_GID": "20", "SUDO_USER": "operator"}
	getenv := func(key string) string { return env[key] }
	lookup := func(string) (*user.User, error) {
		return &user.User{Username: "operator", Uid: "501", Gid: "20"}, nil
	}
	if !trusted(0, 0, 0, getenv, lookup) {
		t.Fatal("root-owned runtime state was rejected")
	}
	if !trusted(501, 0, 0, getenv, lookup) {
		t.Fatal("validated sudo invoker was rejected")
	}
	if trusted(502, 0, 0, getenv, lookup) {
		t.Fatal("unrelated runtime owner was trusted by root")
	}
	env["SUDO_GID"] = "21"
	if trusted(501, 0, 0, getenv, lookup) {
		t.Fatal("mismatched sudo identity was trusted by root")
	}
}

func TestTrustedNonRootAcceptsOnlyRootOrSelf(t *testing.T) {
	getenv := func(string) string { return "" }
	lookup := func(string) (*user.User, error) { return nil, errors.New("unused") }
	if !trusted(0, 501, 501, getenv, lookup) || !trusted(501, 501, 501, getenv, lookup) {
		t.Fatal("non-root process rejected root or its own runtime state")
	}
	if trusted(502, 501, 501, getenv, lookup) {
		t.Fatal("non-root process trusted an unrelated runtime owner")
	}
}
