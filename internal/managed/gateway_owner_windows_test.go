//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// fakeOwnerToken models the gateway's process token for the default-owner
// change: the identity of fakeServiceToken plus a recorded TokenOwner.
type fakeOwnerToken struct {
	fakeServiceToken
	owner    *windows.SID
	sets     int
	setErr   error
	readback *windows.SID
}

func (token *fakeOwnerToken) setDefaultOwner(owner *windows.SID) error {
	token.sets++
	if token.setErr != nil {
		return token.setErr
	}
	token.owner = owner
	return nil
}

func (token *fakeOwnerToken) defaultOwner() (*windows.SID, error) {
	if token.readback != nil {
		return token.readback, nil
	}
	return token.owner, nil
}

func gatewayOwnerTestSIDs(t *testing.T) (service, other, localSystem, user *windows.SID) {
	t.Helper()
	var err error
	if service, err = windows.StringToSid("S-1-5-80-1858176940-1394861675-2895326486-505287571-2610476274"); err != nil {
		t.Fatal(err)
	}
	if other, err = windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"); err != nil {
		t.Fatal(err)
	}
	if localSystem, err = windows.CreateWellKnownSid(windows.WinLocalSystemSid); err != nil {
		t.Fatal(err)
	}
	if user, err = windows.StringToSid("S-1-5-21-1-2-3-1001"); err != nil {
		t.Fatal(err)
	}
	return service, other, localSystem, user
}

// A LocalSystem gateway's token defaults to SYSTEM as owner, which its
// write-restricted token cannot use to secure its own new files (the CI
// install lane failed with "reopen existing database file for ACL
// hardening: Access is denied"). The gateway must own its files as its
// service SID, and no other process may change its owner.
func TestAdoptWindowsGatewayServiceFileOwner(t *testing.T) {
	service, other, localSystem, user := gatewayOwnerTestSIDs(t)
	enabled := uint32(windows.SE_GROUP_ENABLED | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_OWNER)
	for _, test := range []struct {
		name     string
		token    fakeServiceToken
		wantSets int
	}{
		{"localsystem gateway adopts its service SID", fakeServiceToken{
			user:   localSystem,
			groups: []windows.SIDAndAttributes{{Sid: service, Attributes: enabled}},
		}, 1},
		{"virtual account already owns as the service SID", fakeServiceToken{user: service}, 0},
		{"localsystem without the gateway service SID", fakeServiceToken{user: localSystem}, 0},
		{"localsystem with another service SID", fakeServiceToken{
			user:   localSystem,
			groups: []windows.SIDAndAttributes{{Sid: other, Attributes: enabled}},
		}, 0},
		{"interactive user carrying the service SID", fakeServiceToken{
			user:   user,
			groups: []windows.SIDAndAttributes{{Sid: service, Attributes: enabled}},
		}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := &fakeOwnerToken{fakeServiceToken: test.token}
			if err := adoptWindowsGatewayServiceFileOwner(token, service); err != nil {
				t.Fatalf("adopt: %v", err)
			}
			if token.sets != test.wantSets {
				t.Fatalf("default owner set %d times, want %d", token.sets, test.wantSets)
			}
			if test.wantSets > 0 && !token.owner.Equals(service) {
				t.Fatalf("default owner = %v, want service SID %v", token.owner, service)
			}
		})
	}

	gateway := fakeServiceToken{
		user:   localSystem,
		groups: []windows.SIDAndAttributes{{Sid: service, Attributes: enabled}},
	}
	if err := adoptWindowsGatewayServiceFileOwner(
		&fakeOwnerToken{fakeServiceToken: gateway, setErr: windows.ERROR_ACCESS_DENIED}, service,
	); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("a refused owner change must fail closed, got %v", err)
	}
	if err := adoptWindowsGatewayServiceFileOwner(
		&fakeOwnerToken{fakeServiceToken: gateway, readback: localSystem}, service,
	); err == nil {
		t.Fatal("an owner that does not read back as the service SID was accepted")
	}
}

func TestWindowsCurrentProcessOwnerSID(t *testing.T) {
	// TrustedInstaller resolves on every Windows host, so the pin is real.
	t.Setenv(WindowsServiceAccountEnv, `NT SERVICE\TrustedInstaller`)
	service, err := windowsVirtualServiceSID(`NT SERVICE\TrustedInstaller`)
	if err != nil {
		t.Fatal(err)
	}
	_, _, localSystem, user := gatewayOwnerTestSIDs(t)
	enabled := uint32(windows.SE_GROUP_ENABLED | windows.SE_GROUP_ENABLED_BY_DEFAULT | windows.SE_GROUP_OWNER)
	original := windowsCurrentProcessIdentityToken
	t.Cleanup(func() { windowsCurrentProcessIdentityToken = original })

	for _, test := range []struct {
		name  string
		token fakeServiceToken
		want  *windows.SID
	}{
		{"localsystem gateway owns as its service SID", fakeServiceToken{
			user:   localSystem,
			groups: []windows.SIDAndAttributes{{Sid: service, Attributes: enabled}},
		}, service},
		{"other localsystem service stays SYSTEM", fakeServiceToken{user: localSystem}, localSystem},
		{"user process stays the user", fakeServiceToken{
			user:   user,
			groups: []windows.SIDAndAttributes{{Sid: service, Attributes: enabled}},
		}, user},
	} {
		t.Run(test.name, func(t *testing.T) {
			windowsCurrentProcessIdentityToken = test.token
			got, err := WindowsCurrentProcessOwnerSID()
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equals(test.want) {
				t.Fatalf("owner SID = %v, want %v", got, test.want)
			}
		})
	}

	t.Setenv(WindowsServiceAccountEnv, "")
	windowsCurrentProcessIdentityToken = fakeServiceToken{
		user:   localSystem,
		groups: []windows.SIDAndAttributes{{Sid: service, Attributes: enabled}},
	}
	if got, err := WindowsCurrentProcessOwnerSID(); err != nil || !got.Equals(localSystem) {
		t.Fatalf("without a gateway pin owner SID = %v, %v; want SYSTEM", got, err)
	}
}
