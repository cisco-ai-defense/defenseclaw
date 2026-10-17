// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

type testTrustedCMIDLibrary struct {
	events   *[]string
	closeErr error
}

func (library *testTrustedCMIDLibrary) Close() error {
	*library.events = append(*library.events, "close")
	return library.closeErr
}

func (*testTrustedCMIDLibrary) Signer() cmidbroker.LibrarySigner {
	return cmidbroker.LibrarySigner{CommonName: cmidbroker.CMIDLibraryPublisher}
}

type testVerifiedCMIDProvider struct {
	events     *[]string
	refreshErr error
}

func (*testVerifiedCMIDProvider) Token(context.Context) (string, error) { return "", nil }
func (*testVerifiedCMIDProvider) Invalidate()                           {}
func (provider *testVerifiedCMIDProvider) Refresh(context.Context) error {
	*provider.events = append(*provider.events, "refresh")
	return provider.refreshErr
}

func TestDeferredCMIDProviderBuildsOnlyWhileVerifiedLibraryIsLeased(t *testing.T) {
	var events []string
	lease := &testTrustedCMIDLibrary{events: &events}
	built := &testVerifiedCMIDProvider{events: &events}
	provider, signer, err := constructVerifiedCMIDProvider(
		context.Background(), `C:\Cisco\cmidapi.dll`,
		func(string) (trustedCMIDLibrary, error) {
			events = append(events, "verify-and-open")
			return lease, nil
		},
		func(string) (cmidbroker.Provider, error) {
			events = append(events, "construct")
			return built, nil
		},
	)
	if err != nil || provider != built || signer.CommonName != cmidbroker.CMIDLibraryPublisher {
		t.Fatalf("verified construction = (%v, %+v, %v)", provider, signer, err)
	}
	if want := []string{"verify-and-open", "construct", "refresh", "close"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("steps = %v, want %v", events, want)
	}
}

func TestDeferredCMIDProviderNeverBuildsAnUnverifiedLibrary(t *testing.T) {
	var built bool
	provider, _, err := constructVerifiedCMIDProvider(
		context.Background(), `C:\Cisco\cmidapi.dll`,
		func(string) (trustedCMIDLibrary, error) { return nil, cmidbroker.ErrLibrarySigner },
		func(string) (cmidbroker.Provider, error) {
			built = true
			return &testVerifiedCMIDProvider{}, nil
		},
	)
	if provider != nil || !errors.Is(err, cmidbroker.ErrLibrarySigner) || built {
		t.Fatalf("untrusted library result = (%v, %v), built=%v", provider, err, built)
	}
}

func TestDeferredCMIDProviderRequiresSuccessfulRefreshUnderLease(t *testing.T) {
	var events []string
	provider, _, err := constructVerifiedCMIDProvider(
		context.Background(), `C:\Cisco\cmidapi.dll`,
		func(string) (trustedCMIDLibrary, error) {
			events = append(events, "verify-and-open")
			return &testTrustedCMIDLibrary{events: &events}, nil
		},
		func(string) (cmidbroker.Provider, error) {
			events = append(events, "construct")
			return &testVerifiedCMIDProvider{events: &events, refreshErr: errors.New("native refresh unavailable")}, nil
		},
	)
	if provider != nil || err == nil {
		t.Fatalf("failed native refresh adopted a provider: %v, %v", provider, err)
	}
	if want := []string{"verify-and-open", "construct", "refresh", "close"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("steps = %v, want %v", events, want)
	}
}
