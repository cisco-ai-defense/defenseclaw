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

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0201: right after the administrator pointed openshell.trusted_ca_bundle
// at a file the managed gateway refuses, doctor said no image may be built,
// yet the next run started from the image of the CAs before: a create
// trusted the settings the daemon read less than sandboxDaemonSettingsTTL
// ago. A create reads them from the managed gateway every time, so the
// refusal reaches the image choice at once; and a failed read refuses the
// create before the run is resolved.
func TestACreateReadsTheAdministratorsTrustedCAsNow(t *testing.T) {
	ca := openshelltest.NewCA(t, "Corp Root CA")
	f := newSandboxDaemonFixture(t)
	f.d.settingsMu.Lock()
	f.d.settings.Operational.TrustedCAs = string(ca.PEM)
	f.d.settingsMu.Unlock()
	f.d.reloadConfig()
	f.d.settingsAt.Store(time.Now().UnixNano())
	if pem, err := image.TrustedCAsFor(f.d.config()); err != nil || string(pem) != string(ca.PEM) {
		t.Fatalf("before the change: %q, %v", pem, err)
	}
	reads := 0
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		reads++
		s := f.d.currentSettings()
		s.Operational.TrustedCAs, s.Operational.TrustedCAError = "", "/opt/corp/ca.pem: owned by uid 501, not by root"
		return s, nil
	}
	s, err := f.d.createSettings(context.Background())
	if err != nil || reads != 1 || s.Operational.TrustedCAError == "" {
		t.Fatalf("create settings: %+v, %v (reads %d)", s.Operational, err, reads)
	}
	if _, err := image.TrustedCAsFor(f.d.config()); err == nil || !strings.Contains(err.Error(), "owned by uid 501") {
		t.Fatalf("the image choice after the change: %v", err)
	}

	// The whole create: a failed read refuses it before the managed
	// gateway resolves the run.
	f.relay.settings = func() (sandboxrelay.DaemonSettings, error) {
		return sandboxrelay.DaemonSettings{}, errors.New("connection refused")
	}
	resolved := false
	f.relay.resolve = func(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
		resolved = true
		return sandboxrelay.ResolveResponse{}, errors.New("unexpected resolve")
	}
	f.run(t)
	f.d.settingsAt.Store(time.Now().UnixNano())
	client := sandboxapi.NewUnixClient(f.socket)
	_, err = client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode", Project: t.TempDir(), Copy: true})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || resolved {
		t.Fatalf("create with the settings unreadable: %v (resolved %v)", err, resolved)
	}
}
