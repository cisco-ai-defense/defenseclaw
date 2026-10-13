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

package sandboxcli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// On a standalone managed computer the commands talk to the caller's own
// sandbox daemon and never build a client from config.yaml; an untrusted
// descriptor refuses instead of falling back to the per-user gateway.
func TestAppAPIPrefersTheManagedDaemon(t *testing.T) {
	daemon := sandboxapi.NewUnixClient("/nonexistent/sandbox.sock")
	var asked string
	app := &App{GOOS: "linux", HostClient: func(goos string) (API, error) {
		asked = goos
		return daemon, nil
	}}
	got, err := app.api()
	if err != nil || got != API(daemon) || asked != "linux" {
		t.Fatalf("managed host: api = %v, %v (asked %q)", got, err, asked)
	}

	// A per-user config.yaml with a gateway token is not used there.
	cfg := config.DefaultConfig()
	cfg.Gateway.Token = "per-user-token"
	untrusted := errors.New("sandboxapi: the managed runtime descriptor is not trusted: owner")
	app = &App{GOOS: "linux", Cfg: cfg, HostClient: func(string) (API, error) { return nil, untrusted }}
	if got, err := app.api(); !errors.Is(err, untrusted) || got != nil {
		t.Fatalf("untrusted descriptor: api = %v, %v", got, err)
	}

	// Any other computer keeps the per-user gateway client.
	app = &App{GOOS: "linux", HostClient: func(string) (API, error) { return nil, sandboxapi.ErrNotManagedHost }}
	if _, err := app.api(); err == nil {
		t.Fatal("no configuration and no managed host: api succeeded")
	}
}
