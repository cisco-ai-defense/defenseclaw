// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// With no UserUnitSource the lifecycle installs the units this build embeds
// (packaging/systemd/user, packaging/launchd-standalone/agents): the readers
// find them, ensure installs them and verify passes, with and without the
// administrator's proxy.
func TestSandboxDefaultUserUnitsComeFromTheEmbeddedAssets(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			h.env.UserUnitSource = nil
			var doc map[string]any
			if err := yaml.Unmarshal(sandboxConfig(t, goos, true, map[string]any{"install": "setup", "version": "0.1.5"}), &doc); err != nil {
				t.Fatal(err)
			}
			doc["enterprise"].(map[string]any)["network"] = map[string]any{"https_proxy": "http://proxy.example.test:3128", "no_proxy": "localhost"}
			cfg, _ := yaml.Marshal(doc)
			requireOK(t, h.ensure(cfg))
			for _, u := range h.env.userUnits() {
				embedded, err := h.env.userUnitBytes(u)
				if err != nil || len(embedded) == 0 {
					t.Fatalf("no embedded definition of %s: %v", u.Name, err)
				}
				installed := h.read(h.env.userUnitPath(u, ChannelPayload))
				switch {
				case goos == "darwin" && !strings.Contains(installed, "<string>"+u.Name+"</string>"):
					t.Errorf("%s is not the plist of %s:\n%s", h.env.userUnitPath(u, ChannelPayload), u.Name, installed)
				case goos == "darwin" && !strings.Contains(installed, "http://proxy.example.test:3128"):
					t.Errorf("the proxy did not reach %s", u.Name)
				case goos == "linux" && installed != string(embedded):
					t.Errorf("%s differs from the embedded unit", u.Name)
				}
			}
			if goos == "linux" {
				if service := h.read("/etc/systemd/user/" + userUnitSandboxService); !strings.Contains(service, "sandbox-daemon") {
					t.Errorf("the sandbox service unit is not the embedded one:\n%s", service)
				}
				if got := h.link("/etc/systemd/user/sockets.target.wants/" + userUnitSandboxSocket); got != "/etc/systemd/user/"+userUnitSandboxSocket {
					t.Errorf("enable link -> %q", got)
				}
			}
			h.publishLedger([]byte("ledger\n"))
			requireOK(t, h.run(Options{Action: ActionVerify}))
			if again := h.ensure(cfg); !again.Noop {
				t.Errorf("a second ensure applied %v", again.Changes)
			}
		})
	}
}
