//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package systemd

import "net"

// Listener reports no inherited listeners where socket activation does not
// exist (Windows services bind their own sockets under SCM).
func Listener(string) (net.Listener, bool, error) { return nil, false, nil }
