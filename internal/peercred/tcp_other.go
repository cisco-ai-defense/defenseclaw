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

package peercred

import "net"

// loopbackTCPOwner has no kernel source on this platform: Windows names the
// process of a TCP connection, not its account, to a service.
func loopbackTCPOwner(_, _ *net.TCPAddr) (int, error) { return -1, ErrUnsupported }
