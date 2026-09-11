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

package winpath

// ManagedIPCDir has no meaning off Windows: the POSIX builds place their
// sockets under the data directory and gate access with mode and ownership
// rather than with a trusted-root anchor.
func ManagedIPCDir() string { return "" }
