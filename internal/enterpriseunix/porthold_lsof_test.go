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
	"reflect"
	"testing"
)

// GAP-1491: the macOS port preflight took every lsof listener on the API
// port as a holder, also one bound to a LAN address, which does not keep the
// gateway from binding 127.0.0.1, and refused the install. Only a listener
// on 127.0.0.1 or a wildcard counts (as on Linux); a process lsof names no
// address for still does.
func TestDarwinPortHoldersFollowTheLocalAddress(t *testing.T) {
	output := "p100\nu501\nf5\nn192.168.1.20:18970\n" + // a LAN listener only
		"p200\nu502\nf6\nn127.0.0.1:18970\n" +
		"p300\nu503\nf7\nn10.0.0.4:18970\nf8\nn*:18970\n" +
		"p400\nu504\nf9\nn[::]:18970\n" +
		"p500\nu505\nf10\nn[fe80::1]:18970\n" +
		"p600\nu506\nf11\n" // no address
	got := parseDarwinPortHolders(output)
	want := []portHolder{{PID: 200, UID: 502}, {PID: 300, UID: 503}, {PID: 400, UID: 504}, {PID: 600, UID: 506}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("holders = %+v, want %+v", got, want)
	}
}
