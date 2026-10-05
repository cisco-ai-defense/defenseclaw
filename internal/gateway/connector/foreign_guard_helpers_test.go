// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "runtime"

// testForeignHookGuardBinary is an absolute administrator hook binary on
// the host OS (the plugins refuse a relative one). The Windows form carries
// backslashes and a space, so the JavaScript escaping of the rendered guard
// line is exercised too.
func testForeignHookGuardBinary() string {
	if runtime.GOOS == "windows" {
		return `C:\Program Files\DefenseClaw\bin\defenseclaw-hook.exe`
	}
	return "/opt/defenseclaw/bin/defenseclaw-hook"
}
