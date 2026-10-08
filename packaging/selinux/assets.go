// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package selinuxpolicy embeds the DefenseClaw SELinux policy module that
// the Linux lifecycle loads on SELinux hosts, so SELinux-confined users can
// reach the hook socket.
package selinuxpolicy

import _ "embed"

// ModuleName is the module name semodule lists (the CIL file's base name).
const ModuleName = "defenseclaw"

// HookSocketType is the SELinux type the module gives the hook socket.
const HookSocketType = "defenseclaw_hook_sock_t"

//go:embed defenseclaw.cil
var module []byte

// Module returns the module's CIL source.
func Module() []byte { return append([]byte(nil), module...) }
