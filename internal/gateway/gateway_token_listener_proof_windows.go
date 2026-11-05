// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "net/http"

// gatewayTokenProofCallerIsSelf refuses every caller on Windows: DefenseClaw
// does not host the OpenClaw connector there.
func gatewayTokenProofCallerIsSelf(*http.Request) bool { return false }
