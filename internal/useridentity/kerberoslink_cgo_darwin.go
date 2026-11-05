// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package useridentity

// A cgo build links externally; kerberoslink puts the Kerberos framework
// on the link line for the functions sessionfacts_api_darwin.go imports.
import _ "github.com/defenseclaw/defenseclaw/internal/useridentity/kerberoslink"
