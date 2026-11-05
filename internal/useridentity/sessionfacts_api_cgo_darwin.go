// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package useridentity

// sessionfacts_api_darwin.go imports the Kerberos functions dynamically.
// Release builds use CGO_ENABLED=0 and the internal linker; a cgo build
// (go test on macOS) links externally and needs the framework named.

// #cgo LDFLAGS: -framework Kerberos
import "C"
