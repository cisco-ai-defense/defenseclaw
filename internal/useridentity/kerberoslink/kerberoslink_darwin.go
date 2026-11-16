// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

// Package kerberoslink names the Kerberos framework for cgo builds on
// macOS. useridentity imports the Kerberos functions dynamically from Go
// assembly; release builds use CGO_ENABLED=0 and the internal linker, but a
// cgo build links externally and needs the framework on the link line. A
// package with Go assembly cannot use cgo itself, so the flag lives here.
package kerberoslink

// #cgo LDFLAGS: -framework Kerberos
import "C"
