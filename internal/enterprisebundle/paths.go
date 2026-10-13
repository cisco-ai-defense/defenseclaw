// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"strings"
)

// The bundle tree (spec section 3). manifest.json and manifest.sig are the
// signed envelope; every other file is listed in files[].
const (
	ManifestName  = "manifest.json"
	SignatureName = "manifest.sig"
	ConfigName    = "config.yaml"
)

// pathByte reports whether c may appear in a bundle path.
func pathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return c == '.' || c == '_' || c == '-' || c == '/'
}

// windowsReservedNames are device names Windows resolves in every directory,
// with or without an extension.
var windowsReservedNames = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true,
	"com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
}

// checkPathName refuses a bundle path that is not a clean, relative,
// portable name: [A-Za-z0-9._/-] only, no empty, "." or ".." segment, no
// segment ending in a dot (Windows drops it), no Windows device name, at
// most MaxPathBytes long and MaxPathDepth deep.
func checkPathName(path string) *Error {
	if path == "" {
		return refuse(CodeArchiveInvalid, path, "empty path")
	}
	if len(path) > MaxPathBytes {
		return refuse(CodeArchiveInvalid, path, "path longer than %d bytes", MaxPathBytes)
	}
	for i := 0; i < len(path); i++ {
		if !pathByte(path[i]) {
			return refuse(CodeArchiveInvalid, path, "path holds a character outside [A-Za-z0-9._/-]")
		}
	}
	if path[0] == '/' {
		return refuse(CodeArchiveInvalid, path, "absolute path")
	}
	segments := strings.Split(path, "/")
	if len(segments) > MaxPathDepth {
		return refuse(CodeArchiveInvalid, path, "path deeper than %d levels", MaxPathDepth)
	}
	for _, segment := range segments {
		switch {
		case segment == "":
			return refuse(CodeArchiveInvalid, path, "empty path segment")
		case segment == "." || segment == "..":
			return refuse(CodeArchiveInvalid, path, "relative path segment %q", segment)
		case strings.HasSuffix(segment, "."):
			return refuse(CodeArchiveInvalid, path, "path segment ends with a dot")
		}
		base, _, _ := strings.Cut(strings.ToLower(segment), ".")
		if windowsReservedNames[base] {
			return refuse(CodeArchiveInvalid, path, "path segment is a reserved device name")
		}
	}
	return nil
}

// checkLayout refuses a valid path that is outside the bundle tree:
//
//	manifest.json  manifest.sig  config.yaml
//	policies/guardrail/<pack>/...  policies/sandbox/<pack>/...
//	discovery/signature-packs/<name>.json  discovery/confidence.yaml
//	scanners/codeguard/...
//
// dir says whether path names a directory, which may also be a prefix of
// that tree (policies, policies/guardrail).
func checkLayout(path string, dir bool) *Error {
	segments := strings.Split(path, "/")
	top := segments[0]
	if len(segments) == 1 {
		switch {
		case !dir && (top == ManifestName || top == SignatureName || top == ConfigName):
			return nil
		case dir && (top == "policies" || top == "discovery" || top == "scanners"):
			return nil
		case top == "secrets":
			return refuse(CodeArchiveInvalid, path, "bundles carry no secrets; list them in secret_refs and deliver the values with the MDM")
		}
		return refuse(CodeArchiveInvalid, path, "not part of the bundle tree")
	}
	second := segments[1]
	ok := false
	switch top {
	case "policies":
		// policies/guardrail/<pack>/... and policies/sandbox/<pack>/...: a
		// file needs a pack directory above it.
		ok = (second == "guardrail" || second == "sandbox") && (dir || len(segments) >= 4)
	case "discovery":
		switch {
		case second == "signature-packs" && len(segments) == 2:
			ok = dir
		case second == "signature-packs" && len(segments) == 3:
			ok = !dir && strings.HasSuffix(segments[2], ".json")
		case second == "confidence.yaml" && len(segments) == 2:
			ok = !dir
		}
	case "scanners":
		ok = second == "codeguard" && (dir || len(segments) >= 3)
	}
	if !ok {
		return refuse(CodeArchiveInvalid, path, "not part of the bundle tree")
	}
	return nil
}

// checkBundlePath is checkPathName then checkLayout.
func checkBundlePath(path string, dir bool) *Error {
	if err := checkPathName(path); err != nil {
		return err
	}
	return checkLayout(path, dir)
}

// executableContent reports content that is a program: an ELF, Mach-O, PE
// or WebAssembly binary, a Java class or a script with a #! line. Bundles
// carry data only.
func executableContent(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	if data[0] == '#' && data[1] == '!' {
		return true
	}
	if len(data) < 4 {
		return false
	}
	switch string(data[:4]) {
	case "\x7fELF", "\x00asm",
		"\xfe\xed\xfa\xce", "\xfe\xed\xfa\xcf", "\xce\xfa\xed\xfe", "\xcf\xfa\xed\xfe", "\xca\xfe\xba\xbe":
		return true
	}
	if data[0] == 'M' && data[1] == 'Z' && len(data) >= 0x40 {
		offset := int(data[0x3c]) | int(data[0x3d])<<8 | int(data[0x3e])<<16 | int(data[0x3f])<<24
		if offset >= 0x40 && offset+4 <= len(data) && string(data[offset:offset+4]) == "PE\x00\x00" {
			return true
		}
	}
	return false
}
