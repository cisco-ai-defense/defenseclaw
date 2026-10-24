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

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 1.0.4 review (loop round 2): one inspect-* script serves every connector of
// a per-user data directory and nothing authenticates which one an
// invocation runs for. Its fail mode stays closed for every stored mode,
// selector and parser (jq, the python3 fallback, neither), including older
// open records left by an upgrade (sa-port-peer: a per-user open is never
// an outage exception); the malformed-state rows keep the reader's
// hardening on every parser path.
func TestSharedHookFailModeIsTheStrictestRecordedMode(t *testing.T) {
	helper, err := filepath.Abs(filepath.Join("hooks", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	python, pyErr := exec.LookPath("python3")
	_, jqErr := exec.LookPath("jq")
	// Include older sourced and unsourced open records to check that neither
	// can weaken the current per-user posture.
	flat := func(name, mode string) string {
		return "DEFENSECLAW_CONNECTOR=" + name + "\nDEFENSECLAW_FAIL_MODE=" + mode + "\nFAIL_MODE_SOURCE=config\n"
	}
	unsourced := func(name, mode string) string {
		return "DEFENSECLAW_CONNECTOR=" + name + "\nDEFENSECLAW_FAIL_MODE=" + mode + "\n"
	}
	mixedJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"closed","claudecode":"open"},"fail_mode_sources":{"codex":"config","claudecode":"config"}}`
	closedLegacyOpenJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"closed","claudecode":"closed"},"fail_mode_sources":{"codex":"config","claudecode":"config"},"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`
	openJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"open","claudecode":"open"},"fail_mode_sources":{"codex":"config","claudecode":"config"},"legacy_fail_mode":"closed","legacy_fail_mode_source":"config"}`
	legacyOpenJSON := `{"version":2,"gateway_addr":"127.0.0.1:1","legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`
	malformedMap := func(value string) string {
		return `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":` + value + `,"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`
	}
	// sizedJSON and sizedFlat pad the writers' open state to exactly size
	// bytes.
	sizedJSON := func(connector string, size int) string {
		prefix := `{"version":2,"fail_modes":{"` + connector + `":"open"},"fail_mode_sources":{"` + connector + `":"config"},"pad":"`
		return prefix + strings.Repeat("x", size-len(prefix)-2) + `"}`
	}
	sizedFlat := func(connector string, size int) string {
		prefix := flat(connector, "open") + "PAD="
		return prefix + strings.Repeat("x", size-len(prefix)-1) + "\n"
	}
	type state map[string]string
	for _, tc := range []struct {
		name     string
		files    state
		selector string
		// want per parser: jq, python3, none.
		want [3]string
	}{
		{"mixed/selector-open-peer", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": mixedJSON},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"mixed/no-selector", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": mixedJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"mixed/json-only-selector-open-peer", state{".hookcfg": mixedJSON},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"mixed/flat-only-selector-open-peer", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-two-closed-records", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.claudecode": flat("claudecode", "closed"), ".hookcfg": closedLegacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-flat-legacy-open-one-closed", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg.legacy": flat("", "open"),
			".hookcfg": `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{"codex":"closed"},"legacy_fail_mode":"open"}`},
			"", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-selector-unrecorded", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg": closedLegacyOpenJSON},
			"cursor", [3]string{"closed", "closed", "closed"}},
		{"upgrade/legacy-open-json-closed-entry-no-flat", state{".hookcfg": closedLegacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		// The loop round 2 review scenario: codex closed only in the JSON and
		// no parser to read it (TestSharedHookFailModeWithoutAParser covers
		// the managed render markers).
		{"json-closed-entry-flat-open", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": mixedJSON},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"malformed-flat-mode", state{".hookcfg.codex": flat("codex", "OPEN "), ".hookcfg.claudecode": flat("claudecode", "open")},
			"", [3]string{"closed", "closed", "closed"}},
		{"malformed-json", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "{not json"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-fail-modes-not-a-map", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":["open"]}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		// The modes the shared hooks keep: a selected connector's own open
		// record when every record is open, and the legacy mode for a call
		// no single connector owns (an install no connector refresh has
		// rewritten yet, or several open records), as before 1.0.4.
		{"all-open/no-selector", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": openJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"all-open/no-selector-legacy-open", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg.legacy": flat("", "open"), ".hookcfg": strings.Replace(openJSON, `"legacy_fail_mode":"closed"`, `"legacy_fail_mode":"open"`, 1)},
			"", [3]string{"closed", "closed", "closed"}},
		// Loop round 3: the JSON legacy open alone (no flat legacy record,
		// which every writer since 0.8.10 writes with it) opens nothing.
		{"all-open/no-selector-json-legacy-open-only", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": strings.Replace(openJSON, `"legacy_fail_mode":"closed"`, `"legacy_fail_mode":"open"`, 1)},
			"", [3]string{"closed", "closed", "closed"}},
		{"single-open-record", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"},"fail_mode_sources":{"codex":"config"}}`},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"all-open/selector-recorded", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": openJSON},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"all-open/selector-unrecorded", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": openJSON},
			"cursor", [3]string{"closed", "closed", "closed"}},
		{"single-closed", state{".hookcfg.codex": flat("codex", "closed"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"closed"}}`},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-only-open-json-only", state{".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-only-open-flat", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-only-open-selector", state{".hookcfg": legacyOpenJSON},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-closed-json-open", state{".hookcfg.legacy": flat("", "closed"), ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-open-json-legacy-missing", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": `{"version":2,"gateway_addr":"127.0.0.1:1"}`},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-open-json-empty-map", state{".hookcfg.legacy": flat("", "open"),
			".hookcfg": `{"version":2,"gateway_addr":"127.0.0.1:1","fail_modes":{},"legacy_fail_mode":"open","legacy_fail_mode_source":"config"}`},
			"", [3]string{"closed", "closed", "closed"}},
		// A legacy record must name no connector, as a connector record must
		// name its own.
		{"legacy-flat-without-connector-line", state{".hookcfg.legacy": "DEFENSECLAW_FAIL_MODE=open\n", ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-naming-a-connector", state{".hookcfg.legacy": flat("codex", "open"), ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		{"nothing", state{}, "", [3]string{"closed", "closed", "closed"}},
		// An open no config chose (an earlier release resolved it, or it was
		// lowered for a vendor): closed on every parser path (G3-upg).
		{"unsourced/single-open-record", state{".hookcfg.codex": unsourced("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"}}`},
			"codex", [3]string{"closed", "closed", "closed"}},
		// No parser: JSON state that cannot be read is closed (G-hooks-upg R2-1).
		{"unsourced/json-open-flat-sourced", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"}}`},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"unsourced/legacy-only-open", state{".hookcfg.legacy": unsourced("", "open"), ".hookcfg": `{"version":2,"legacy_fail_mode":"open"}`},
			"", [3]string{"closed", "closed", "closed"}},
		// Loop round 3: a v2 JSON whose fail_modes is present but not an
		// object never reaches the legacy mode, with or without the flat
		// legacy record, on every parser path.
		{"fail-modes-missing-no-flat", state{".hookcfg": legacyOpenJSON}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-null-no-flat", state{".hookcfg": malformedMap("null")}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-null", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("null")}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-false", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("false")}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-empty-list", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("[]")}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-zero", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("0")}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-empty-string", state{".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap(`""`)}, "", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-null-selector", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": malformedMap("null")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"fail-modes-null-single-flat-record", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg.legacy": flat("", "open"), ".hookcfg": malformedMap("null")},
			"", [3]string{"closed", "closed", "closed"}},
		// 1.0.4 review (loop round 2 of G-hooks-upg): a flat record that is
		// not a regular file or does not name its own connector is malformed,
		// with or without JSON state.
		{"flat-record-names-another-connector", state{".hookcfg.codex": flat("claudecode", "open"), ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-without-connector-line", state{".hookcfg.codex": "DEFENSECLAW_FAIL_MODE=open\n", ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-empty", state{".hookcfg.codex": "", ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-link", state{".hookcfg.codex": "@link:" + flat("codex", "open"), ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-dangling-link", state{".hookcfg.codex": "@dangling", ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-directory", state{".hookcfg.codex": "@dir", ".hookcfg.claudecode": flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-state-directory", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "@dir"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-state-dangling-link", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "@dangling"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		// 1.0.4 review (loop round 3 of G-hooks-upg): JSON state that is not
		// the one document the writers make is malformed on every parser
		// path, and so is a flat record that is not their KEY=value lines.
		// Before, jq read empty or blank text, a fractional version, a field
		// of another type, a key given twice, two documents and a byte-order
		// mark as open, both parsers followed a link to open JSON, and a
		// flat record giving its mode twice took the first.
		{"json-empty", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": ""},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-blank", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": " \n\t\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-fractional-version", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2.5,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-string", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":"2","fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-bool", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":true,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-legacy-mode-not-a-string", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"legacy_fail_mode":5}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-gateway-not-a-string", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"gateway_addr":["x"],"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-entry-not-a-string", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open","codex":1}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-field-in-another-case", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"FAIL_MODES":{"codex":"closed"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-key-twice", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"closed"},"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-entry-twice", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"closed","claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-two-documents", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"}} {"version":2,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-byte-order-mark", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "\ufeff" + `{"version":2,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-link-to-open-state", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "@link:" + `{"version":2,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-mode-twice", state{".hookcfg.claudecode": flat("claudecode", "open") + "DEFENSECLAW_FAIL_MODE=closed\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-connector-twice", state{".hookcfg.claudecode": flat("claudecode", "open") + "DEFENSECLAW_CONNECTOR=claudecode\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-extra-line", state{".hookcfg.claudecode": flat("claudecode", "open") + "{\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-blank-line", state{".hookcfg.claudecode": "\n" + flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-lower-case-key", state{".hookcfg.claudecode": "x=1\n" + flat("claudecode", "open")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-cut-short", state{".hookcfg.claudecode": strings.TrimSuffix(flat("claudecode", "open"), "\n")},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"flat-record-nul", state{".hookcfg.claudecode": "DEFENSECLAW_CONNECTOR=claudecode\nDEFENSECLAW_FAIL_MODE=op\x00en\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-mode-twice", state{".hookcfg.legacy": flat("", "closed") + "DEFENSECLAW_FAIL_MODE=open\n"},
			"", [3]string{"closed", "closed", "closed"}},
		// 1.0.4 review (loop round 4 of G-hooks-upg): jq reads number tokens
		// no other reader takes (nan, Infinity, +2, 02, .5, 1.) and reads 2e0
		// as the integer 2, so with an open entry the jq path ran open where
		// the python3 path, the native hook and the writers close. A version
		// past 2^63-1 opened both paths, and an escaped key or value was read
		// decoded. Both paths now read the raw text alike: no backslash,
		// every number as JSON writes it, at most 32 levels of nesting, and
		// a version written as an integer from 2 to 2^63-1.
		{"json-version-exponent", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2e0,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-exponent-upper", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2E+0,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-scaled-fraction", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":0.2e1,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-leading-zero", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":02,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-plus", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":+2,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-past-int64", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":9223372036854775808,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-long", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":99999999999999999999,"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-escaped-key", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"\u0076ersion":2e0,"x":{"version":2},"fail_modes":{"claudecode":"open"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-nan", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":nan}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-infinity", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":[Infinity]}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-fraction-without-integer", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":.5}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-trailing-dot", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":1.}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-leading-zero", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":{"y":-01}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-escaped-entry", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"\u006fpen"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-escaped-backslash", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":"a\\b"}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-form-feed", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "{\"version\":2,\f\"fail_modes\":{\"claudecode\":\"open\"}}"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-deeper-than-32", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-far-deeper", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"x":` + strings.Repeat("[", 2000) + strings.Repeat("]", 2000) + `}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		// Controls: numbers as JSON writes them, a nested 2e0, the largest
		// version, 32 levels and a document split across lines stay open.
		{"json-strict-numbers", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"},"x":[1e5,-0.5,0,1E-2,true,false,null],"y":{"version":2e0},"z":"version"}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-version-int64-max", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": `{"version":9223372036854775807,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-32-levels", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"},"x":` + strings.Repeat("[", 31) + strings.Repeat("]", 31) + `}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-split-across-lines", state{".hookcfg.claudecode": flat("claudecode", "open"), ".hookcfg": "{\n\"version\"\n:\n 2\n,\"fail_modes\":{\"claudecode\":\"open\"},\"fail_mode_sources\":{\"claudecode\":\"config\"}}\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		// Controls: the writers' JSON, null fields and nested objects with
		// unique keys stay readable.
		{"json-writer-shape", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": "{\n  \"version\": 2,\n  \"gateway_addr\": \"127.0.0.1:1\",\n  \"fail_modes\": {\n    \"claudecode\": \"open\"\n  },\n  \"fail_mode_sources\": {\n    \"claudecode\": \"config\"\n  },\n  \"managed_enterprise\": true\n}\n"},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-null-fields", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": `{"version":3,"gateway_addr":null,"legacy_fail_mode":null,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		{"json-nested-unique-keys", state{".hookcfg.claudecode": flat("claudecode", "open"),
			".hookcfg": `{"version":2,"fail_modes":{"claudecode":"open"},"fail_mode_sources":{"claudecode":"config"},"extra":{"a":{"a":1},"b":[{"a":1},{"a":2}]}}`},
			"claudecode", [3]string{"closed", "closed", "closed"}},
		// 1.0.4 review (loop round 2 after round 4 of G-hooks-upg): the
		// writers refuse a sidecar larger than 64 KiB (HookSidecarMaxBytes),
		// so a refresh that would close it is not applied, while the shared
		// hooks still read the open mode in it. Every record the shared hooks
		// read (the JSON, a connector's flat record, the legacy record) is
		// malformed past 64 KiB, and so is JSON holding a NUL byte; exactly
		// 64 KiB stays readable.
		{"json-larger-than-64-KiB", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": sizedJSON("codex", 70<<10)},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"json-64-KiB-plus-one", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": sizedJSON("codex", 64<<10+1)},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"json-exactly-64-KiB", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": sizedJSON("codex", 64<<10)},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"json-multibyte-past-64-KiB", state{".hookcfg.codex": flat("codex", "open"),
			".hookcfg": `{"version":2,"fail_modes":{"codex":"open"},"pad":"` + strings.Repeat("\u00e9", 35<<10) + `"}`},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"json-nul-in-a-string", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg": `{"version":2,"fail_modes":{"codex":"open"},"pad":"a` + "\x00" + `b"}`},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"flat-record-larger-than-64-KiB", state{".hookcfg.codex": sizedFlat("codex", 70<<10)},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"flat-record-64-KiB-plus-one", state{".hookcfg.codex": sizedFlat("codex", 64<<10+1)},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"flat-record-exactly-64-KiB", state{".hookcfg.codex": sizedFlat("codex", 64<<10)},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-larger-than-64-KiB", state{".hookcfg.legacy": sizedFlat("", 70<<10)},
			"", [3]string{"closed", "closed", "closed"}},
		{"legacy-flat-larger-than-64-KiB-with-json", state{".hookcfg.legacy": sizedFlat("", 70<<10), ".hookcfg": legacyOpenJSON},
			"", [3]string{"closed", "closed", "closed"}},
		// Controls: names the writers use for other files never count as
		// records, and an install with no JSON state opens from its flat
		// records on every parser path.
		{"flat-only/single-open-record", state{".hookcfg.codex": flat("codex", "open")},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"flat-only/open-record-and-writer-files", state{".hookcfg.codex": flat("codex", "open"), ".hookcfg.lock": "", ".hookcfg.codex.tmp-1": flat("codex", "closed")},
			"codex", [3]string{"closed", "closed", "closed"}},
		{"flat-only/legacy-open", state{".hookcfg.legacy": flat("", "open")},
			"", [3]string{"closed", "closed", "closed"}},
	} {
		for i, parser := range []string{"jq", "python3", "none"} {
			t.Run(tc.name+"/"+parser, func(t *testing.T) {
				root := t.TempDir()
				hookDir := filepath.Join(root, "hooks")
				binDir := filepath.Join(root, "bin")
				for _, dir := range []string{hookDir, binDir} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for name, body := range tc.files {
					path := filepath.Join(hookDir, name)
					var err error
					switch {
					case body == "@dir":
						err = os.Mkdir(path, 0o700)
					case body == "@dangling":
						err = os.Symlink(filepath.Join(root, "missing"), path)
					case strings.HasPrefix(body, "@link:"):
						target := filepath.Join(root, name+".target")
						if err = os.WriteFile(target, []byte(strings.TrimPrefix(body, "@link:")), 0o600); err == nil {
							err = os.Symlink(target, path)
						}
					default:
						err = os.WriteFile(path, []byte(body), 0o600)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				path := os.Getenv("PATH")
				switch parser {
				case "jq":
					if jqErr != nil {
						t.Skip("jq is not installed")
					}
				case "python3":
					if pyErr != nil {
						t.Skip("python3 is not installed")
					}
					if err := os.Symlink(python, filepath.Join(binDir, "python3")); err != nil {
						t.Fatal(err)
					}
					if uname, err := exec.LookPath("uname"); err == nil {
						if err := os.Symlink(uname, filepath.Join(binDir, "uname")); err != nil {
							t.Fatal(err)
						}
					}
					path = binDir
				case "none":
					path = binDir
				}
				bash, err := exec.LookPath("bash")
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bash, "-c", `. "$1"; defenseclaw_shared_runtime_fail_mode "$2" "$3"`, "probe", helper, hookDir, tc.selector)
				cmd.Env = append(sanitizedTestEnv(), "PATH="+path, "HOME="+root)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("helper failed: %v\n%s", err, out)
				}
				if got := strings.TrimSpace(string(out)); got != tc.want[i] {
					t.Fatalf("fail mode %q, want %q", got, tc.want[i])
				}
			})
		}
	}
}

// The same rule end to end, through real setup writers and inspect-* scripts:
// with DEFENSECLAW_HOME missing, every per-user hook blocks.
func TestSharedInspectHooksNeverTakeAPeersOpenMode(t *testing.T) {
	type install struct {
		conn Connector
		mode string
	}
	for _, tc := range []struct {
		name string
		// legacy is the sidecar an older release left (written before the
		// connector writers): "" none, "scalar" the 0.8.x KEY=value file,
		// "v2" the 1.0.x unscoped writer.
		legacy    string
		installs  []install
		selectors []string
		wantAllow bool
	}{
		{"codex-closed-claude-open", "", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"", "claudecode", "codex", "cursor"}, false},
		{"upgrade-0.8-open-two-closed", "scalar", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "closed"}},
			[]string{"", "claudecode", "codex"}, false},
		{"upgrade-1.0-open-two-closed", "v2", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "closed"}},
			[]string{"", "claudecode", "codex"}, false},
		{"upgrade-1.0-open-one-closed-one-open", "v2", []install{{NewCodexConnector(), "closed"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"", "claudecode"}, false},
		// Controls: a connector of an install every connector chose open
		// stays open, and so does a legacy open the config chose
		// (writeHookConfigSidecar records its config source) that no
		// connector refresh has rewritten yet or whose records are all open.
		{"both-open", "", []install{{NewCodexConnector(), "open"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"claudecode", "codex"}, false},
		{"both-open-unattributed", "", []install{{NewCodexConnector(), "open"}, {NewClaudeCodeConnector(), "open"}},
			[]string{"", "cursor"}, false},
		{"upgrade-1.0-open-both-open-unattributed", "v2", []install{{NewCodexConnector(), "open"}, {NewClaudeCodeConnector(), "open"}},
			[]string{""}, false},
		{"legacy-open-not-refreshed", "v2", nil, []string{""}, false},
		// Loop round 3: the same install with fail_modes made null is
		// malformed and blocks.
		{"legacy-open-not-refreshed-null-map", "v2-null-map", nil, []string{""}, false},
	} {
		for _, invoke := range hookArgvInspectCases() {
			if len(invoke.stdin) > 4096 {
				continue
			}
			for _, selector := range tc.selectors {
				t.Run(tc.name+"/"+invoke.script+"/selector="+selector, func(t *testing.T) {
					dataDir := t.TempDir()
					hookDir := filepath.Join(dataDir, "hooks")
					if err := os.MkdirAll(hookDir, 0o700); err != nil {
						t.Fatal(err)
					}
					switch tc.legacy {
					case "scalar":
						if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg"), []byte("DEFENSECLAW_GATEWAY_ADDR=127.0.0.1:1\nDEFENSECLAW_FAIL_MODE=open\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					case "v2", "v2-null-map":
						if err := writeHookConfigSidecar(hookDir, "127.0.0.1:1", "", "open", false); err != nil {
							t.Fatal(err)
						}
					}
					writers := tc.installs
					if len(writers) == 0 {
						// Render the scripts without adding a connector record.
						writers = []install{{NewCodexConnector(), "open"}}
					}
					for _, in := range writers {
						opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:1", APIToken: "scoped-test-token", HookFailMode: in.mode}
						if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, in.conn); err != nil {
							t.Fatal(err)
						}
					}
					if len(tc.installs) == 0 {
						if err := clearHookConfigSidecarEntry(hookDir, "codex"); err != nil {
							t.Fatal(err)
						}
					}
					if tc.legacy == "v2-null-map" {
						path := filepath.Join(hookDir, ".hookcfg")
						body, err := os.ReadFile(path)
						if err != nil || strings.Contains(string(body), `"fail_modes"`) {
							t.Fatalf("unexpected sidecar (%v):\n%s", err, body)
						}
						body = []byte(strings.Replace(string(body), `"legacy_fail_mode"`, `"fail_modes": null, "legacy_fail_mode"`, 1))
						if err := os.WriteFile(path, body, 0o600); err != nil {
							t.Fatal(err)
						}
					}
					if tc.legacy != "" {
						body, err := os.ReadFile(filepath.Join(hookDir, ".hookcfg"))
						if err != nil || !strings.Contains(string(body), `"legacy_fail_mode": "open"`) {
							t.Fatalf("the upgrade did not keep the legacy open mode (%v):\n%s", err, body)
						}
					}
					cmd := exec.Command("bash", filepath.Join(hookDir, invoke.script))
					cmd.Stdin = strings.NewReader(invoke.stdin)
					cmd.Env = append(sanitizedTestEnv(), "HOME="+dataDir, "DEFENSECLAW_HOME="+filepath.Join(dataDir, "missing"))
					if selector != "" {
						cmd.Env = append(cmd.Env, "DEFENSECLAW_CONNECTOR="+selector)
					}
					cmd.Env = append(cmd.Env, invoke.env...)
					output, err := cmd.CombinedOutput()
					if allowed := err == nil; allowed != tc.wantAllow {
						t.Fatalf("allowed=%v want %v (err=%v)\n%s", allowed, tc.wantAllow, err, output)
					}
					if !tc.wantAllow && !strings.Contains(string(output), "hook home unavailable") {
						t.Fatalf("the block did not come from the unavailable-home exit:\n%s", output)
					}
				})
			}
		}
	}
}

// The 64 KiB bound of the shared hooks' sidecar reads is in bytes in every
// locale: in a UTF-8 locale bash's read -n counts characters, so 70 KiB of
// two-byte characters (35 Ki characters) would read as within the bound.
func TestSharedHookSidecarBoundIsBytesInEveryLocale(t *testing.T) {
	helper, err := filepath.Abs(filepath.Join("hooks", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("\u00e9", 35<<10)
	for _, tc := range []struct {
		name, file, body string
	}{
		{"json", ".hookcfg", `{"version":2,"fail_modes":{"codex":"open"},"pad":"` + pad + `"}`},
		{"flat-record", ".hookcfg.codex", "DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\nPAD=" + pad + "\n"},
	} {
		for _, locale := range []string{"C", "C.UTF-8", "en_US.UTF-8"} {
			t.Run(tc.name+"/"+locale, func(t *testing.T) {
				hookDir := filepath.Join(t.TempDir(), "hooks")
				if err := os.MkdirAll(hookDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if tc.file == ".hookcfg" {
					if err := os.WriteFile(filepath.Join(hookDir, ".hookcfg.codex"), []byte("DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=open\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(hookDir, tc.file), []byte(tc.body), 0o600); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(bash, "-c", `. "$1"; defenseclaw_shared_runtime_fail_mode "$2" codex`, "probe", helper, hookDir)
				cmd.Env = append(sanitizedTestEnv(), "PATH="+os.Getenv("PATH"), "HOME="+t.TempDir(), "LC_ALL="+locale, "LANG="+locale)
				// Stdout only: bash warns on stderr for a locale the host
				// does not have, and then reads bytes anyway.
				out, err := cmd.Output()
				if err != nil {
					t.Fatalf("helper failed: %v\n%s", err, out)
				}
				if got := strings.TrimSpace(string(out)); got != "closed" {
					t.Fatalf("fail mode %q for %d bytes in locale %s, want closed", got, len(tc.body), locale)
				}
			})
		}
	}
}
