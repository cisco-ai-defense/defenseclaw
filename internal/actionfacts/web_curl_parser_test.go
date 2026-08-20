// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestParseCurlArgvStopsShortBundleAtValueOperand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		argv          []string
		canonical     string
		value         string
		joined        bool
		wantOptions   int
		forbidOptions []string
	}{
		{
			name: "joined data containing output letters",
			argv: []string{
				"curl", "-dfoo", "https://files.invalid/run",
			},
			canonical:     "--data",
			value:         "foo",
			joined:        true,
			wantOptions:   1,
			forbidOptions: []string{"--output"},
		},
		{
			name: "safe prefix then joined data",
			argv: []string{
				"curl", "-sd@/tmp/fixture", "https://files.invalid/run",
			},
			canonical:     "--data",
			value:         "@/tmp/fixture",
			joined:        true,
			wantOptions:   2,
			forbidOptions: []string{"--output"},
		},
		{
			name: "joined header contents remain opaque",
			argv: []string{
				"curl", "-HX-Mode:ok", "https://files.invalid/run",
			},
			canonical:     "--header",
			value:         "X-Mode:ok",
			joined:        true,
			wantOptions:   1,
			forbidOptions: []string{"--request", "--output"},
		},
		{
			name: "safe prefix then separated header",
			argv: []string{
				"curl", "-sH", "X-Mode: ok", "https://files.invalid/run",
			},
			canonical:   "--header",
			value:       "X-Mode: ok",
			wantOptions: 2,
		},
		{
			name: "safe prefix then joined method",
			argv: []string{
				"curl", "-sXGET", "https://files.invalid/run",
			},
			canonical:   "--request",
			value:       "GET",
			joined:      true,
			wantOptions: 2,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed := parseCurlArgv(test.argv)
			if !parsed.Complete || len(parsed.Unresolved) != 0 ||
				len(parsed.Options) != test.wantOptions ||
				len(parsed.Targets) != 1 ||
				!parsed.provesResponseStdout() {
				t.Fatalf("parse = %#v", parsed)
			}
			option := requireCurlParsedOption(t, parsed, test.canonical)
			if !option.Known || !option.TakesValue ||
				!option.ValuePresent || option.Value != test.value ||
				option.ValueJoined != test.joined {
				t.Fatalf("option = %#v", option)
			}
			for _, forbidden := range test.forbidOptions {
				if curlParsedOptionExists(parsed, forbidden) {
					t.Fatalf("operand minted %q option: %#v", forbidden, parsed.Options)
				}
			}
		})
	}
}

func TestParseCurlArgvOwnsOptionLookingAndEmptyValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		argv      []string
		canonical string
		value     string
	}{
		{
			name:      "short header owns help token",
			argv:      []string{"curl", "-H", "--help", "https://files.invalid/run"},
			canonical: "--header",
			value:     "--help",
		},
		{
			name:      "long header owns head token",
			argv:      []string{"curl", "--header", "--head", "https://files.invalid/run"},
			canonical: "--header",
			value:     "--head",
		},
		{
			name:      "data owns apparent short option",
			argv:      []string{"curl", "-d", "-I", "https://files.invalid/run"},
			canonical: "--data",
			value:     "-I",
		},
		{
			name:      "empty header value is present",
			argv:      []string{"curl", "-H", "", "https://files.invalid/run"},
			canonical: "--header",
			value:     "",
		},
		{
			name:      "empty data value is present",
			argv:      []string{"curl", "--data", "", "https://files.invalid/run"},
			canonical: "--data",
			value:     "",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed := parseCurlArgv(test.argv)
			if !parsed.Complete || parsed.Preview ||
				len(parsed.Targets) != 1 || !parsed.provesResponseStdout() {
				t.Fatalf("parse = %#v", parsed)
			}
			option := requireCurlParsedOption(t, parsed, test.canonical)
			if !option.ValuePresent || option.Value != test.value {
				t.Fatalf("option = %#v", option)
			}
		})
	}

	missing := parseCurlArgv([]string{"curl", "-H"})
	if missing.Complete || len(missing.Unresolved) != 1 ||
		missing.responseStdoutState() != curlResponseStdoutUnknown {
		t.Fatalf("missing value parse = %#v", missing)
	}
}

func TestParseCurlArgvOwnsURLQueryValues(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		{"curl", "--url-query", "key=value", "https://files.invalid/run"},
		{"curl", "--url-query", "", "https://files.invalid/run"},
	} {
		parsed := parseCurlArgv(argv)
		option := requireCurlParsedOption(t, parsed, "--url-query")
		if !parsed.Complete || len(parsed.Targets) != 1 ||
			!option.ValuePresent || !parsed.hasValidOptionValues() {
			t.Fatalf("parse = %#v", parsed)
		}
	}
}

func TestParseCurlArgvShortAliasAndNoValueBundleParity(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		{"curl", "-m", "1", "https://files.invalid/run"},
		{"curl", "-m1", "https://files.invalid/run"},
		{"curl", "--max-time", "1", "https://files.invalid/run"},
	} {
		parsed := parseCurlArgv(argv)
		option := requireCurlParsedOption(t, parsed, "--max-time")
		if !parsed.Complete || len(parsed.Targets) != 1 ||
			parsed.Targets[0].Value != "https://files.invalid/run" ||
			option.Value != "1" || !parsed.provesResponseStdout() {
			t.Fatalf("argv=%v parse=%#v", argv, parsed)
		}
	}

	aliases := []struct {
		short     []string
		long      []string
		canonical string
		value     string
	}{
		{
			short:     []string{"curl", "-Uproxy:user", "https://files.invalid/run"},
			long:      []string{"curl", "--proxy-user", "proxy:user", "https://files.invalid/run"},
			canonical: "--proxy-user",
			value:     "proxy:user",
		},
		{
			short:     []string{"curl", "-Eclient.pem", "https://files.invalid/run"},
			long:      []string{"curl", "--cert", "client.pem", "https://files.invalid/run"},
			canonical: "--cert",
			value:     "client.pem",
		},
	}
	for _, test := range aliases {
		for _, argv := range [][]string{test.short, test.long} {
			parsed := parseCurlArgv(argv)
			option := requireCurlParsedOption(t, parsed, test.canonical)
			if !parsed.Complete || option.Value != test.value ||
				len(parsed.Targets) != 1 || !parsed.provesResponseStdout() {
				t.Fatalf("argv=%v parse=%#v", argv, parsed)
			}
		}
	}

	include := parseCurlArgv([]string{
		"curl", "-si", "https://files.invalid/run",
	})
	if !include.Complete || len(include.Options) != 2 ||
		!curlParsedOptionExists(include, "--silent") ||
		!curlParsedOptionExists(include, "--include") ||
		!include.provesResponseStdout() {
		t.Fatalf("include bundle = %#v", include)
	}

	explicitStdout := parseCurlArgv([]string{
		"curl", "-iso-", "https://files.invalid/run",
	})
	if !explicitStdout.Complete || len(explicitStdout.Options) != 3 ||
		len(explicitStdout.Targets) != 1 ||
		explicitStdout.Targets[0].Output != curlOutputStdout ||
		!explicitStdout.provesResponseStdout() {
		t.Fatalf("explicit stdout bundle = %#v", explicitStdout)
	}
}

func TestParseCurlArgvRejectsJoinedLongOptionValues(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		{"curl", "--data=fixture", "https://files.invalid/run"},
		{"curl", "--data=", "https://files.invalid/run"},
		{"curl", "--max-time=1", "https://files.invalid/run"},
		{"curl", "--request=GET", "https://files.invalid/run"},
		{"curl", "--url=https://files.invalid/run"},
		{"curl", "--silent=true", "https://files.invalid/run"},
	} {
		parsed := parseCurlArgv(argv)
		if parsed.Complete || len(parsed.Unresolved) != 1 ||
			parsed.Unresolved[0].Raw != argv[1] ||
			parsed.Unresolved[0].Reason !=
				"joined value is not accepted for this curl option" ||
			len(parsed.Options) != 1 || parsed.Options[0].ValuePresent ||
			parsed.provesResponseStdout() {
			t.Fatalf("joined long argv=%v parse=%#v", argv, parsed)
		}
	}

	shortJoined := parseCurlArgv([]string{
		"curl", "-m1", "-XGET", "https://files.invalid/run",
	})
	if !shortJoined.Complete || !shortJoined.hasValidOptionValues() ||
		!shortJoined.provesResponseStdout() {
		t.Fatalf("short joined options lost authority: %#v", shortJoined)
	}
}

func TestParseCurlArgvAssignsOutputSlotsPerTransfer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		argv       []string
		outputs    []curlOutputKind
		wantStdout bool
	}{
		{
			name: "file slot leaves second target on stdout",
			argv: []string{
				"curl", "-o", "one.bin",
				"https://one.invalid/a", "https://two.invalid/b",
			},
			outputs:    []curlOutputKind{curlOutputFile, curlOutputStdout},
			wantStdout: true,
		},
		{
			name: "explicit stdout and file slots",
			argv: []string{
				"curl", "-o-", "-o", "two.bin",
				"https://one.invalid/a", "https://two.invalid/b",
			},
			outputs:    []curlOutputKind{curlOutputStdout, curlOutputFile},
			wantStdout: true,
		},
		{
			name: "all targets write files",
			argv: []string{
				"curl", "-o", "one.bin", "-o", "two.bin",
				"https://one.invalid/a", "https://two.invalid/b",
			},
			outputs: []curlOutputKind{curlOutputFile, curlOutputFile},
		},
		{
			name: "remote name then stdout",
			argv: []string{
				"curl", "-O", "-o-",
				"https://one.invalid/a", "https://two.invalid/b",
			},
			outputs:    []curlOutputKind{curlOutputRemoteName, curlOutputStdout},
			wantStdout: true,
		},
		{
			name: "remote name all",
			argv: []string{
				"curl", "--remote-name-all",
				"https://one.invalid/a", "https://two.invalid/b",
			},
			outputs: []curlOutputKind{curlOutputRemoteName, curlOutputRemoteName},
		},
		{
			name: "remote name all starts after earlier target",
			argv: []string{
				"curl", "https://one.invalid/a", "--remote-name-all",
			},
			outputs:    []curlOutputKind{curlOutputStdout},
			wantStdout: true,
		},
		{
			name: "remote name all stops after earlier target",
			argv: []string{
				"curl", "--remote-name-all", "https://one.invalid/a",
				"--no-remote-name-all",
			},
			outputs: []curlOutputKind{curlOutputRemoteName},
		},
		{
			name: "singular no remote name disables all default",
			argv: []string{
				"curl", "--remote-name-all", "--no-remote-name",
				"https://one.invalid/a", "https://two.invalid/b",
			},
			outputs:    []curlOutputKind{curlOutputStdout, curlOutputRemoteName},
			wantStdout: true,
		},
		{
			name: "explicit remote name overrides singular no remote name",
			argv: []string{
				"curl", "--no-remote-name", "-O",
				"https://one.invalid/a",
			},
			outputs: []curlOutputKind{curlOutputRemoteName},
		},
		{
			name: "next resets output slots",
			argv: []string{
				"curl", "-o", "one.bin", "https://one.invalid/a",
				"--next", "https://two.invalid/b",
			},
			outputs:    []curlOutputKind{curlOutputFile, curlOutputStdout},
			wantStdout: true,
		},
		{
			name: "surplus stdout slot does not apply",
			argv: []string{
				"curl", "-o", "one.bin", "-o-", "https://one.invalid/a",
			},
			outputs: []curlOutputKind{curlOutputFile},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parsed := parseCurlArgv(test.argv)
			if !parsed.Complete || len(parsed.Targets) != len(test.outputs) ||
				parsed.provesResponseStdout() != test.wantStdout {
				t.Fatalf("parse = %#v", parsed)
			}
			for index, output := range test.outputs {
				if parsed.Targets[index].Output != output {
					t.Fatalf("target[%d]=%#v, want output=%d", index, parsed.Targets[index], output)
				}
			}
		})
	}
}

func TestParseCurlArgvAssignsUploadSlotsPerTransfer(t *testing.T) {
	t.Parallel()

	parsed := parseCurlArgv([]string{
		"curl", "-T", "first.bin",
		"https://one.invalid/upload", "https://two.invalid/download",
	})
	if !parsed.Complete || len(parsed.Targets) != 2 ||
		!parsed.Targets[0].UploadSet ||
		parsed.Targets[0].UploadValue != "first.bin" ||
		parsed.Targets[1].UploadSet {
		t.Fatalf("parse=%#v", parsed)
	}

	surplus := parseCurlArgv([]string{
		"curl", "-T", "first.bin", "-T", "unused.bin",
		"https://one.invalid/upload",
	})
	if !surplus.Complete || len(surplus.Targets) != 1 ||
		surplus.Targets[0].UploadValue != "first.bin" {
		t.Fatalf("surplus upload parse=%#v", surplus)
	}
}

func TestParseCurlArgvMethodHeadConfigUnknownAndNoTarget(t *testing.T) {
	t.Parallel()

	head := parseCurlArgv([]string{"curl", "-sI", "https://files.invalid/run"})
	if !head.Complete || len(head.Targets) != 1 || !head.Targets[0].Head ||
		head.Targets[0].ResponseBodyStdout ||
		head.responseStdoutState() != curlResponseStdoutNone {
		t.Fatalf("head parse = %#v", head)
	}

	methodHead := parseCurlArgv([]string{
		"curl", "-sXHEAD", "https://files.invalid/run",
	})
	if !methodHead.Complete || len(methodHead.Targets) != 1 ||
		methodHead.Targets[0].Method != "HEAD" ||
		methodHead.Targets[0].ResponseBodyStdout {
		t.Fatalf("method HEAD parse = %#v", methodHead)
	}

	finalGet := parseCurlArgv([]string{
		"curl", "-sXHEAD", "--request", "GET", "https://files.invalid/run",
	})
	if !finalGet.Complete || len(finalGet.Targets) != 1 ||
		finalGet.Targets[0].Method != "GET" ||
		!finalGet.provesResponseStdout() {
		t.Fatalf("final GET parse = %#v", finalGet)
	}

	noHead := parseCurlArgv([]string{
		"curl", "-I", "--no-head", "https://files.invalid/run",
	})
	if !noHead.Complete || len(noHead.Targets) != 1 ||
		noHead.Targets[0].Head || !noHead.provesResponseStdout() {
		t.Fatalf("no-head parse = %#v", noHead)
	}

	config := parseCurlArgv([]string{
		"curl", "-sKconfig", "https://files.invalid/run",
	})
	configOption := requireCurlParsedOption(t, config, "--config")
	if config.Complete || !config.ConfigOpaque || configOption.Value != "config" ||
		len(config.Targets) != 1 ||
		config.responseStdoutState() != curlResponseStdoutUnknown {
		t.Fatalf("config parse = %#v", config)
	}

	unknown := parseCurlArgv([]string{
		"curl", "--future-mode", "https://files.invalid/run",
	})
	if unknown.Complete || len(unknown.Unresolved) != 1 ||
		unknown.responseStdoutState() != curlResponseStdoutUnknown {
		t.Fatalf("unknown parse = %#v", unknown)
	}

	for _, argv := range [][]string{
		{"curl"},
		{"curl", "-s"},
		{"curl", "-o-"},
		{"curl", "-H", "https://files.invalid/run"},
	} {
		parsed := parseCurlArgv(argv)
		if !parsed.Complete || len(parsed.Targets) != 0 ||
			parsed.responseStdoutState() != curlResponseStdoutNone {
			t.Fatalf("no-target argv=%v parse=%#v", argv, parsed)
		}
	}

	for _, argv := range [][]string{
		{"curl", "--next", "https://files.invalid/run"},
		{
			"curl", "https://files.invalid/first", "--next", "--next",
			"https://files.invalid/second",
		},
	} {
		parsed := parseCurlArgv(argv)
		if !parsed.EmptyTransferGroup || parsed.provesResponseStdout() {
			t.Fatalf("empty transfer group argv=%v parse=%#v", argv, parsed)
		}
	}
	trailingEmptyGroup := parseCurlArgv([]string{
		"curl", "https://files.invalid/run", "--next",
	})
	if !trailingEmptyGroup.EmptyTransferGroup ||
		!trailingEmptyGroup.provesResponseStdout() {
		t.Fatalf("trailing empty transfer group parse=%#v", trailingEmptyGroup)
	}

	urlOption := parseCurlArgv([]string{
		"curl", "--url", "https://files.invalid/run",
	})
	if !urlOption.Complete || len(urlOption.Targets) != 1 ||
		!urlOption.Targets[0].ViaURLOption || !urlOption.provesResponseStdout() {
		t.Fatalf("URL option parse = %#v", urlOption)
	}

	preview := parseCurlArgv([]string{
		"curl", "-sV", "https://files.invalid/run",
	})
	if !preview.Complete || !preview.Preview || len(preview.Targets) != 1 ||
		preview.provesResponseStdout() {
		t.Fatalf("preview parse = %#v", preview)
	}
}

func TestParseCurlArgvExactProofRequiresValidValuesAndTarget(t *testing.T) {
	t.Parallel()

	for _, argv := range [][]string{
		{"curl", "-m", "soon", "https://files.invalid/run"},
		{"curl", "--connect-timeout=1m", "https://files.invalid/run"},
		{"curl", "-F", "", "https://files.invalid/run"},
		{"curl", "-D", "", "https://files.invalid/run"},
		{"curl", "-"},
	} {
		parsed := parseCurlArgv(argv)
		if parsed.provesResponseStdout() {
			t.Fatalf("invalid argv=%v proved response stdout: %#v", argv, parsed)
		}
	}

	for _, argv := range [][]string{
		{"curl", "-m", "0.5", "https://files.invalid/run"},
		{"curl", "-H", "", "https://files.invalid/run"},
		{"curl", "-d", "", "https://files.invalid/run"},
	} {
		parsed := parseCurlArgv(argv)
		if !parsed.provesResponseStdout() {
			t.Fatalf("valid argv=%v did not prove response stdout: %#v", argv, parsed)
		}
	}
}

func requireCurlParsedOption(
	t *testing.T,
	parsed curlArgvParse,
	canonical string,
) curlOptionToken {
	t.Helper()
	for _, option := range parsed.Options {
		if option.Canonical == canonical {
			return option
		}
	}
	t.Fatalf("missing option %q in %#v", canonical, parsed.Options)
	return curlOptionToken{}
}

func curlParsedOptionExists(parsed curlArgvParse, canonical string) bool {
	for _, option := range parsed.Options {
		if option.Canonical == canonical {
			return true
		}
	}
	return false
}
