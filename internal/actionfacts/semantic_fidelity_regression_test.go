// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

func TestSemanticFidelityPowerShellNewItemPreservesLiteralWhitespace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      Input
		want       string
		retargeted string
	}{
		{
			name: "raw leading whitespace",
			input: Input{
				Tool:        "powershell",
				Command:     `New-Item -Path ' /etc/cron.d/persist' -ItemType File`,
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       " /etc/cron.d/persist",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "raw trailing whitespace",
			input: Input{
				Tool:        "powershell",
				Command:     `New-Item -Path '/etc/cron.d/persist ' -ItemType File`,
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       "/etc/cron.d/persist ",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "raw joined parent",
			input: Input{
				Tool:        "powershell",
				Command:     `New-Item -Path ' /etc/cron.d' -Name persist -ItemType File`,
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       " /etc/cron.d/persist",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "raw joined name",
			input: Input{
				Tool:        "powershell",
				Command:     `New-Item -Path /etc/cron.d -Name 'persist ' -ItemType File`,
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       "/etc/cron.d/persist ",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "structured leading whitespace",
			input: Input{
				Tool: "powershell",
				Argv: []string{
					"New-Item", "-Path", " /etc/cron.d/persist",
					"-ItemType", "File",
				},
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       " /etc/cron.d/persist",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "structured trailing whitespace",
			input: Input{
				Tool: "powershell",
				Argv: []string{
					"New-Item", "-Path", "/etc/cron.d/persist ",
					"-ItemType", "File",
				},
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       "/etc/cron.d/persist ",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "structured joined parent",
			input: Input{
				Tool: "powershell",
				Argv: []string{
					"New-Item", "-Path", " /etc/cron.d", "-Name", "persist",
					"-ItemType", "File",
				},
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       " /etc/cron.d/persist",
			retargeted: "/etc/cron.d/persist",
		},
		{
			name: "structured joined name",
			input: Input{
				Tool: "powershell",
				Argv: []string{
					"New-Item", "-Path", "/etc/cron.d", "-Name", "persist ",
					"-ItemType", "File",
				},
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			want:       "/etc/cron.d/persist ",
			retargeted: "/etc/cron.d/persist",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(test.input)
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("exact New-Item operand lost authority: %#v", facts)
			}
			if !factsHavePath(facts, PathAccessWrite, test.want) {
				t.Fatalf("literal New-Item target was not preserved: %#v", facts)
			}
			if factsHavePath(facts, PathAccessWrite, test.retargeted) {
				t.Fatalf("New-Item target was silently retargeted: %#v", facts)
			}
		})
	}

	t.Run("unicode whitespace never retargets", func(t *testing.T) {
		t.Parallel()

		const (
			literal    = "\u00a0/etc/cron.d/persist\u00a0"
			retargeted = "/etc/cron.d/persist"
		)
		for _, input := range []Input{
			{
				Tool:        "powershell",
				Command:     "New-Item -Path '" + literal + "' -ItemType File",
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
			{
				Tool: "powershell",
				Argv: []string{
					"New-Item", "-Path", literal, "-ItemType", "File",
				},
				DialectHint: DialectPowerShell,
				CWD:         "/work",
			},
		} {
			facts := Analyze(input)
			if factsHavePath(facts, PathAccessWrite, retargeted) {
				t.Fatalf("Unicode whitespace was stripped from New-Item: %#v", facts)
			}
			if facts.Authoritative() &&
				!factsHavePath(facts, PathAccessWrite, literal) {
				t.Fatalf("authoritative Unicode target was not byte-exact: %#v", facts)
			}
		}
	})
}

func TestSemanticFidelityDevRedirectWhitespaceRemainsAFile(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		command string
		target  string
		access  PathAccess
	}{
		{
			name:    "write leading TCP",
			command: "printf x > ",
			target:  " /dev/tcp/example.com/443",
			access:  PathAccessWrite,
		},
		{
			name:    "write trailing UDP",
			command: "printf x > ",
			target:  "/dev/udp/example.com/53\u00a0",
			access:  PathAccessWrite,
		},
		{
			name:    "read leading TCP",
			command: "cat < ",
			target:  "\u00a0/dev/tcp/example.com/443",
			access:  PathAccessRead,
		},
		{
			name:    "read trailing UDP",
			command: "cat < ",
			target:  "/dev/udp/example.com/53 ",
			access:  PathAccessRead,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool:        "shell",
				Command:     test.command + "'" + test.target + "'",
				DialectHint: DialectPOSIX,
				CWD:         "/work",
			})
			if !facts.Authoritative() || !facts.EnforcementEligible() {
				t.Fatalf("literal file redirect lost authority: %#v", facts)
			}
			if len(facts.Commands) != 1 || len(facts.Network) != 0 ||
				commandHasOperation(facts.Commands[0], OperationConnect) {
				t.Fatalf("spaced file redirect became a network socket: %#v", facts)
			}
			if !factsHavePath(facts, test.access, test.target) {
				t.Fatalf("literal redirect path was not preserved: %#v", facts)
			}
			for _, flow := range facts.DataFlows {
				if flow.From == DataNetwork || flow.To == DataNetwork {
					t.Fatalf("literal file redirect gained network flow: %#v", facts)
				}
			}
		})
	}

	exact := Analyze(Input{
		Tool:        "shell",
		Command:     "printf x > /dev/tcp/example.com/443",
		DialectHint: DialectPOSIX,
	})
	if !exact.Authoritative() || len(exact.Commands) != 1 ||
		len(exact.Network) != 1 ||
		!commandHasOperation(exact.Commands[0], OperationConnect) ||
		len(exact.Paths) != 0 {
		t.Fatalf("exact /dev/tcp control lost network semantics: %#v", exact)
	}
}

func TestSemanticFidelityWhitespaceNetworkOperandsFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input Input
	}{
		{
			name: "POSIX netcat raw",
			input: Input{
				Tool:        "shell",
				Command:     `nc ' example.com' 443`,
				DialectHint: DialectPOSIX,
			},
		},
		{
			name:  "netcat argv",
			input: Input{Tool: "shell", Argv: []string{"nc", "example.com ", "443"}},
		},
		{
			name: "nmap raw",
			input: Input{
				Tool:        "shell",
				Command:     `nmap ' 10.0.0.1'`,
				DialectHint: DialectPOSIX,
			},
		},
		{
			name:  "masscan argv",
			input: Input{Tool: "shell", Argv: []string{"masscan", "10.0.0.1 "}},
		},
		{
			name:  "fping argv",
			input: Input{Tool: "shell", Argv: []string{"fping", "\u00a0example.com"}},
		},
		{
			name:  "chisel argv",
			input: Input{Tool: "shell", Argv: []string{"chisel", "client", " example.com:8080"}},
		},
		{
			name:  "socat argv",
			input: Input{Tool: "shell", Argv: []string{"socat", "STDIO", "TCP:example.com:443 "}},
		},
		{
			name: "CMD ncat raw",
			input: Input{
				Tool:        "cmd",
				Command:     `ncat.exe " example.com" 443`,
				DialectHint: DialectCMD,
			},
		},
		{
			name: "PowerShell ncat raw",
			input: Input{
				Tool:        "powershell",
				Command:     `ncat.exe 'example.com ' 443`,
				DialectHint: DialectPowerShell,
			},
		},
		{
			name: "CMD ncat argv",
			input: Input{
				Tool:        "cmd",
				Argv:        []string{"ncat.exe", " example.com", "443"},
				DialectHint: DialectCMD,
			},
		},
		{
			name: "PowerShell ncat argv",
			input: Input{
				Tool:        "powershell",
				Argv:        []string{"ncat.exe", "example.com ", "443"},
				DialectHint: DialectPowerShell,
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(test.input)
			if facts.Authoritative() || facts.EnforcementEligible() ||
				len(facts.Network) != 0 {
				t.Fatalf("whitespace-bearing endpoint was retargeted: %#v", facts)
			}
			if !containsIssue(facts.Parse.Issues, IssueUnknownOperandGrammar) {
				t.Fatalf("endpoint rejection lost its closed issue code: %#v", facts)
			}
		})
	}
}

func TestSemanticFidelityExactNetworkControlsRemainAuthoritative(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name     string
		input    Input
		wantHost string
	}{
		{
			name:     "netcat",
			input:    Input{Tool: "shell", Argv: []string{"nc", "example.com", "443"}},
			wantHost: "example.com",
		},
		{
			name:     "nmap",
			input:    Input{Tool: "shell", Argv: []string{"nmap", "10.0.0.1"}},
			wantHost: "10.0.0.1",
		},
		{
			name:     "chisel",
			input:    Input{Tool: "shell", Argv: []string{"chisel", "client", "example.com:8080"}},
			wantHost: "example.com",
		},
		{
			name:     "socat",
			input:    Input{Tool: "shell", Argv: []string{"socat", "STDIO", "TCP:example.com:443"}},
			wantHost: "example.com",
		},
		{
			name:     "Windows ncat",
			wantHost: "example.com",
			input: Input{
				Tool:        "cmd",
				Command:     `ncat.exe example.com 443`,
				DialectHint: DialectCMD,
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(test.input)
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				len(facts.Network) != 1 ||
				facts.Network[0].NormalizedHost != test.wantHost {
				t.Fatalf("exact network control lost semantics: %#v", facts)
			}
		})
	}
}

func TestSemanticFidelityNetworkCanonicalizersNeverDeleteWhitespace(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		" example.com",
		"example.com ",
		"\texample.com",
		"example.com\n",
		"\u00a0example.com",
		"10.0.0.1, 10.0.0.2",
		"10.0.0.1 ,10.0.0.2",
		"10.0.0.1 -10.0.0.2",
		"10.0.0.1- 10.0.0.2",
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			normalized, _, kind, prefixLength := deriveNetworkTarget(value)
			if normalized != "" || kind != NetworkTargetUnknown ||
				prefixLength != 0 {
				t.Fatalf(
					"deriveNetworkTarget(%q) retargeted to (%q, %q, %d)",
					value,
					normalized,
					kind,
					prefixLength,
				)
			}
			if !strings.Contains(value, ",") && !strings.Contains(value, " -") &&
				!strings.Contains(value, "- ") {
				if host, ok := canonicalNetworkHost(value); ok || host != "" {
					t.Fatalf(
						"canonicalNetworkHost(%q) = (%q, true), want rejection",
						value,
						host,
					)
				}
			}
		})
	}

	for value, wantKind := range map[string]NetworkTargetKind{
		"example.com":          NetworkTargetSingleHost,
		"10.0.0.1,10.0.0.2":    NetworkTargetList,
		"10.0.0.1-10.0.0.2":    NetworkTargetRange,
		"10.0.0.1,10.0.0.2/32": NetworkTargetList,
	} {
		value := value
		wantKind := wantKind
		t.Run("control "+value, func(t *testing.T) {
			t.Parallel()

			normalized, _, kind, _ := deriveNetworkTarget(value)
			if normalized == "" || kind != wantKind {
				t.Fatalf(
					"deriveNetworkTarget(%q) = (%q, %q), want kind %q",
					value,
					normalized,
					kind,
					wantKind,
				)
			}
		})
	}
}

func TestSemanticFidelityWhitespaceDeviceLookalikesStayOrdinary(t *testing.T) {
	t.Parallel()

	for _, input := range []Input{
		{
			Tool:        "shell",
			Command:     `cat ' /dev/null '`,
			DialectHint: DialectPOSIX,
		},
		{
			Tool: "shell",
			Argv: []string{"dd", "if=/tmp/in", "of= /dev/sda"},
		},
	} {
		facts := Analyze(input)
		if !facts.Authoritative() {
			t.Fatalf("literal relative path unexpectedly lost authority: %#v", facts)
		}
		for _, pathFact := range facts.Paths {
			if pathFact.Flavor == PathFlavorDevice {
				t.Fatalf("spaced relative path became a device: %#v", facts)
			}
		}
		for _, command := range facts.Commands {
			if commandHasOperation(command, OperationDiskWrite) {
				t.Fatalf("spaced relative path became a disk write: %#v", facts)
			}
		}
	}

	exact := Analyze(Input{
		Tool: "shell",
		Argv: []string{"dd", "if=/tmp/in", "of=/dev/sda"},
	})
	if !exact.Authoritative() || len(exact.Commands) != 1 ||
		!commandHasOperation(exact.Commands[0], OperationDiskWrite) {
		t.Fatalf("exact block-device control lost disk semantics: %#v", exact)
	}
}

func TestSemanticFidelityWindowsWhitespaceHelpersDoNotRetarget(t *testing.T) {
	t.Parallel()

	for _, value := range []string{" del", "del ", "\tdel", "\u00a0del"} {
		if got := windowsExecutable(value); got != "" {
			t.Errorf("windowsExecutable(%q) = %q, want rejection", value, got)
		}
	}
	if got := windowsExecutable(`C:\Windows\System32\DEL.EXE`); got != "del.exe" {
		t.Fatalf("exact Windows executable control = %q, want del.exe", got)
	}
	for _, value := range []string{
		` \\.\PhysicalDrive0`,
		`\\.\PhysicalDrive0 `,
	} {
		if got := windowsPathFlavor(value); got == PathFlavorDevice {
			t.Errorf("windowsPathFlavor(%q) retargeted to device", value)
		}
	}
}

func TestSemanticFidelityDockerMountWhitespaceOwnership(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"type=bind,source= /etc,target=/mnt",
		"type=bind, source=/etc,target=/mnt",
		"type= bind,source=/etc,target=/mnt",
		"type=bind,source=/etc,target= /mnt",
		"type=bind,source=/etc,target=/mnt,readonly= true",
	} {
		value := value
		t.Run("reject "+value, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool: "shell",
				Argv: []string{
					"docker", "run", "--mount", value, "alpine",
				},
			})
			if facts.Authoritative() || facts.EnforcementEligible() ||
				factsHavePath(facts, PathAccessRead, "/etc") ||
				factsHavePath(facts, PathAccessWrite, "/etc") {
				t.Fatalf("invalid Docker mount field was retargeted: %#v", facts)
			}
		})
	}

	for _, value := range []string{
		"type=bind,source=/etc,target=/mnt",
		" type=bind,source=/etc,target=/mnt ",
	} {
		value := value
		t.Run("accept "+value, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(Input{
				Tool: "shell",
				Argv: []string{
					"docker", "run", "--mount", value, "alpine",
				},
			})
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				!factsHavePath(facts, PathAccessRead, "/etc") ||
				!factsHavePath(facts, PathAccessWrite, "/etc") {
				t.Fatalf("owned Docker mount control lost semantics: %#v", facts)
			}
		})
	}
}

func TestSemanticFidelityWindowsSuperscriptDeviceAliasesFailClosed(t *testing.T) {
	t.Parallel()

	for _, prefix := range []string{"COM", "LPT"} {
		for _, digit := range []string{"¹", "²", "³"} {
			component := prefix + digit + ".txt"
			if !windowsReservedDeviceComponent(component) {
				t.Errorf("%q was not recognized as a reserved device", component)
			}
			if !windowsReservedDeviceComponent(strings.ToLower(component) + ":stream") {
				t.Errorf("%q ADS form was not recognized as reserved", component)
			}
			value := `C:\Temp\` + component
			facts := Analyze(Input{
				Tool:        "powershell",
				Argv:        []string{"Remove-Item", "-LiteralPath", value, "-Force"},
				DialectHint: DialectPowerShell,
			})
			if facts.Authoritative() || facts.EnforcementEligible() ||
				len(facts.Paths) != 0 {
				t.Errorf("reserved alias %q became a file: %#v", component, facts)
			}
		}
	}

	for _, test := range []struct {
		name  string
		input Input
	}{
		{
			name: "raw PowerShell COM1 superscript",
			input: Input{
				Tool:        "powershell",
				Command:     `Remove-Item -LiteralPath 'C:\Temp\COM¹.txt' -Force`,
				DialectHint: DialectPowerShell,
			},
		},
		{
			name: "raw CMD COM2 superscript",
			input: Input{
				Tool:        "cmd",
				Command:     `del /F C:\Temp\COM².log`,
				DialectHint: DialectCMD,
			},
		},
		{
			name: "structured PowerShell LPT3 superscript",
			input: Input{
				Tool:        "powershell",
				Argv:        []string{"Remove-Item", "-LiteralPath", `C:\Temp\LPT³.txt`, "-Force"},
				DialectHint: DialectPowerShell,
			},
		},
		{
			name: "structured CMD LPT2 superscript",
			input: Input{
				Tool:        "cmd",
				Argv:        []string{"del", "/F", `C:\Temp\LPT².log`},
				DialectHint: DialectCMD,
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			facts := Analyze(test.input)
			if facts.Authoritative() || facts.EnforcementEligible() ||
				len(facts.Paths) != 0 {
				t.Fatalf("reserved Windows device alias became a file: %#v", facts)
			}
			if !containsIssue(facts.Parse.Issues, IssueUnknownOperandGrammar) {
				t.Fatalf("reserved alias rejection lost issue code: %#v", facts)
			}
		})
	}

	for _, component := range []string{"COM10.txt", "LPT10.log", "COM⁴.txt", "LPT⁴.log"} {
		component := component
		t.Run("ordinary "+component, func(t *testing.T) {
			t.Parallel()

			if windowsReservedDeviceComponent(component) {
				t.Fatalf("ordinary lookalike %q became reserved", component)
			}
			value := `C:\Temp\` + component
			facts := Analyze(Input{
				Tool:        "powershell",
				Argv:        []string{"Remove-Item", "-LiteralPath", value, "-Force"},
				DialectHint: DialectPowerShell,
			})
			if !facts.Authoritative() || !factsHavePath(facts, PathAccessDelete, value) {
				t.Fatalf("ordinary Windows lookalike lost file semantics: %#v", facts)
			}
		})
	}
}
