// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

func TestAnalyzeNormalizesStructuredPathFacts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       Input
		wantValue   string
		wantNormal  string
		wantAbs     bool
		wantResolve string
	}{
		{
			name: "POSIX relative path and extracted CWD",
			input: Input{
				Tool: "Read",
				Args: []byte(`{
					"path": "./fixtures/../fixtures/etc/passwd",
					"cwd": "/repo/./work/.."
				}`),
			},
			wantValue:   "./fixtures/../fixtures/etc/passwd",
			wantNormal:  "fixtures/etc/passwd",
			wantResolve: "/repo/fixtures/etc/passwd",
		},
		{
			name: "POSIX absolute dot segments",
			input: Input{
				Tool: "Read",
				Args: []byte(`{"path":"/var/../etc/passwd","cwd":"/repo"}`),
			},
			wantValue:   "/var/../etc/passwd",
			wantNormal:  "/etc/passwd",
			wantAbs:     true,
			wantResolve: "/etc/passwd",
		},
		{
			name: "Windows relative path and extracted CWD",
			input: Input{
				Tool: "Read",
				Args: []byte(`{
					"path": ".\\fixtures\\..\\secret.txt",
					"cwd": "C:\\repo\\.\\work\\.."
				}`),
			},
			wantValue:   `.\fixtures\..\secret.txt`,
			wantNormal:  "secret.txt",
			wantResolve: "C:/repo/secret.txt",
		},
		{
			name: "Windows CWD with neutral relative separators",
			input: Input{
				Tool: "Read",
				Args: []byte(`{
					"path": "fixtures/../secret.txt",
					"cwd": "C:\\repo"
				}`),
			},
			wantValue:   "fixtures/../secret.txt",
			wantNormal:  "secret.txt",
			wantResolve: "C:/repo/secret.txt",
		},
		{
			name: "Windows absolute dot segments",
			input: Input{
				Tool: "Read",
				Args: []byte(`{
					"path": "c:\\repo\\.\\fixtures\\..\\secret.txt",
					"cwd": "D:\\other"
				}`),
			},
			wantValue:   `c:\repo\.\fixtures\..\secret.txt`,
			wantNormal:  "C:/repo/secret.txt",
			wantAbs:     true,
			wantResolve: "C:/repo/secret.txt",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			if !facts.Authoritative() || len(facts.Paths) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			path := facts.Paths[0]
			if path.Value != test.wantValue ||
				path.Normalized != test.wantNormal ||
				path.Absolute != test.wantAbs ||
				path.Resolved != test.wantResolve {
				t.Fatalf("path = %#v", path)
			}
		})
	}
}

func TestNormalizedPathFlavorTracksEffectiveStaticTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fact        PathFact
		cwd         string
		wantFlavor  PathFlavor
		wantResolve string
	}{
		{
			name: "POSIX path normalizes into device directory",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "/tmp/../dev/sda",
			},
			wantFlavor: PathFlavorDevice, wantResolve: "/dev/sda",
		},
		{
			name: "device-looking path normalizes out of device directory",
			fact: PathFact{
				Flavor: PathFlavorDevice,
				Value:  "/dev/../tmp/fixture.img",
			},
			wantFlavor: PathFlavorPOSIX, wantResolve: "/tmp/fixture.img",
		},
		{
			name: "relative path resolves into device directory",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "../dev/loop0",
			},
			cwd: "/tmp", wantFlavor: PathFlavorDevice,
			wantResolve: "/dev/loop0",
		},
		{
			name: "Windows filesystem path stays Windows",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `C:\tmp\..\fixture.txt`,
			},
			wantFlavor:  PathFlavorWindows,
			wantResolve: "C:/fixture.txt",
		},
		{
			name: "Windows physical drive stays a device",
			fact: PathFact{
				Flavor: PathFlavorDevice,
				Value:  `\\.\PhysicalDrive0`,
			},
			wantFlavor:  PathFlavorDevice,
			wantResolve: "//./PhysicalDrive0",
		},
		{
			name: "registry path stays registry",
			fact: PathFact{
				Flavor: PathFlavorRegistry,
				Value:  `HKEY_LOCAL_MACHINE\SAM`,
			},
			wantFlavor: PathFlavorRegistry, wantResolve: "HKLM/SAM",
		},
		{
			name: "unresolved bare operand stays unknown",
			fact: PathFact{
				Flavor: PathFlavorUnknown,
				Value:  "fixture.img",
			},
			wantFlavor: PathFlavorUnknown,
		},
		{
			name: "rooted POSIX unknown path preserves literal backslash",
			fact: PathFact{
				Flavor: PathFlavorUnknown,
				Value:  `/tmp/we\ird`,
			},
			wantFlavor: PathFlavorPOSIX, wantResolve: `/tmp/we\ird`,
		},
		{
			name: "rooted POSIX device path preserves literal backslash",
			fact: PathFact{
				Flavor: PathFlavorDevice,
				Value:  `/tmp/we\ird`,
			},
			wantFlavor: PathFlavorPOSIX, wantResolve: `/tmp/we\ird`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := []PathFact{test.fact}
			normalizePathFacts(facts, test.cwd)
			if facts[0].Flavor != test.wantFlavor ||
				facts[0].Resolved != test.wantResolve {
				t.Fatalf("path=%#v", facts[0])
			}
		})
	}
}

func TestPathResolutionRequiresCompatibleStaticCWD(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fact        PathFact
		cwd         string
		wantNormal  string
		wantAbs     bool
		wantResolve string
	}{
		{
			name: "Windows relative path with POSIX CWD",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `.\secret.txt`,
			},
			cwd:        "/repo",
			wantNormal: "secret.txt",
		},
		{
			name: "POSIX relative path with Windows CWD",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "./secret.txt",
			},
			cwd:        `C:\repo`,
			wantNormal: "secret.txt",
		},
		{
			name: "Windows drive-relative path with other drive CWD",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `D:secret.txt`,
			},
			cwd:        `C:\repo`,
			wantNormal: "D:secret.txt",
		},
		{
			name: "tilde remains unresolved",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "~/.ssh/../id_ed25519",
			},
			cwd:        "/repo",
			wantNormal: "~/.ssh/../id_ed25519",
		},
		{
			name: "POSIX variable remains unresolved",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "$HOME/../secret",
			},
			cwd:        "/repo",
			wantNormal: "$HOME/../secret",
		},
		{
			name: "structured Windows percent content is literal",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `%USERPROFILE%\..\secret`,
			},
			cwd:         `C:\repo`,
			wantNormal:  "secret",
			wantResolve: `C:/repo/secret`,
		},
		{
			name: "POSIX CWD preserves literal backslash",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "secret.txt",
			},
			cwd:         `/tmp/we\ird`,
			wantNormal:  "secret.txt",
			wantResolve: `/tmp/we\ird/secret.txt`,
		},
		{
			name: "unknown path follows rooted POSIX CWD with literal backslash",
			fact: PathFact{
				Flavor: PathFlavorUnknown,
				Value:  "secret.txt",
			},
			cwd:         `/tmp/we\ird`,
			wantNormal:  "secret.txt",
			wantResolve: `/tmp/we\ird/secret.txt`,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			normalized, absolute, resolved := derivePath(test.fact, test.cwd)
			if normalized != test.wantNormal ||
				absolute != test.wantAbs ||
				resolved != test.wantResolve {
				t.Fatalf(
					"derivePath(%#v, %q) = (%q, %v, %q)",
					test.fact,
					test.cwd,
					normalized,
					absolute,
					resolved,
				)
			}
		})
	}
}

func TestDollarPathSyntaxDistinguishesExpansionsFromWindowsNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		fact        PathFact
		cwd         string
		wantNormal  string
		wantAbs     bool
		wantResolve string
	}{
		{
			name: "POSIX name expansion stays unresolved",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "$HOME/../secret",
			},
			cwd:        "/repo",
			wantNormal: "$HOME/../secret",
		},
		{
			name: "POSIX braced expansion stays unresolved",
			fact: PathFact{
				Flavor: PathFlavorPOSIX,
				Value:  "${HOME}/../secret",
			},
			cwd:        "/repo",
			wantNormal: "${HOME}/../secret",
		},
		{
			name: "PowerShell name expansion stays unresolved",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `C:\Users\$name\..\secret`,
			},
			cwd:        `C:\repo`,
			wantNormal: "C:/Users/$name/../secret",
			wantAbs:    true,
		},
		{
			name: "Windows administrative share is literal",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `\\host\C$\dir\..\secret`,
			},
			wantNormal:  "//host/C$/secret",
			wantAbs:     true,
			wantResolve: "//host/C$/secret",
		},
		{
			name: "Windows device name is literal",
			fact: PathFact{
				Flavor: PathFlavorDevice,
				Value:  `\\.\CONOUT$`,
			},
			wantNormal:  "//./CONOUT$",
			wantAbs:     true,
			wantResolve: "//./CONOUT$",
		},
		{
			name: "relative Windows device name resolves",
			fact: PathFact{
				Flavor: PathFlavorWindows,
				Value:  `CONOUT$`,
			},
			cwd:         `C:\work`,
			wantNormal:  "CONOUT$",
			wantResolve: "C:/work/CONOUT$",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			normalized, absolute, resolved := derivePath(
				test.fact,
				test.cwd,
			)
			if normalized != test.wantNormal ||
				absolute != test.wantAbs ||
				resolved != test.wantResolve {
				t.Fatalf(
					"derivePath(%#v, %q) = (%q, %v, %q), want (%q, %v, %q)",
					test.fact,
					test.cwd,
					normalized,
					absolute,
					resolved,
					test.wantNormal,
					test.wantAbs,
					test.wantResolve,
				)
			}
		})
	}
}

func TestWindowsContextPathsMustBeExact(t *testing.T) {
	tests := []struct {
		name        string
		input       Input
		wantInvalid bool
	}{
		{
			name: "direct CWD glob",
			input: Input{
				Argv:        []string{"Get-Content", "secret.txt"},
				CWD:         `C:\work*`,
				DialectHint: DialectPowerShell,
			},
		},
		{
			name: "Args-derived CWD wildcard",
			input: Input{
				Tool: "Read",
				Args: []byte(`{
					"path": "secret.txt",
					"cwd": "C:\\work?"
				}`),
			},
		},
		{
			name: "active home glob",
			input: Input{
				Argv:        []string{"Get-Content", `~\secret.txt`},
				ActiveHome:  `C:\Users\*`,
				DialectHint: DialectPowerShell,
			},
			wantInvalid: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(test.input)
			if test.wantInvalid {
				if facts.Parse.Status != StatusInvalid ||
					!containsIssue(facts.Parse.Issues, IssueInvalidSyntax) ||
					facts.Authoritative() ||
					facts.EnforcementEligible() ||
					facts.ActiveHome != "" {
					t.Fatalf("inexact active home remained authoritative: %#v", facts)
				}
				return
			}
			if !facts.Authoritative() || len(facts.Paths) != 1 ||
				facts.Paths[0].Resolved != "" {
				t.Fatalf("inexact CWD resolved an exact target: %#v", facts)
			}
		})
	}
}

func TestExtendedWindowsContextPathsRemainExact(t *testing.T) {
	cwd := Analyze(Input{
		Argv:        []string{"Get-Content", "secret.txt"},
		CWD:         `\\?\C:\work`,
		DialectHint: DialectPowerShell,
	})
	if !cwd.Authoritative() || len(cwd.Paths) != 1 ||
		cwd.Paths[0].Resolved != "C:/work/secret.txt" {
		t.Fatalf("extended CWD did not resolve exactly: %#v", cwd)
	}

	activeHome := Analyze(Input{
		Argv:        []string{"Get-Content", `~\secret.txt`},
		ActiveHome:  `\\?\C:\Users\fixture`,
		DialectHint: DialectPowerShell,
	})
	if !activeHome.Authoritative() ||
		activeHome.ActiveHome != "C:/Users/fixture" ||
		len(activeHome.Paths) != 1 ||
		activeHome.Paths[0].Resolved != "C:/Users/fixture/secret.txt" {
		t.Fatalf("extended active home did not resolve exactly: %#v", activeHome)
	}
}

func TestStructuredPOSIXWildcardCharactersRemainLiteral(t *testing.T) {
	for _, value := range []string{"report?.txt", "*.txt"} {
		facts := Analyze(Input{
			Argv: []string{"cat", value},
			CWD:  "/repo",
		})
		if !facts.Authoritative() || len(facts.Paths) != 1 ||
			facts.Paths[0].Normalized != value ||
			facts.Paths[0].Resolved != "/repo/"+value {
			t.Fatalf(
				"structured POSIX filename %q lost literal semantics: %#v",
				value,
				facts,
			)
		}
	}
}

func TestResolvedPathsDistinguishActiveTargetsFromRepositoryFixtures(t *testing.T) {
	t.Parallel()

	active := Analyze(Input{
		Tool: "Read",
		Args: []byte(`{"path":"/etc/shadow","cwd":"/repo"}`),
	})
	fixture := Analyze(Input{
		Tool: "Read",
		Args: []byte(`{"path":"testdata/etc/shadow","cwd":"/repo"}`),
	})
	if len(active.Paths) != 1 || len(fixture.Paths) != 1 {
		t.Fatalf("active=%#v fixture=%#v", active, fixture)
	}
	if got := active.Paths[0].Resolved; got != "/etc/shadow" {
		t.Fatalf("active resolved path = %q", got)
	}
	if got := fixture.Paths[0].Resolved; got != "/repo/testdata/etc/shadow" {
		t.Fatalf("fixture resolved path = %q", got)
	}
}

func TestAnalyzeNormalizesBareRelativePathAcrossCWDFlavors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		cwd          string
		wantResolved string
	}{
		{name: "empty CWD"},
		{name: "POSIX CWD", cwd: "/repo", wantResolved: "/repo/targets.txt"},
		{name: "Windows CWD", cwd: `C:\repo`, wantResolved: "C:/repo/targets.txt"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			facts := Analyze(Input{
				Tool: "Read",
				Args: []byte(`{"path":"targets.txt"}`),
				CWD:  test.cwd,
			})
			if !facts.Authoritative() || len(facts.Paths) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			path := facts.Paths[0]
			if path.Value != "targets.txt" ||
				path.Normalized != "targets.txt" ||
				path.Absolute ||
				path.Resolved != test.wantResolved {
				t.Fatalf("path = %#v", path)
			}
		})
	}
}

func TestWindowsSpecialPathNormalization(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		value      string
		normalized string
		absolute   bool
		resolved   string
	}{
		{
			name:       "filesystem provider",
			value:      `Microsoft.PowerShell.Core\FileSystem::C:\Windows\win.ini`,
			normalized: "C:/Windows/win.ini",
			absolute:   true,
			resolved:   "C:/Windows/win.ini",
		},
		{
			name:       "extended drive",
			value:      `\\?\c:\Windows\win.ini`,
			normalized: "C:/Windows/win.ini",
			absolute:   true,
			resolved:   "C:/Windows/win.ini",
		},
		{
			name:       "extended UNC",
			value:      `\\?\UNC\server\share\secret.txt`,
			normalized: "//server/share/secret.txt",
			absolute:   true,
			resolved:   "//server/share/secret.txt",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			normalized, absolute, resolved := derivePath(PathFact{
				Flavor: PathFlavorWindows,
				Value:  test.value,
			}, "")
			if normalized != test.normalized ||
				absolute != test.absolute ||
				resolved != test.resolved {
				t.Fatalf(
					"derivePath(%q) = (%q, %t, %q)",
					test.value,
					normalized,
					absolute,
					resolved,
				)
			}
		})
	}

	for _, value := range []string{
		`Microsoft.PowerShell.Core\FileSystem:C:\secret.txt`,
		`Microsoft.PowerShell.Core\FileSystem::`,
		`Microsoft.PowerShell.Core\Registry::HKLM:\SAM`,
		`Microsoft.PowerShell.Core/FileSystem::C:\secret.txt`,
		`\\?\GLOBALROOT\Device\HarddiskVolume1\secret`,
		`\\?\C:\safe\..\secret.txt`,
		`\\?\C:\safe\CON.txt`,
		`\\?\UNC\server`,
	} {
		value := value
		t.Run("unsafe "+value, func(t *testing.T) {
			normalized, _, resolved := derivePath(PathFact{
				Flavor: PathFlavorWindows,
				Value:  value,
			}, `C:\repo`)
			if normalized == "" || resolved != "" {
				t.Fatalf(
					"unsafe special path %q resolved as (%q, %q)",
					value,
					normalized,
					resolved,
				)
			}
		})
	}
}

func TestPowerShellFilesystemProviderRejectsNestedProviders(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`Microsoft.PowerShell.Core\FileSystem::Variable::secret`,
		`Microsoft.PowerShell.Core\FileSystem::Environment::PATH`,
		`Microsoft.PowerShell.Core\FileSystem::Microsoft.PowerShell.Core\Registry::HKLM:\SAM`,
	} {
		if canonical, ok := canonicalWindowsFilesystemPath(value); ok {
			t.Errorf("nested provider %q canonicalized to %q", value, canonical)
		}
	}

	const filesystemPath = `Microsoft.PowerShell.Core\FileSystem::C:\Windows\win.ini`
	if canonical, ok := canonicalWindowsFilesystemPath(filesystemPath); !ok ||
		canonical != `C:\Windows\win.ini` {
		t.Fatalf(
			"filesystem provider path canonicalized to (%q, %t)",
			canonical,
			ok,
		)
	}
}

func TestPowerShellNonFilesystemProviderDrivesFailClosed(t *testing.T) {
	t.Parallel()

	for _, provider := range []string{
		"Variable",
		"Cert",
		"Function",
		"Alias",
		"WSMan",
	} {
		provider := provider
		t.Run(provider, func(t *testing.T) {
			t.Parallel()

			for _, value := range []string{
				provider + `:\fixture`,
				strings.ToUpper(provider) + ":/fixture",
				strings.ToLower(provider) + ":fixture",
				`Microsoft.PowerShell.Core\FileSystem::` +
					provider + `:\fixture`,
			} {
				if canonical, ok := canonicalWindowsFilesystemPath(value); ok {
					t.Errorf(
						"non-filesystem provider path %q canonicalized to %q",
						value,
						canonical,
					)
				}

				normalized, absolute, resolved := derivePath(PathFact{
					Flavor: PathFlavorWindows,
					Value:  value,
				}, `C:\repo`)
				if normalized == "" || absolute || resolved != "" {
					t.Errorf(
						"non-filesystem provider path %q derived as (%q, %t, %q)",
						value,
						normalized,
						absolute,
						resolved,
					)
				}
			}
		})
	}

	for _, value := range []string{
		`Secrets:\fixture`,
		`SECRETS:/fixture`,
		`Microsoft.PowerShell.Core\FileSystem::Secrets:\fixture`,
	} {
		if canonical, ok := canonicalWindowsFilesystemPath(value); ok {
			t.Errorf(
				"custom provider path %q canonicalized to %q",
				value,
				canonical,
			)
		}
	}
}

func TestAnalyzePowerShellNonFilesystemProvidersDoNotMintPaths(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`Variable:\fixture`,
		`CERT:/fixture`,
		`function:\fixture`,
		`ALIAS:/fixture`,
		`wsman:\fixture`,
		`Secrets:\fixture`,
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			for _, input := range []Input{
				{
					Tool:        "powershell",
					Command:     `Get-Content '` + value + `'`,
					DialectHint: DialectPowerShell,
				},
				{
					Tool:        "powershell",
					Argv:        []string{"Get-Content", value},
					DialectHint: DialectPowerShell,
				},
			} {
				facts := Analyze(input)
				if facts.Parse.Status != StatusPartial ||
					!containsIssue(
						facts.Parse.Issues,
						IssueUnknownOperandGrammar,
					) ||
					facts.Authoritative() ||
					facts.EnforcementEligible() ||
					len(facts.Paths) != 0 {
					t.Fatalf(
						"provider path %q minted filesystem facts: %#v",
						value,
						facts,
					)
				}
			}
		})
	}
}

func TestPowerShellProviderDriveRejectionPreservesFilesystemPaths(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{
			name: "filesystem provider",
			path: `Microsoft.PowerShell.Core\FileSystem::C:\Windows\win.ini`,
			want: `C:\Windows\win.ini`,
		},
		{
			name: "drive",
			path: `c:\Windows\win.ini`,
			want: `c:\Windows\win.ini`,
		},
		{
			name: "forward slash drive",
			path: `C:/Windows/win.ini`,
			want: `C:/Windows/win.ini`,
		},
		{
			name: "UNC",
			path: `\\server\share\secret.txt`,
			want: `\\server\share\secret.txt`,
		},
		{
			name: "safe extended drive",
			path: `\\?\c:\Windows\win.ini`,
			want: `C:\Windows\win.ini`,
		},
		{
			name: "relative alternate data stream",
			path: `fixture.txt:stream`,
			want: `fixture.txt:stream`,
		},
		{
			name: "drive alternate data stream",
			path: `C:\Windows\win.ini:stream`,
			want: `C:\Windows\win.ini:stream`,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			canonical, ok := canonicalWindowsFilesystemPath(test.path)
			if !ok || canonical != test.want {
				t.Fatalf(
					"filesystem path %q canonicalized to (%q, %t)",
					test.path,
					canonical,
					ok,
				)
			}
		})
	}

	if canonical, ok := canonicalRegistryPath(`HKLM:\SAM`); !ok ||
		canonical != "HKLM/SAM" {
		t.Fatalf("registry path canonicalized to (%q, %t)", canonical, ok)
	}
	for _, value := range []string{
		`HKLM:\`,
		"HKLM:/",
		`Registry::HKLM:\`,
		`Microsoft.PowerShell.Core\Registry::HKLM:\`,
	} {
		if canonical, ok := canonicalRegistryPath(value); ok || canonical != "" {
			t.Errorf(
				"trailing-separator registry path %q canonicalized to (%q, %t)",
				value,
				canonical,
				ok,
			)
		}
	}
	if !windowsEnvironmentProviderPath(`eNv:/API_TOKEN`) {
		t.Fatal("environment provider path was not preserved")
	}
}

func TestCanonicalWindowsFilesystemPathRejectsWin32Aliases(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`C:\safe\file.`,
		`C:\safe\file `,
		`C:\safe\directory.\file.txt`,
		`C:\safe\directory \file.txt`,
		`\\server\share.\file.txt`,
		`\\server\share \file.txt`,
		`Microsoft.PowerShell.Core\FileSystem::C:\safe\file.`,
		`C:\safe\file.:stream`,
		`C:\safe\file :stream`,
		`C:\safe\NUL`,
		`C:\safe\nul.txt`,
		`C:\safe\CON.log`,
		`C:\safe\prn`,
		`C:\safe\Aux.data`,
		`C:\safe\COM1`,
		`C:\safe\com9.txt`,
		`C:\safe\LPT1`,
		`C:\safe\lpt9.log`,
		`C:\safe\NUL:stream`,
		`C:\safe\COM1.txt:stream`,
		`\\server\share\NUL.txt`,
		`\\?\UNC\server\share\COM1.txt`,
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			if canonical, ok := canonicalWindowsFilesystemPath(value); ok ||
				canonical != "" {
				t.Fatalf(
					"Win32 alias %q canonicalized to (%q, %t)",
					value,
					canonical,
					ok,
				)
			}
		})
	}
}

func TestCanonicalWindowsFilesystemPathPreservesUnambiguousPaths(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "drive",
			value: `C:\safe\file.txt`,
			want:  `C:\safe\file.txt`,
		},
		{
			name:  "UNC",
			value: `\\server\share\file.txt`,
			want:  `\\server\share\file.txt`,
		},
		{
			name:  "UNC reserved-looking namespace identifiers",
			value: `\\NUL\CON\file.txt`,
			want:  `\\NUL\CON\file.txt`,
		},
		{
			name: "filesystem provider",
			value: `Microsoft.PowerShell.Core\FileSystem::` +
				`C:\safe\file.txt`,
			want: `C:\safe\file.txt`,
		},
		{
			name:  "alternate data stream",
			value: `C:\safe\file.txt:stream`,
			want:  `C:\safe\file.txt:stream`,
		},
		{
			name:  "dot segment",
			value: `C:\safe\.\file.txt`,
			want:  `C:\safe\.\file.txt`,
		},
		{
			name:  "dot dot segment",
			value: `C:\safe\sub\..\file.txt`,
			want:  `C:\safe\sub\..\file.txt`,
		},
		{
			name:  "trailing separator",
			value: `C:\safe\`,
			want:  `C:\safe\`,
		},
		{
			name:  "extended drive",
			value: `\\?\C:\safe\file.txt`,
			want:  `C:\safe\file.txt`,
		},
		{
			name:  "extended UNC",
			value: `\\?\UNC\server\share\file.txt`,
			want:  `\\server\share\file.txt`,
		},
		{
			name:  "extended UNC reserved-looking namespace identifiers",
			value: `\\?\UNC\NUL\CON\file.txt`,
			want:  `\\NUL\CON\file.txt`,
		},
		{
			name:  "NULL lookalike",
			value: `C:\safe\NULL.txt`,
			want:  `C:\safe\NULL.txt`,
		},
		{
			name:  "nulled lookalike",
			value: `C:\safe\nulled`,
			want:  `C:\safe\nulled`,
		},
		{
			name:  "COM10 lookalike",
			value: `C:\safe\COM10.log`,
			want:  `C:\safe\COM10.log`,
		},
		{
			name:  "LPT10 lookalike",
			value: `C:\safe\LPT10.log`,
			want:  `C:\safe\LPT10.log`,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			canonical, ok := canonicalWindowsFilesystemPath(test.value)
			if !ok || canonical != test.want {
				t.Fatalf(
					"path %q canonicalized to (%q, %t), want %q",
					test.value,
					canonical,
					ok,
					test.want,
				)
			}
		})
	}
}

func TestAnalyzePowerShellWin32AliasesFailClosed(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`C:\Windows\System32\drivers\etc\hosts.`,
		`C:\Windows\System32\drivers\etc\NUL.txt`,
	} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			for _, input := range []Input{
				{
					Tool:        "powershell",
					Command:     `Remove-Item -LiteralPath '` + value + `'`,
					DialectHint: DialectPowerShell,
				},
				{
					Tool:        "powershell",
					Argv:        []string{"Remove-Item", "-LiteralPath", value},
					DialectHint: DialectPowerShell,
				},
			} {
				facts := Analyze(input)
				if facts.Parse.Status != StatusPartial ||
					facts.Authoritative() ||
					facts.EnforcementEligible() ||
					len(facts.Paths) != 0 ||
					!containsIssue(
						facts.Parse.Issues,
						IssueUnknownOperandGrammar,
					) {
					t.Fatalf(
						"Win32 alias %q minted exact path facts: %#v",
						value,
						facts,
					)
				}
			}
		})
	}
}

func TestActiveHomeTildeNormalizationPreservesRawSpelling(t *testing.T) {
	facts := []PathFact{{
		Flavor: PathFlavorPOSIX,
		Value:  "~/.ssh/../id_ed25519",
	}}
	normalizePathFacts(facts, "/workspace", "/home/fixture")
	if len(facts) != 1 ||
		facts[0].Normalized != "~/.ssh/../id_ed25519" ||
		facts[0].Resolved != "/home/fixture/id_ed25519" {
		t.Fatalf("tilde path spelling was lost: %#v", facts)
	}
}

func TestNormalizePathFactsRejectsAmbiguousActiveHomes(t *testing.T) {
	t.Parallel()

	for _, homes := range [][]string{
		{"/Users/first", "/Users/second"},
		{"/Users/second", "/Users/first"},
	} {
		facts := []PathFact{{
			Flavor: PathFlavorPOSIX,
			Value:  "~/.ssh/id_ed25519",
		}}
		normalizePathFacts(facts, "", homes...)
		if facts[0].Normalized != "~/.ssh/id_ed25519" ||
			facts[0].Absolute ||
			facts[0].Resolved != "" {
			t.Fatalf("ambiguous homes %q resolved path: %#v", homes, facts[0])
		}
	}

	facts := []PathFact{{
		Flavor: PathFlavorPOSIX,
		Value:  "~/.ssh/id_ed25519",
	}}
	normalizePathFacts(facts, "", "/Users/fixture")
	if facts[0].Resolved != "/Users/fixture/.ssh/id_ed25519" {
		t.Fatalf("single active home did not resolve path: %#v", facts[0])
	}
}

func TestPowerShellRawAndArgvSpecialPathNormalizationParity(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`Microsoft.PowerShell.Core\FileSystem::C:\Windows\win.ini`,
		`\\?\C:\Windows\win.ini`,
		`\\?\UNC\server\share\secret.txt`,
	} {
		raw := Analyze(Input{
			Tool:        "powershell",
			Command:     `Get-Content '` + value + `'`,
			DialectHint: DialectPowerShell,
		})
		argv := Analyze(Input{
			Tool:        "powershell",
			Argv:        []string{"Get-Content", value},
			DialectHint: DialectPowerShell,
		})
		if !raw.Authoritative() || !argv.Authoritative() ||
			len(raw.Paths) != 1 || len(argv.Paths) != 1 ||
			raw.Paths[0].Normalized != argv.Paths[0].Normalized ||
			raw.Paths[0].Resolved != argv.Paths[0].Resolved {
			t.Fatalf("value=%q raw=%#v argv=%#v", value, raw, argv)
		}
	}
}

func TestNetworkTargetNormalization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		host       string
		normalized string
		scope      NetworkScope
		kind       NetworkTargetKind
		prefix     int64
	}{
		{
			name:       "IPv4 loopback",
			host:       "127.0.0.1",
			normalized: "127.0.0.1",
			scope:      NetworkScopeLoopback,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "legacy IPv4 loopback",
			host:       "0x7f000001",
			normalized: "127.0.0.1",
			scope:      NetworkScopeLoopback,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 loopback",
			host:       "::1",
			normalized: "::1",
			scope:      NetworkScopeLoopback,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 link-local",
			host:       "169.254.12.4",
			normalized: "169.254.12.4",
			scope:      NetworkScopeLinkLocal,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 link-local",
			host:       "fe80::1",
			normalized: "fe80::1",
			scope:      NetworkScopeLinkLocal,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 private",
			host:       "10.20.30.40",
			normalized: "10.20.30.40",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 private",
			host:       "fd00::2",
			normalized: "fd00::2",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 public",
			host:       "8.8.8.8",
			normalized: "8.8.8.8",
			scope:      NetworkScopePublic,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 shared address space is not public",
			host:       "100.64.0.1",
			normalized: "100.64.0.1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 current network space is not public",
			host:       "0.0.0.1",
			normalized: "0.0.0.1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 benchmarking space is not public",
			host:       "198.18.0.1",
			normalized: "198.18.0.1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv4 documentation space is not public",
			host:       "198.51.100.1",
			normalized: "198.51.100.1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 public",
			host:       "2001:4860:4860::8888",
			normalized: "2001:4860:4860::8888",
			scope:      NetworkScopePublic,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 documentation space is not public",
			host:       "2001:db8::1",
			normalized: "2001:db8::1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 discard-only space is not public",
			host:       "100::1",
			normalized: "100::1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "IPv6 documentation space two is not public",
			host:       "3fff::1",
			normalized: "3fff::1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:       "single-address IPv4 CIDR",
			host:       "127.0.0.1/32",
			normalized: "127.0.0.1/32",
			scope:      NetworkScopeLoopback,
			kind:       NetworkTargetSingleAddressCIDR,
			prefix:     32,
		},
		{
			name:       "multi-address IPv4 CIDR",
			host:       "10.0.0.19/24",
			normalized: "10.0.0.0/24",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetMultiAddressCIDR,
			prefix:     24,
		},
		{
			name:       "single-address IPv6 CIDR",
			host:       "::1/128",
			normalized: "::1/128",
			scope:      NetworkScopeLoopback,
			kind:       NetworkTargetSingleAddressCIDR,
			prefix:     128,
		},
		{
			name:       "IPv4 range",
			host:       "192.168.1.1-20",
			normalized: "192.168.1.1-20",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetRange,
		},
		{
			name:       "range spanning disjoint private blocks",
			host:       "10.0.0.1-192.168.1.1",
			normalized: "10.0.0.1-192.168.1.1",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetRange,
		},
		{
			name:       "IPv4 generated target",
			host:       "192.168.4.*",
			normalized: "192.168.4.*",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetGenerated,
		},
		{
			name:  "range rejects leading-zero octet",
			host:  "192.168.01.1-20",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
		{
			name:  "range rejects signed octet",
			host:  "192.168.1.+1-20",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
		{
			name:  "full range rejects leading-zero octet",
			host:  "192.168.01.1-192.168.1.20",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
		{
			name:  "generated target rejects leading-zero octet",
			host:  "192.168.04.*",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
		{
			name:  "generated target rejects signed octet",
			host:  "192.168.+4.*",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
		{
			name:       "target list",
			host:       "10.0.0.1,10.0.0.2",
			normalized: "10.0.0.1,10.0.0.2",
			scope:      NetworkScopePrivate,
			kind:       NetworkTargetList,
		},
		{
			name:       "hostname has unknown scope",
			host:       "Example.TEST",
			normalized: "example.test",
			scope:      NetworkScopeUnknown,
			kind:       NetworkTargetSingleHost,
		},
		{
			name:  "malformed host",
			host:  "bad host",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
		{
			name:  "malformed CIDR",
			host:  "10.0.0.0/99",
			scope: NetworkScopeUnknown,
			kind:  NetworkTargetUnknown,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			normalized, scope, kind, prefix := deriveNetworkTarget(test.host)
			if normalized != test.normalized ||
				scope != test.scope ||
				kind != test.kind ||
				prefix != test.prefix {
				t.Fatalf(
					"deriveNetworkTarget(%q) = (%q, %q, %q, %d)",
					test.host,
					normalized,
					scope,
					kind,
					prefix,
				)
			}
		})
	}
}

func TestAnalyzePopulatesStructuredNetworkDerivations(t *testing.T) {
	t.Parallel()

	facts := Analyze(Input{
		Tool: "HttpRequest",
		Args: []byte(`{
			"url": "http://127.0.0.1:8080/private",
			"method": "GET"
		}`),
	})
	if !facts.Authoritative() || len(facts.Network) != 1 {
		t.Fatalf("facts = %#v", facts)
	}
	network := facts.Network[0]
	if network.Host != "127.0.0.1" ||
		network.NormalizedHost != "127.0.0.1" ||
		network.Scope != NetworkScopeLoopback ||
		network.TargetKind != NetworkTargetSingleHost ||
		network.Port != 8080 {
		t.Fatalf("network = %#v", network)
	}
}
