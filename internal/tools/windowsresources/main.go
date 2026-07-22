// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// windowsresources applies or verifies the release-owned Windows PE resource
// contract. It is invoked by GoReleaser and the native installer build before
// Authenticode signing; it is never included in the installed product.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/windowsresources"
)

func main() {
	var (
		target     = flag.String("target", "windows_amd64", "build target (windows_amd64 or windows_arm64)")
		executable = flag.String("executable", "", "Windows executable to update or verify")
		component  = flag.String("component", "", "resource component: gateway, hook, launcher, startup, or setup")
		version    = flag.String("version", "", "semantic product version")
		icon       = flag.String("icon", windowsresources.IconSource, "project-owned source PNG")
		verifyOnly = flag.Bool("verify-only", false, "verify resources without changing the executable")
	)
	flag.Parse()

	parsedTarget, windowsTarget, err := classifyTarget(*target)
	if err != nil {
		fatalf("%v", err)
	}
	if !windowsTarget {
		fmt.Printf("Windows resources: skipped non-Windows target %s\n", *target)
		return
	}
	if strings.TrimSpace(*executable) == "" || strings.TrimSpace(*version) == "" {
		fatalf("-executable and -version are required for Windows targets")
	}
	parsedComponent, err := windowsresources.ParseComponent(*component)
	if err != nil {
		fatalf("%v", err)
	}
	if *verifyOnly {
		err = windowsresources.VerifyForTarget(*executable, parsedTarget, parsedComponent, *version, *icon)
	} else {
		err = windowsresources.ApplyForTarget(*executable, parsedTarget, parsedComponent, *version, *icon)
	}
	if err != nil {
		fatalf("%v", err)
	}
	verb := "applied and verified"
	if *verifyOnly {
		verb = "verified"
	}
	fmt.Printf("Windows resources: %s %s (%s %s %s)\n", verb, *executable, parsedTarget, parsedComponent, *version)
}

// classifyTarget leaves the shared GoReleaser hook as an intentional no-op for
// the four configured Linux and macOS targets. Every other value fails closed
// unless it is one of the two canonical Windows resource targets.
func classifyTarget(value string) (windowsresources.Target, bool, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64":
		return "", false, nil
	case string(windowsresources.TargetWindowsAMD64), string(windowsresources.TargetWindowsARM64):
		target, err := windowsresources.ParseTarget(normalized)
		return target, true, err
	default:
		return "", false, fmt.Errorf("unsupported resource hook target %q", value)
	}
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "windowsresources: "+format+"\n", arguments...)
	os.Exit(1)
}
