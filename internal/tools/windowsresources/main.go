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
		target     = flag.String("target", "windows_amd64", "build target (for example windows_amd64)")
		executable = flag.String("executable", "", "Windows executable to update or verify")
		component  = flag.String("component", "", "resource component: gateway, hook, launcher, startup, or setup")
		version    = flag.String("version", "", "semantic product version")
		icon       = flag.String("icon", windowsresources.IconSource, "project-owned source PNG")
		verifyOnly = flag.Bool("verify-only", false, "verify resources without changing the executable")
	)
	flag.Parse()

	// The gateway GoReleaser build also targets Linux and macOS. Its post hook
	// is intentionally a no-op there; every Windows target remains fail-closed.
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(*target)), "windows_") {
		fmt.Printf("Windows resources: skipped non-Windows target %s\n", *target)
		return
	}
	if strings.ToLower(strings.TrimSpace(*target)) != "windows_amd64" {
		fatalf("Windows resources support only the certified windows_amd64 target, got %q", *target)
	}
	if strings.TrimSpace(*executable) == "" || strings.TrimSpace(*version) == "" {
		fatalf("-executable and -version are required for Windows targets")
	}
	parsedComponent, err := windowsresources.ParseComponent(*component)
	if err != nil {
		fatalf("%v", err)
	}
	if *verifyOnly {
		err = windowsresources.Verify(*executable, parsedComponent, *version, *icon)
	} else {
		err = windowsresources.Apply(*executable, parsedComponent, *version, *icon)
	}
	if err != nil {
		fatalf("%v", err)
	}
	verb := "applied and verified"
	if *verifyOnly {
		verb = "verified"
	}
	fmt.Printf("Windows resources: %s %s (%s %s)\n", verb, *executable, parsedComponent, *version)
}

func fatalf(format string, arguments ...any) {
	fmt.Fprintf(os.Stderr, "windowsresources: "+format+"\n", arguments...)
	os.Exit(1)
}
