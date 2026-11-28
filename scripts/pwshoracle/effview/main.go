// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Command effview prints the effects the PowerShell frontend extracts from each
// base64 script of a file (Windows flavour, PowerShell dialect). Test-only
// tooling for the PowerShell differential oracle.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func main() {
	f, _ := os.Open(os.Args[1])
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	o := effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPowerShell, Home: `C:\Users\alice`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\alice`}}
	i := 0
	for sc.Scan() {
		raw, _ := base64.StdEncoding.DecodeString(sc.Text())
		r := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Tool: "shell", Command: string(raw), Workdir: o.CWD}, o)
		var parts []string
		for _, e := range r.Effects {
			parts = append(parts, fmt.Sprintf("%s:%s(%s/%s)", e.Kind, e.Target.Path, e.TargetState, e.RoleState))
		}
		fmt.Printf("%d\tfullyKnown=%v\tunknowns=%v\t%s\n", i, r.FullyKnown(), r.Unknowns, strings.Join(parts, " | "))
		i++
	}
}
