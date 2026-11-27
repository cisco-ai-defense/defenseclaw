// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Command effprog prints, for each base64 script of a file, the effects the
// PowerShell frontend extracts with the program of each (kind, path, states,
// program), one tab-separated row per script. Test-only tooling for the
// PowerShell differential oracle (classifying effects one reader loses).
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
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	o := effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPowerShell, Home: `C:\Users\alice`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true, Env: map[string]string{"USERPROFILE": `C:\Users\alice`}}
	i := 0
	for sc.Scan() {
		raw, _ := base64.StdEncoding.DecodeString(sc.Text())
		r := effects.Extract(effects.Call{Surface: effects.SurfaceShell, Tool: "shell", Command: string(raw), Workdir: o.CWD}, o)
		var parts []string
		for _, e := range r.Effects {
			parts = append(parts, fmt.Sprintf("%s:%s(%s/%s)@%s", e.Kind, e.Target.Path, e.TargetState, e.RoleState, strings.ToLower(e.Origin.Program)))
		}
		fmt.Printf("%d\t%s\n", i, strings.Join(parts, " | "))
		i++
	}
}
