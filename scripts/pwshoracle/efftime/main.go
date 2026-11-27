// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// efftime times the PowerShell effects frontend per row: for every base64 row
// of the input file it runs effects.Extract REPS times and prints the best
// time in nanoseconds ("<row>\t<bytes>\t<ns>"). Build it twice, once with
// -ldflags=-X=github.com/defenseclaw/defenseclaw/internal/psparse.legacyFrontend=psparse
// (the 1.0.10 reader) and once without (the port), alternate the two
// processes over several rounds, and compare per-row best times
// (efftime.py). Prints no row text.
package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

func main() {
	reps := 5
	if len(os.Args) > 2 {
		reps, _ = strconv.Atoi(os.Args[2])
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	o := effects.Options{Flavor: effects.FlavorWindows, Dialect: effects.DialectPowerShell, Home: `C:\Users\alice`, CWD: `C:\work`, Drive: "C", CaseInsensitive: true}
	if pf := os.Getenv("EFFTIME_CPUPROFILE"); pf != "" {
		pfh, err := os.Create(pf)
		if err == nil && pprof.StartCPUProfile(pfh) == nil {
			defer pprof.StopCPUProfile()
		}
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for i := 0; sc.Scan(); i++ {
		raw, _ := base64.StdEncoding.DecodeString(sc.Text())
		call := effects.Call{Surface: effects.SurfaceShell, Tool: "shell", Command: string(raw), Workdir: o.CWD}
		best := time.Duration(1<<63 - 1)
		for r := 0; r < reps; r++ {
			st := time.Now()
			effects.Extract(call, o)
			if d := time.Since(st); d < best {
				best = d
			}
		}
		fmt.Fprintf(w, "%d\t%d\t%d\n", i, len(raw), best.Nanoseconds())
	}
}
