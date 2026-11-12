// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

const (
	bannerWidth    = 80
	bannerMaxLines = 8
	bannerAllowMax = 8
)

// bannerLines is the banner: at most 8 plain lines of at most 80 columns.
func bannerLines(b Banner, t Target) []string {
	name := safetext.Line(b.Name)
	if name == "" {
		name = t.Name
	}
	head := "DefenseClaw agent " + name
	if c := safetext.Line(b.Connector); c != "" {
		head += " (" + c + ")"
	}
	head += " in actor " + t.String()
	lines := []string{head}
	var parts []string
	for _, p := range [][2]string{{"profile", b.Profile}, {"model", b.Model}, {"route", b.Route}} {
		if v := safetext.Line(p[1]); v != "" {
			parts = append(parts, p[0]+" "+v)
		}
	}
	if len(parts) > 0 {
		s := strings.Join(parts, ", ")
		lines = append(lines, strings.ToUpper(s[:1])+s[1:])
	}
	if l := allowLine(b.AllowList); l != "" {
		lines = append(lines, l)
	}
	asks := safetext.Line(b.Asks)
	if asks == "" {
		asks = "Asks appear on the bottom line; press Ctrl-\\ to answer one."
	}
	lines = append(lines, asks)
	for _, e := range b.Extra {
		if len(lines) >= bannerMaxLines-1 {
			break
		}
		if e = safetext.Line(e); e != "" {
			lines = append(lines, e)
		}
	}
	lines = append(lines, "Ctrl-] detaches; the agent keeps running.")
	for i := range lines {
		lines[i] = fitWidth(lines[i], bannerWidth)
	}
	return lines
}

// allowLine lists the first entries of the allow list that fit, then
// "+N more".
func allowLine(list []string) string {
	var items []string
	for _, a := range list {
		if a = safetext.Line(a); a != "" {
			items = append(items, a)
		}
	}
	if len(items) == 0 {
		return ""
	}
	const head = "Allowed: "
	line := head
	shown := 0
	for i, a := range items {
		if shown == bannerAllowMax {
			break
		}
		next := line
		if shown > 0 {
			next += ", "
		}
		next += a
		more := ""
		if rest := len(items) - i - 1; rest > 0 {
			more = " +" + strconv.Itoa(rest) + " more"
		}
		if len([]rune(next+more)) > bannerWidth && shown > 0 {
			break
		}
		line = next
		shown++
	}
	if rest := len(items) - shown; rest > 0 {
		line += " +" + strconv.Itoa(rest) + " more"
	}
	return line
}

func writeBanner(w io.Writer, b Banner, t Target) {
	for _, l := range bannerLines(b, t) {
		fmt.Fprintln(w, l)
	}
}
