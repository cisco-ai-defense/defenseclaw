// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Command gen writes the secret reason table into the docs page from
// internal/substrate/reasons. Run it from the repository root:
//
//	go run ./internal/substrate/reasons/gen          # rewrite the page
//	go run ./internal/substrate/reasons/gen -check   # exit 1 on drift
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/substrate/reasons"
)

func main() {
	check := flag.Bool("check", false, "exit 1 when the page is not up to date; write nothing")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gen [-check]")
		os.Exit(2)
	}
	old, err := os.ReadFile(reasons.DocsPage)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	page, err := reasons.Splice(string(old))
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", reasons.DocsPage+":", err)
		os.Exit(1)
	}
	if page == string(old) {
		return
	}
	if *check {
		fmt.Fprintln(os.Stderr, "gen:", reasons.DocsPage, "is out of date; run: go run ./internal/substrate/reasons/gen")
		os.Exit(1)
	}
	if err := os.WriteFile(reasons.DocsPage, []byte(page), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}
