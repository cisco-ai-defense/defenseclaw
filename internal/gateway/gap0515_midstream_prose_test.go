// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// The GAP-0515 helpers the exact and probe tests share with the
// !windows cost tests.

// gap0515Prose is n bytes of deterministic benign prose: words, numbers,
// punctuation, list items, short code spans with a path, and line breaks.
func gap0515Prose(n int, seed int64) string {
	words := strings.Fields(`the stream carries plain words about lists maps loops and the
	parser reads every line before it writes a summary of what changed in version
	release notes say config file values default to true when unset a function returns
	an error so the caller checks it then retries after a short wait with backoff we
	use tables for the results and charts for trends across weeks of data which shows
	how latency moved under load while memory stayed flat`)
	r := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for b.Len() < n {
		switch k := r.Intn(40); {
		case k == 0:
			b.WriteString("\n\n- ")
		case k == 1:
			b.WriteString(".\n")
		case k == 2:
			fmt.Fprintf(&b, " %d.%d", r.Intn(10), r.Intn(20))
		case k == 3:
			b.WriteString(" `go test ./...`")
		case k < 7:
			b.WriteString(", ")
		default:
			b.WriteByte(' ')
		}
		b.WriteString(words[r.Intn(len(words))])
	}
	return b.String()[:n]
}

// gap0515WholeCheck is the median time of a mid-stream check of text read
// whole: the check of a stream with no memory of the checks before it.
func gap0515WholeCheck(text string, reps int) time.Duration {
	insp := NewGuardrailInspector("local", nil, nil)
	ds := make([]time.Duration, 0, reps)
	for i := 0; i < reps; i++ {
		t0 := time.Now()
		insp.InspectMidStream(context.Background(), "completion", text, []ChatMessage{{Role: "assistant", Content: text}}, "m", "action")
		ds = append(ds, time.Since(t0))
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}
