// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package secretshape

import (
	"sort"
	"strings"
)

// InlineSecretSpan is one credential with a well-known issuer shape found
// in a text: its kind and the byte range [Start, End) that holds the whole
// credential (prefix included). The caller slices the text to read the
// value; the span itself holds none, so it is safe to log.
type InlineSecretSpan struct {
	Label string
	Start int
	End   int
}

// FindInlineSecretSpans returns every non-overlapping credential with a
// well-known issuer shape in text, in order. It uses the same shapes as
// FindInlineSecret (private-key PEM blocks are not included: they span
// lines and are not single values). A body made of one repeated character
// is a placeholder, not a secret, and is skipped.
func FindInlineSecretSpans(text string) []InlineSecretSpan {
	return FindInlineSecretSpansOf(text, nil)
}

// FindInlineSecretSpansOf is FindInlineSecretSpans over the shapes whose
// label keep accepts (nil: every shape). Overlaps are resolved among those
// shapes only, so a shape the caller does not want (a JWT whose last
// segment runs into a following key) cannot hide one it does.
func FindInlineSecretSpansOf(text string, keep func(label string) bool) []InlineSecretSpan {
	var spans []InlineSecretSpan
	for _, shape := range inlineCredentialShapes {
		if keep != nil && !keep(shape.label) {
			continue
		}
		for _, loc := range shape.re.FindAllStringSubmatchIndex(text, -1) {
			body := text[loc[2*shape.body]:loc[2*shape.body+1]]
			if body == "" || strings.Trim(body, body[:1]) == "" {
				continue
			}
			spans = append(spans, InlineSecretSpan{Label: shape.label, Start: loc[0], End: loc[1]})
		}
	}
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].Start != spans[j].Start {
			return spans[i].Start < spans[j].Start
		}
		return spans[i].End > spans[j].End
	})
	out := spans[:0]
	end := -1
	for _, s := range spans {
		if s.Start < end {
			continue // overlaps a longer or earlier match (sk-ant- is also sk-)
		}
		out = append(out, s)
		end = s.End
	}
	return out
}
