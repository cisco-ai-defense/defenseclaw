// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import "strings"

// identifierWords cuts an identifier into lower case words at _ - . / and
// space, at a lower case or digit to upper case change, and before the last
// capital of an acronym: sendEmail -> send, email; chat_postMessage -> chat,
// post, message; HTTPServer -> http, server; DB_PASSWORD -> db, password.
func identifierWords(name string) []string {
	var words []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			words = append(words, strings.ToLower(name[start:end]))
		}
		start = -1
	}
	isUpper := func(b byte) bool { return b >= 'A' && b <= 'Z' }
	isLower := func(b byte) bool { return b >= 'a' && b <= 'z' }
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch c {
		case '_', '-', '.', '/', ' ', ':':
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		prev := name[i-1]
		switch {
		case isUpper(c) && (isLower(prev) || prev >= '0' && prev <= '9'):
			flush(i)
			start = i
		case isUpper(c) && isUpper(prev) && i+1 < len(name) && isLower(name[i+1]):
			flush(i)
			start = i
		}
	}
	flush(len(name))
	return words
}

// toolLeafWords returns the words of the last part of a tool name
// (mcp__mail__sendEmail -> send, email; slack.chat_postMessage -> chat, post,
// message).
func toolLeafWords(tool string) []string {
	leaf := strings.TrimSpace(tool)
	if i := strings.LastIndex(leaf, "__"); i >= 0 {
		leaf = leaf[i+2:]
	} else if i := strings.LastIndexByte(leaf, '.'); i >= 0 {
		leaf = leaf[i+1:]
	}
	return identifierWords(leaf)
}
