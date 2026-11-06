// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

func heredocBodyWord(t *testing.T, body string) *syntax.Word {
	t.Helper()
	file, ok := Parse("cat > /tmp/out.txt << 'EOF'\n" + body + "EOF\n")
	if !ok || len(file.Stmts) != 1 {
		t.Fatalf("heredoc did not parse: %v", ok)
	}
	for _, redirect := range file.Stmts[0].Redirs {
		if redirect.Hdoc != nil {
			return redirect.Hdoc
		}
	}
	t.Fatal("no here-document")
	return nil
}

// GAP-0700: the brace groups of one here-document body multiply, whatever the
// blanks and lines between them.
func TestBraceFieldsTooLargeCountsAHeredocBodyAsOneWord(t *testing.T) {
	var big strings.Builder
	for _, alternatives := range []int{7, 6, 4, 2, 4, 2, 2, 4, 2, 4, 2, 4, 2, 4, 2} {
		names := make([]string, alternatives)
		for i := range names {
			names[i] = "n" + strconv.Itoa(i)
		}
		big.WriteString("const { " + strings.Join(names, ", ") + " } = require(\"m\")\n")
	}
	if !BraceFieldsTooLarge(heredocBodyWord(t, big.String())) {
		t.Fatal("fifteen destructuring lists in one here-document must be past the bound")
	}
	if _, err := Fields(&expand.Config{}, heredocBodyWord(t, big.String())); !errors.Is(err, ErrBraceFieldsTooLarge) {
		t.Fatalf("Fields must refuse the word before it expands: %v", err)
	}
}

func TestBraceFieldsTooLargeLeavesOrdinaryWordsAlone(t *testing.T) {
	var long strings.Builder
	for range 3000 {
		long.WriteString("line of text without a group\n")
	}
	for _, body := range []string{
		"const { a, b, c } = require(\"m\")\nconst { d, e } = require(\"n\")\n",
		"plain text\n",
		long.String() + "const { a, b } = x\n",
	} {
		if BraceFieldsTooLarge(heredocBodyWord(t, body)) {
			t.Fatalf("an ordinary here-document is not past the bound: %.40q", body)
		}
	}
	for _, word := range []string{"src/{a,b,c}/{x,y}", "file{,.bak}", "{1..100}", "plain", "'{a,b}'"} {
		file, ok := Parse("echo " + word)
		if !ok {
			t.Fatal(word)
		}
		arg := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		if BraceFieldsTooLarge(arg) {
			t.Fatalf("%s is not past the bound", word)
		}
		got, err := Fields(&expand.Config{}, arg)
		want, wantErr := expand.Fields(&expand.Config{}, arg)
		if (err == nil) != (wantErr == nil) || strings.Join(got, " ") != strings.Join(want, " ") {
			t.Fatalf("Fields(%s) = %v, %v; expand.Fields = %v, %v", word, got, err, want, wantErr)
		}
	}
	if BraceFieldsTooLarge(nil) {
		t.Fatal("nil word")
	}
}
