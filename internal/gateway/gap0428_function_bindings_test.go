// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

func TestGAP0428IndexedPrintfBindingsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	rows := []struct{ name, command, want string }{
		{"separate_index_protected", `f=out.txt; printf -v 'f[0]' %s keylink; echo m >> "$f"`, "block"},
		{"separate_index_ordinary", `f=keylink; printf -v 'f[0]' %s out.txt; echo m >> "$f"`, "allow"},
		{"attached_index_protected", `f=out.txt; printf '-vf[0]' %s keylink; echo m >> "$f"`, "block"},
		{"attached_index_ordinary", `f=keylink; printf '-vf[0]' %s out.txt; echo m >> "$f"`, "allow"},
		{"dynamic_name_protected", `f=out.txt; dest='f[0]'; printf -v "$dest" %s keylink; echo m >> "$f"`, "block"},
		{"dynamic_name_ordinary", `f=keylink; dest='f[0]'; printf -v "$dest" %s out.txt; echo m >> "$f"`, "allow"},
		{"positive_index_protected", `f=keylink; printf -v 'f[1]' %s out.txt; echo m >> "$f"`, "block"},
		{"positive_index_ordinary", `f=out.txt; printf -v 'f[1]' %s keylink; echo m >> "$f"`, "allow"},
		{"expression_index_protected", `f=out.txt; printf -v 'f[1-1]' %s keylink; echo m >> "$f"`, "block"},
		{"expression_index_ordinary", `f=keylink; printf -v 'f[1-1]' %s out.txt; echo m >> "$f"`, "allow"},
	}
	payloads := make([][]byte, len(rows))
	for i, row := range rows {
		payloads[i] = f.payload(t, row.command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode(row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
		}
	}
}

func TestGAP0428FunctionBindingEffectsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	rows := []struct{ name, command, want string }{
		{"builtin_assign_protected", `f=out.txt; builtin() { f=keylink; }; printf() { builtin printf %s -xf; }; printf -vf %s out2.txt; echo m >> "$f"`, "block"},
		{"builtin_assign_ordinary", `f=keylink; builtin() { f=out.txt; }; printf() { builtin printf %s -xf; }; printf -vf %s keylink; echo m >> "$f"`, "allow"},
		{"command_assign_protected", `f=out.txt; command() { f=keylink; }; printf() { command printf %s -xf; }; printf -vf %s out2.txt; echo m >> "$f"`, "block"},
		{"command_assign_ordinary", `f=keylink; command() { f=out.txt; }; printf() { command printf %s -xf; }; printf -vf %s keylink; echo m >> "$f"`, "allow"},
		{"colon_builtin_assign_protected", `f=out.txt; builtin() { f=keylink; }; :() { builtin printf %s -xf; }; printf() { :; :; }; printf -vf %s out2.txt; echo m >> "$f"`, "block"},
		{"colon_builtin_assign_ordinary", `f=keylink; builtin() { f=out.txt; }; :() { builtin printf %s -xf; }; printf() { :; :; }; printf -vf %s keylink; echo m >> "$f"`, "allow"},
		{"colon_command_assign_protected", `f=out.txt; command() { f=keylink; }; :() { command printf %s -xf; }; printf() { :; :; }; printf -vf %s out2.txt; echo m >> "$f"`, "block"},
		{"colon_command_assign_ordinary", `f=keylink; command() { f=out.txt; }; :() { command printf %s -xf; }; printf() { :; :; }; printf -vf %s keylink; echo m >> "$f"`, "allow"},
		{"external_builtin_output_protected", `f=out.txt; builtin() { /usr/bin/printf %s -vf; }; echo() { builtin printf %s -vf; }; opt=$(echo -vf); printf "$opt" %s keylink; echo m >> "$f"`, "block"},
		{"external_builtin_output_ordinary", `f=keylink; builtin() { /usr/bin/printf %s -vf; }; echo() { builtin printf %s -vf; }; opt=$(echo -vf); printf "$opt" %s out.txt; echo m >> "$f"`, "allow"},
		{"printf_function_protected", `f=keylink; printf() { :; :; }; printf -vf %s out.txt; echo m >> "$f"`, "block"},
		{"printf_function_ordinary", `f=out.txt; printf() { :; :; }; printf -vf %s keylink; echo m >> "$f"`, "allow"},
		{"builtin_binding_protected", `f=out.txt; builtin printf -vf %s keylink; echo m >> "$f"`, "block"},
		{"builtin_binding_ordinary", `f=out.txt; builtin printf -vf %s out2.txt; echo m >> "$f"`, "allow"},
		{"command_binding_protected", `f=out.txt; command printf -vf %s keylink; echo m >> "$f"`, "block"},
		{"command_binding_ordinary", `f=out.txt; command printf -vf %s out2.txt; echo m >> "$f"`, "allow"},
		{"end_options_protected", `f=keylink; printf -- %s x; echo m >> "$f"`, "block"},
		{"end_options_ordinary", `f=out.txt; printf -- %s x; echo m >> "$f"`, "allow"},
		{"function_redirect_protected", `f=keylink; swap() { f=out.txt; }; swap >> "$f"`, "block"},
		{"percent_b_protected", `f=out.txt; printf -vf %b 'key\154ink'; echo m >> "$f"`, "block"},
		{"percent_b_ordinary", `f=keylink; printf -vf %b 'out\056txt'; echo m >> "$f"`, "allow"},
		{"readonly_protected", `f=keylink; readonly f; printf -vf %b 'out\056txt'; echo m >> "$f"`, "block"},
		{"readonly_ordinary", `f=out.txt; readonly f; printf -vf %b 'key\154ink'; echo m >> "$f"`, "allow"},
		{"function_option_protected", `f=keylink; echo() { builtin printf %s -xf; }; opt=$(echo -vf); printf "$opt" %s out.txt; echo m >> "$f"`, "block"},
		{"function_option_ordinary", `f=out.txt; echo() { builtin printf %s -xf; }; opt=$(echo -vf); printf "$opt" %s keylink; echo m >> "$f"`, "allow"},
	}
	payloads := make([][]byte, len(rows))
	for i, row := range rows {
		payloads[i] = f.payload(t, row.command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode(row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		t.Logf("RV4ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
		}
	}
}
