// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"testing"
)

// TestKiroTrustedWriteArgs pins the projection of each reviewed Kiro write
// shape onto write_file or edit with the text it writes, the conservative
// projection of every other write-class call, and the passthrough of the
// shapes that were already judged (fs_write {path, content}, other tools).
func TestKiroTrustedWriteArgs(t *testing.T) {
	const p = "~/.ssh/authorized_keys"
	write := `{"content":"k","path":"~/.ssh/authorized_keys"}`
	edit := `{"file_path":"~/.ssh/authorized_keys","new_string":"b","old_string":"a"}`
	for _, tc := range []struct {
		name, tool, args, wantTool, wantArgs string
		wantOK                               bool
	}{
		{"live cli write create", "write", `{"__tool_use_purpose":"Creating the requested file with the specified content","command":"create","path":"/var/tmp/v688/proj/lab-hard2.txt","content":"V688-HARDLINK2\n"}`, "write_file", `{"content":"V688-HARDLINK2\n","path":"/var/tmp/v688/proj/lab-hard2.txt"}`, true},
		{"write create file_text", "write", `{"command":"create","path":"` + p + `","file_text":"k"}`, "write_file", write, true},
		{"write create fileText", "write", `{"command":"create","path":"` + p + `","fileText":"k"}`, "write_file", write, true},
		{"write create new_str", "write", `{"command":"create","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"write create newStr", "write", `{"command":"create","path":"` + p + `","newStr":"k"}`, "write_file", write, true},
		{"write create same aliases", "write", `{"command":"create","path":"` + p + `","content":"k","file_text":"k","fileText":"k","new_str":"k","newStr":"k"}`, "write_file", write, true},
		{"write create empty content", "write", `{"command":"create","path":"` + p + `","content":""}`, "write_file", `{"content":"","path":"~/.ssh/authorized_keys"}`, true},
		{"write append", "write", `{"command":"append","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"write append newStr", "write", `{"command":"append","path":"` + p + `","newStr":"k"}`, "write_file", write, true},
		{"write append content", "write", `{"command":"append","path":"` + p + `","content":"k","__tool_use_purpose":"u"}`, "write_file", write, true},
		{"write insert", "write", `{"command":"insert","path":"` + p + `","insert_line":3,"new_str":"k"}`, "write_file", write, true},
		{"write insert camel", "write", `{"command":"insert","path":"` + p + `","insertLine":3,"newStr":"k"}`, "write_file", write, true},
		{"write insert content at end", "write", `{"command":"insert","path":"` + p + `","content":"k","__tool_use_purpose":"u"}`, "write_file", write, true},
		{"write insert content at line", "write", `{"command":"insert","path":"` + p + `","content":"k","insertLine":3,"__tool_use_purpose":"u"}`, "write_file", write, true},
		{"write insert snake line content", "write", `{"command":"insert","path":"` + p + `","content":"k","insert_line":3}`, "write_file", write, true},
		{"write insert same aliases", "write", `{"command":"insert","path":"` + p + `","insert_line":3,"insertLine":3,"new_str":"k","newStr":"k"}`, "write_file", write, true},
		{"write str_replace snake", "write", `{"command":"str_replace","path":"` + p + `","old_str":"a","new_str":"b"}`, "edit", edit, true},
		{"write strReplace camel", "write", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b"}`, "edit", edit, true},
		{"write strReplace replaceAll true", "write", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b","replaceAll":true,"__tool_use_purpose":"u"}`, "edit", edit, true},
		{"write str_replace replaceAll false", "write", `{"command":"str_replace","path":"` + p + `","old_str":"a","new_str":"b","replaceAll":false}`, "edit", edit, true},
		{"write str_replace same aliases", "write", `{"command":"str_replace","path":"` + p + `","old_str":"a","oldStr":"a","new_str":"b","newStr":"b"}`, "edit", edit, true},
		{"write bare content", "write", `{"path":"` + p + `","content":"k"}`, "write_file", write, true},
		{"write bare content purpose", "write", `{"path":"` + p + `","content":"k","__tool_use_purpose":"u"}`, "write_file", write, true},
		{"cli create", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k"}`, "write_file", write, true},
		{"cli create purpose", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k","summary":"s","__tool_use_purpose":"u"}`, "write_file", write, true},
		{"cli create new_str fallback", "fs_write", `{"command":"create","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"cli create null text", "fs_write", `{"command":"create","path":"` + p + `","file_text":null,"new_str":"k"}`, "write_file", write, true},
		{"cli append", "fs_write", `{"command":"append","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"cli append content", "fs_write", `{"command":"append","path":"` + p + `","content":"k"}`, "write_file", write, true},
		{"cli insert", "fs_write", `{"command":"insert","path":"` + p + `","insert_line":3,"new_str":"k"}`, "write_file", write, true},
		{"cli insert content at end", "fs_write", `{"command":"insert","path":"` + p + `","content":"k"}`, "write_file", write, true},
		{"cli str_replace", "fs_write", `{"command":"str_replace","path":"` + p + `","old_str":"a","new_str":"b"}`, "edit", edit, true},
		{"cli str_replace replaceAll", "fs_write", `{"command":"str_replace","path":"` + p + `","old_str":"a","new_str":"b","replaceAll":true}`, "edit", edit, true},
		{"ide fs_write", "fs_write", `{"path":"` + p + `","text":"k"}`, "write_file", write, true},
		{"ide fsWrite", "fsWrite", `{"path":"` + p + `","text":"k"}`, "write_file", write, true},
		{"cli fsWrite create", "fsWrite", `{"command":"create","path":"` + p + `","fileText":"k"}`, "write_file", write, true},
		{"cli fsWrite append", "fsWrite", `{"command":"append","path":"` + p + `","newStr":"k"}`, "write_file", write, true},
		{"cli fsWrite insert", "fsWrite", `{"command":"insert","path":"` + p + `","insertLine":3,"newStr":"k"}`, "write_file", write, true},
		{"cli fsWrite insert at end", "fsWrite", `{"command":"insert","path":"` + p + `","content":"k"}`, "write_file", write, true},
		{"cli fsWrite strReplace", "fsWrite", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b"}`, "edit", edit, true},
		{"cli fsWrite strReplace replaceAll", "fsWrite", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b","replaceAll":true}`, "edit", edit, true},
		{"ide fsWrite content", "fsWrite", `{"path":"` + p + `","content":"k"}`, "write_file", write, true},
		{"ide fs_append", "fs_append", `{"path":"` + p + `","text":"k"}`, "write_file", write, true},
		{"ide fsAppend", "fsAppend", `{"path":"` + p + `","text":"k"}`, "write_file", write, true},
		{"str_replace camel", "str_replace", `{"path":"` + p + `","oldStr":"a","newStr":"b"}`, "edit", edit, true},
		{"str_replace snake", "str_replace", `{"path":"` + p + `","old_str":"a","new_str":"b","__tool_use_purpose":"u"}`, "edit", edit, true},
		{"strReplace camel", "strReplace", `{"path":"` + p + `","oldStr":"a","newStr":"b"}`, "edit", edit, true},
		{"strReplace snake", "strReplace", `{"path":"` + p + `","old_str":"a","new_str":"b"}`, "edit", edit, true},
		{"fs_write content with note", "fs_write", `{"path":"` + p + `","content":"k","__tool_use_purpose":"u"}`, "write_file", write, true},

		{"unknown command", "fs_write", `{"command":"delete","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"write unknown delete", "write", `{"command":"delete","path":"` + p + `","content":"k"}`, "apply_patch", `{}`, true},
		{"write unknown undo_edit", "write", `{"command":"undo_edit","path":"` + p + `","content":"k"}`, "apply_patch", `{}`, true},
		{"unknown key", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k","mode":"0600"}`, "apply_patch", `{}`, true},
		{"write unknown key", "write", `{"command":"create","path":"` + p + `","content":"k","mode":"0600"}`, "apply_patch", `{}`, true},
		{"write conflicting content aliases", "write", `{"command":"create","path":"` + p + `","content":"k","fileText":"other"}`, "apply_patch", `{}`, true},
		{"write null content alias", "write", `{"command":"create","path":"` + p + `","content":null,"fileText":"k"}`, "apply_patch", `{}`, true},
		{"cli conflicting create texts", "fs_write", `{"command":"create","path":"` + p + `","file_text":"k","new_str":"other"}`, "apply_patch", `{}`, true},
		{"write conflicting new text aliases", "write", `{"command":"append","path":"` + p + `","new_str":"k","newStr":"other"}`, "apply_patch", `{}`, true},
		{"write conflicting append content", "write", `{"command":"append","path":"` + p + `","content":"k","newStr":"other"}`, "apply_patch", `{}`, true},
		{"write conflicting insert content", "write", `{"command":"insert","path":"` + p + `","content":"k","newStr":"other"}`, "apply_patch", `{}`, true},
		{"write conflicting line aliases", "write", `{"command":"insert","path":"` + p + `","insert_line":3,"insertLine":4,"new_str":"k"}`, "apply_patch", `{}`, true},
		{"write conflicting edit aliases", "write", `{"command":"str_replace","path":"` + p + `","old_str":"a","oldStr":"other","new_str":"b","newStr":"b"}`, "apply_patch", `{}`, true},
		{"write null edit alias", "write", `{"command":"str_replace","path":"` + p + `","old_str":null,"oldStr":"a","new_str":"b","newStr":"b"}`, "apply_patch", `{}`, true},
		{"write mixed edit aliases", "write", `{"command":"strReplace","path":"` + p + `","old_str":"a","newStr":"b"}`, "apply_patch", `{}`, true},
		{"ide unknown key", "fs_append", `{"path":"` + p + `","text":"k","content":"x"}`, "apply_patch", `{}`, true},
		{"repeated key", "fs_write", `{"path":"notes.txt","path":"` + p + `","text":"k"}`, "apply_patch", `{}`, true},
		{"write repeated key", "write", `{"command":"create","path":"notes.txt","path":"` + p + `","content":"k"}`, "apply_patch", `{}`, true},
		{"path not a string", "fs_write", `{"path":["` + p + `"],"text":"k"}`, "apply_patch", `{}`, true},
		{"empty path", "fs_append", `{"path":" ","text":"k"}`, "apply_patch", `{}`, true},
		{"write empty path", "write", `{"command":"create","path":" ","content":"k"}`, "apply_patch", `{}`, true},
		{"text not a string", "fs_append", `{"path":"` + p + `","text":7}`, "apply_patch", `{}`, true},
		{"write content not string", "write", `{"command":"create","path":"` + p + `","content":7}`, "apply_patch", `{}`, true},
		{"write missing text", "write", `{"command":"create","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"cli create missing text", "fs_write", `{"command":"create","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"write missing bare text", "write", `{"path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"append no text", "fs_write", `{"command":"append","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"insert at end", "fs_write", `{"command":"insert","path":"` + p + `","new_str":"k"}`, "write_file", write, true},
		{"write null line", "write", `{"command":"insert","path":"` + p + `","insertLine":null,"newStr":"k"}`, "apply_patch", `{}`, true},
		{"write wrong line type", "write", `{"command":"insert","path":"` + p + `","insertLine":"3","newStr":"k"}`, "apply_patch", `{}`, true},
		{"write negative line", "write", `{"command":"insert","path":"` + p + `","insertLine":-1,"content":"k"}`, "apply_patch", `{}`, true},
		{"write fractional line", "write", `{"command":"insert","path":"` + p + `","insertLine":1.5,"content":"k"}`, "apply_patch", `{}`, true},
		{"write missing insert content", "write", `{"command":"insert","path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"write replaceAll string", "write", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b","replaceAll":"true"}`, "apply_patch", `{}`, true},
		{"write replaceAll null", "write", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b","replaceAll":null}`, "apply_patch", `{}`, true},
		{"write replaceAll unknown spelling", "write", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b","replace_all":true}`, "apply_patch", `{}`, true},
		{"str_replace no new", "str_replace", `{"path":"` + p + `","oldStr":"a"}`, "apply_patch", `{}`, true},
		{"str_replace mixed dialects", "str_replace", `{"path":"` + p + `","oldStr":"a","new_str":"b"}`, "apply_patch", `{}`, true},
		{"strReplace unknown key", "strReplace", `{"path":"` + p + `","oldStr":"a","newStr":"b","mode":"replace"}`, "apply_patch", `{}`, true},
		{"fsAppend missing text", "fsAppend", `{"path":"` + p + `"}`, "apply_patch", `{}`, true},
		{"fsAppend command", "fsAppend", `{"command":"append","path":"` + p + `","newStr":"k"}`, "apply_patch", `{}`, true},
		{"fsWrite unknown command", "fsWrite", `{"command":"undo_edit","path":"` + p + `","content":"k"}`, "apply_patch", `{}`, true},
		{"strReplace command", "strReplace", `{"command":"strReplace","path":"` + p + `","oldStr":"a","newStr":"b"}`, "apply_patch", `{}`, true},
		{"not an object", "fs_write", `"x"`, "apply_patch", `{}`, true},

		{"fs_write content passthrough", "fs_write", `{"path":"` + p + `","content":"k"}`, "", `{"path":"` + p + `","content":"k"}`, false},
		{"fs_write invalid content", "fs_write", `{"path":"` + p + `","content":7}`, "apply_patch", `{}`, true},
		{"fs_write empty path", "fs_write", `{"path":" ","content":"k"}`, "apply_patch", `{}`, true},
		{"other tool", "execute_bash", `{"command":"ls"}`, "", `{"command":"ls"}`, false},
		{"other case", "WRITE", `{"path":"` + p + `","content":"k"}`, "", `{"path":"` + p + `","content":"k"}`, false},
		{"fs_read", "fs_read", `{"path":"` + p + `"}`, "", `{"path":"` + p + `"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool, out, ok := KiroTrustedWriteArgs(tc.tool, json.RawMessage(tc.args))
			if tool != tc.wantTool || ok != tc.wantOK || string(out) != tc.wantArgs {
				t.Fatalf("KiroTrustedWriteArgs(%s, %s) = %q, %s, %t; want %q, %s, %t",
					tc.tool, tc.args, tool, out, ok, tc.wantTool, tc.wantArgs, tc.wantOK)
			}
		})
	}
}
