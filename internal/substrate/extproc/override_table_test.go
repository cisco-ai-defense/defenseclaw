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

package extproc

import (
	"bytes"
	"compress/gzip"
	"context"
	"strings"
	"testing"

	"golang.org/x/text/encoding/charmap"
	"golang.org/x/text/encoding/unicode"
)

// The GAP-0046 class table (lane F10). A request's effective method and
// path are what the server frameworks compute; the callout evaluates the
// url rules for every candidate and the strictest wins. Rows come from
// lane R (R1), R2, R3a, R4 and R5, then the framework list (F10). Every row
// runs the headers and, when the callout asks for it and the egress
// filter sends it, the body.

// ovTableRules are the rules the rows use unless a row brings its own.
var ovTableRules = []URLRuleCfg{
	{Name: "no-delete", Hosts: []string{"api.github.com"}, Methods: []string{"DELETE"}, Action: "deny"},
	{Name: "ask-release", Hosts: []string{"api.github.com"}, PathPrefix: "/repos/acme/releases", Action: "ask"},
	{Name: "no-admin-post", Hosts: []string{"x.example"}, Methods: []string{"POST"}, PathPrefix: "/admin/", Action: "deny"},
}

type ovCase struct {
	name, from         string
	method, host, path string
	hdr                []string // header name, value pairs
	ct                 []string // Content-Type lines; nil: none
	body               []byte   // nil: no body (end of stream on the headers)
	contentLength      int64    // 0: len(body); -1: not stated (chunked)
	rules              []URLRuleCfg
	mode, inspect      string // failure_mode, body_inspection ("": closed, auto)
	managed            bool
	stock              bool // the egress filter never sends a body (stock Substrate v1.0.0)
	want               string
	wantAskMethod      string // an AskRequest's Method must contain it, and its Rule key the Method
	wantAsks           int    // asks raised; 0: not checked
	noAsk              bool   // no ask may be raised
}

const formCT = "application/x-www-form-urlencoded"

func ovGzip(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.Bytes()
}

func ovUTF16LE(s string) []byte {
	b, _ := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder().Bytes([]byte(s))
	return b
}

func ebcdic037(s string) []byte {
	b, _ := charmap.CodePage037.NewEncoder().Bytes([]byte(s))
	return b
}

func ovCases() []ovCase {
	del := []byte("_method=DELETE")
	return []ovCase{
		// Lane R (R1) and R2: path spellings and the query override.
		{name: "dot segment", from: "R1", method: "POST", host: "x.example", path: "/./admin/x", want: "deny:url_rule"},
		{name: "escaped letter", from: "R1", method: "POST", host: "x.example", path: "/%61dmin/x", want: "deny:url_rule"},
		{name: "double slash", from: "R1", method: "POST", host: "x.example", path: "//admin//x", want: "deny:url_rule"},
		{name: "dotdot semicolon", from: "R1", method: "POST", host: "x.example", path: "/admin/..;/public/x", want: "deny:path_ambiguous"},
		{name: "case", from: "R1", method: "POST", host: "x.example", path: "/ADMIN/x", want: "deny:url_rule"},
		{name: "encoded semicolon", from: "R1", method: "POST", host: "x.example", path: "/admin%3Bx/y", want: "deny:path_ambiguous"},
		{name: "override header", from: "R1", method: "GET", host: "x.example", path: "/admin/x", hdr: []string{"x-http-method-override", "POST"}, want: "deny:url_rule"},
		{name: "X-HTTP-Method", from: "R1", method: "GET", host: "x.example", path: "/admin/x", hdr: []string{"x-http-method", "post"}, want: "deny:url_rule"},
		{name: "X-Method-Override", from: "R1", method: "GET", host: "x.example", path: "/admin/x", hdr: []string{"x-method-override", "POST"}, want: "deny:url_rule"},
		{name: "dotdot pops the prefix", from: "R2", method: "POST", host: "x.example", path: "/admin/../public/x", want: "deny:path_ambiguous"},
		{name: "escaped dotdot", from: "R2", method: "POST", host: "x.example", path: "/admin/%2e%2e/public/x", want: "deny:path_ambiguous"},
		{name: "mixed dotdot", from: "R2", method: "POST", host: "x.example", path: "/admin/.%2E/public/x", want: "deny:path_ambiguous"},
		{name: "query _method", from: "R2", method: "GET", host: "x.example", path: "/admin/x?_method=POST", want: "deny:url_rule"},
		// R3a.
		{name: "header comma list", from: "R3a", method: "POST", host: "api.github.com", path: "/repos/acme/web", hdr: []string{"x-http-method-override", "DELETE, GET"}, want: "deny:url_rule"},
		{name: "header list reversed", from: "R3a", method: "POST", host: "api.github.com", path: "/repos/acme/web", hdr: []string{"x-http-method-override", "GET,DELETE"}, want: "deny:url_rule"},
		{name: "form body", from: "R3a", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: del, want: "deny:url_rule"},
		{name: "trailing slash prefix covers the directory", from: "R3a", method: "POST", host: "x.example", path: "/admin", want: "deny:url_rule"},
		{name: "double-encoded dot", from: "R3a", method: "POST", host: "x.example", path: "/admin/%252e%252e/x", want: "deny:path_ambiguous"},
		{name: "encoded backslash", from: "R3a", method: "POST", host: "x.example", path: "/admin%5Cx", want: "deny:path_ambiguous"},
		{name: "query _method list", from: "R3a", method: "GET", host: "api.github.com", path: "/repos/acme/web?_method=GET,DELETE", want: "deny:url_rule"},
		{name: "query _method repeated", from: "R3a", method: "GET", host: "api.github.com", path: "/repos/acme/web?_method=GET&_method=DELETE", want: "deny:url_rule"},
		{name: "query _method semicolon", from: "R3a", method: "GET", host: "api.github.com", path: "/repos/acme/web?a=1;_method=delete", want: "deny:url_rule"},
		{name: "overlong dot (not UTF-8)", from: "R3a", method: "POST", host: "x.example", path: "/x/%c0%ae%c0%ae/admin/y", want: "deny:path_ambiguous"},
		// R4.
		{name: "no Content-Type (Rack form)", from: "R4", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, want: "deny:url_rule"},
		{name: "content type params and case", from: "R4", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"Application/X-WWW-Form-Urlencoded; charset=utf-8"}, body: []byte("a=1&_method=delete"), want: "deny:url_rule"},
		{name: "gzip form", from: "R4", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, hdr: []string{"content-encoding", "gzip"}, body: ovGzip("_method=DELETE"), want: "deny:url_rule"},
		{name: "ask binds the body method", from: "R4", method: "POST", host: "api.github.com", path: "/repos/acme/releases/1", ct: []string{formCT}, body: del,
			rules: []URLRuleCfg{{Name: "release-writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST", "DELETE"}, PathPrefix: "/repos/acme/releases", Action: "ask"}},
			want:  "allow", wantAskMethod: "DELETE", wantAsks: 1},
		{name: "ask without methods binds the body method", from: "R4", method: "POST", host: "api.github.com", path: "/repos/acme/releases/1", ct: []string{formCT}, body: del,
			rules: []URLRuleCfg{{Name: "release-any", Hosts: []string{"api.github.com"}, PathPrefix: "/repos/acme/releases", Action: "ask"}},
			want:  "allow", wantAskMethod: "DELETE", wantAsks: 1},
		{name: "header override is asked", from: "R4", method: "POST", host: "api.github.com", path: "/repos/acme/releases/1", hdr: []string{"x-http-method-override", "DELETE"},
			rules: []URLRuleCfg{{Name: "release-writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST", "DELETE"}, PathPrefix: "/repos/acme/releases", Action: "ask"}},
			want:  "allow", wantAskMethod: "DELETE,POST", wantAsks: 1},
		{name: "deny on the override beats an ask", from: "R4", method: "POST", host: "api.github.com", path: "/x?_method=delete",
			rules: []URLRuleCfg{{Name: "ask-all", Hosts: []string{"api.github.com"}, Action: "ask"}, {Name: "no-delete", Hosts: []string{"api.github.com"}, Methods: []string{"DELETE"}, Action: "deny"}},
			want:  "deny:url_rule", noAsk: true},
		{name: "body deny beats an ask", from: "F10", method: "POST", host: "api.github.com", path: "/x", ct: []string{formCT}, body: del,
			rules: []URLRuleCfg{{Name: "ask-all", Hosts: []string{"api.github.com"}, Action: "ask"}, {Name: "no-delete", Hosts: []string{"api.github.com"}, Methods: []string{"DELETE"}, Action: "deny"}},
			want:  "deny:url_rule", noAsk: true},

		// F10: Rack (Rails, Sinatra, Hanami): Rack::Request#form_data? is a
		// POST with no media type or a form type; multipart/related and
		// multipart/mixed are parsed too; the media type is the first item
		// of the value split on ; and ,.
		{name: "Rack: empty Content-Type", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{""}, body: del, want: "deny:url_rule"},
		{name: "Rack: parameters only", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"; charset=utf-8"}, body: del, want: "deny:url_rule"},
		{name: "Rack: form first in a list", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT + ", application/json"}, body: del, want: "deny:url_rule"},
		{name: "two Content-Type lines", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json", formCT}, body: del, want: "deny:url_rule"},
		{name: "Rack: chunked, no Content-Type", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, contentLength: -1, want: "deny:url_rule"},
		{name: "Rack: lower-case post", from: "F10", method: "post", host: "api.github.com", path: "/repos/acme/web", body: del, want: "deny:url_rule"},
		{name: "Rack: underscore header name", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", hdr: []string{"x_http_method_override", "DELETE"}, want: "deny:url_rule"},
		{name: "Rack: multipart/mixed (never buffered), closed", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"multipart/mixed; boundary=b"}, body: []byte("--b--"), want: "deny:body_uninspectable"},
		{name: "multipart/form-data, open", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"multipart/form-data; boundary=b"}, body: []byte("--b--"), mode: FailureOpen, want: "alert:method_override_unchecked"},
		// PHP (Laravel, Symfony): $_POST and $_GET keys drop leading
		// spaces, turn . and space into _, and [ starts an array.
		{name: "PHP: dot for underscore", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte(".method=DELETE"), want: "deny:url_rule"},
		{name: "PHP: leading spaces", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte("%20%20_method=DELETE"), want: "deny:url_rule"},
		{name: "PHP: array key", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte("_method[]=DELETE"), want: "deny:url_rule"},
		{name: "PHP: query dot", from: "F10", method: "GET", host: "api.github.com", path: "/repos/acme/web?.method=DELETE", want: "deny:url_rule"},
		{name: "escaped key and value", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte("%5F%6Dethod=DEL%45TE"), want: "deny:url_rule"},
		{name: "plus-padded value", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte("_method=+delete+"), want: "deny:url_rule"},
		// Spring HiddenHttpMethodFilter and Tomcat/ASP.NET read the form in
		// its declared charset.
		{name: "Tomcat: UTF-16 form", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT + "; charset=utf-16le"}, body: ovUTF16LE("_method=DELETE"), want: "deny:url_rule"},
		{name: "ASP.NET: EBCDIC form", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT + "; charset=ibm037"}, body: ebcdic037("_method=DELETE"), want: "deny:url_rule"},
		{name: "unknown charset, closed", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT + "; charset=x-dc-unknown"}, body: []byte("a=1"), want: "deny:body_uninspectable"},
		{name: "unknown charset, open", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT + "; charset=x-dc-unknown"}, body: []byte("a=1"), mode: FailureOpen, want: "alert:method_override_unchecked"},
		{name: "Latin-1 form is ASCII", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT + "; charset=ISO-8859-1"}, body: del, want: "deny:url_rule"},
		// Salesforce REST: ?_HttpMethod=PATCH.
		{name: "Salesforce _HttpMethod", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web?_HttpMethod=DELETE", want: "deny:url_rule"},
		// Content-Encoding: decoded, and also read raw (an origin that
		// ignores the header reads the bytes as they are).
		{name: "gzip label on a plain body", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, hdr: []string{"content-encoding", "gzip"}, body: del, want: "deny:url_rule"},
		{name: "br form, closed", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, hdr: []string{"content-encoding", "br"}, body: []byte{0x1b, 0x02}, want: "deny:body_uninspectable"},
		// Bodies the callout can't read follow failure_mode.
		{name: "over the cap, closed", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: del, contentLength: 1 << 30, want: "deny:body_uninspectable"},
		{name: "over the cap, open", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: del, contentLength: 1 << 30, mode: FailureOpen, want: "alert:method_override_unchecked"},
		{name: "body_inspection off, closed", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, inspect: BodyOff, want: "deny:body_uninspectable"},
		{name: "body_inspection off, open", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, inspect: BodyOff, mode: FailureOpen, want: "alert:method_override_unchecked"},
		{name: "stock Substrate, closed (stk)", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, stock: true, want: "deny:body_uninspectable"},
		{name: "stock Substrate, managed", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: del, stock: true, managed: true, want: "deny:body_uninspectable"},
		{name: "stock Substrate, open", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, stock: true, mode: FailureOpen, want: "unchecked"},
		{name: "body_inspection on, body arrives", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", body: del, inspect: BodyOn, want: "deny:url_rule"},
		// R5: a JSON POST body's top-level _method (Laravel's JSON request
		// bag, Express method-override's req.body getter after express.json()),
		// read where a deny or ask rule names a method other than POST.
		{name: "JSON _method (Laravel)", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_method":"DELETE","title":"x"}`), want: "deny:url_rule"},
		{name: "+json type", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/vnd.api+json"}, body: []byte(`{"_method":"DELETE"}`), want: "deny:url_rule"},
		{name: "JSON charset, case variants", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"Application/JSON; charset=utf-8"}, body: []byte(`{"_METHOD":"delete"}`), want: "deny:url_rule"},
		{name: "JSON _HttpMethod", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_httpMethod":"DELETE"}`), want: "deny:url_rule"},
		{name: "gzip JSON", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, hdr: []string{"content-encoding", "gzip"}, body: ovGzip(`{"_method":"DELETE"}`), want: "deny:url_rule"},
		{name: "JSON duplicate key", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_method":"GET","_method":"DELETE"}`), want: "deny:url_rule"},
		{name: "JSON array value", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_method":["DELETE"]}`), want: "deny:url_rule"},
		{name: "JSON UTF-16 charset", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json; charset=utf-16le"}, body: ovUTF16LE(`{"_method":"DELETE"}`), want: "deny:url_rule"},
		{name: "JSON, stock Substrate, closed", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_method":"DELETE"}`), stock: true, want: "deny:body_uninspectable"},
		{name: "JSON, stock Substrate, open", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_method":"DELETE"}`), stock: true, mode: FailureOpen, want: "unchecked"},
		{name: "JSON, body_inspection off, open", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"_method":"DELETE"}`), inspect: BodyOff, mode: FailureOpen, want: "alert:method_override_unchecked"},
		{name: "JSON ask binds the body method", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/releases/1", ct: []string{"application/json"}, body: []byte(`{"_method":"DELETE"}`),
			rules: []URLRuleCfg{{Name: "release-writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST", "DELETE"}, PathPrefix: "/repos/acme/releases", Action: "ask"}},
			want:  "allow", wantAskMethod: "DELETE", wantAsks: 1},
		{name: "JSON under a POST-only rule is not held", from: "R5", method: "POST", host: "y.example", path: "/api/x", ct: []string{"application/json"}, body: []byte(`{"_method":"DELETE"}`), stock: true,
			rules: []URLRuleCfg{{Name: "api-posts", Hosts: []string{"y.example"}, Methods: []string{"POST"}, PathPrefix: "/api", Action: "ask"}},
			want:  "allow-nobody"},

		// Asks: every applying ask rule is asked, each with its methods.
		{name: "two ask rules both asked", from: "F10", method: "POST", host: "y.example", path: "/api/admin/x", ct: []string{formCT}, body: del,
			rules: []URLRuleCfg{{Name: "api-posts", Hosts: []string{"y.example"}, Methods: []string{"POST"}, PathPrefix: "/api", Action: "ask"},
				{Name: "admin-deletes", Hosts: []string{"y.example"}, Methods: []string{"DELETE"}, PathPrefix: "/api/admin", Action: "ask"}},
			want: "allow", wantAskMethod: "DELETE", wantAsks: 2},

		// Balanced defaults: these pass, and no body is asked for where no
		// rule could apply.
		{name: "JSON API POST, no rule names another method", from: "F10", method: "POST", host: "x.example", path: "/public/x", ct: []string{"application/json"}, body: []byte(`{"title":"x"}`), stock: true, want: "allow-nobody"},
		{name: "JSON with charset, only a POST rule on the path", from: "F10", method: "POST", host: "x.example", path: "/public/x", ct: []string{"application/json; charset=utf-8"}, body: []byte(`{}`), stock: true, managed: true, want: "allow-nobody"},
		{name: "JSON without _method under a DELETE rule, body read", from: "R5", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"application/json"}, body: []byte(`{"title":"x"}`), want: "allow"},
		{name: "plain form", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte("title=hello"), want: "allow"},
		{name: "override to an allowed method", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: []byte("_method=PATCH"), want: "allow"},
		{name: "POST without a body", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", stock: true, want: "allow-nobody"},
		{name: "no rule on the host", from: "F10", method: "POST", host: "example.com", path: "/x", body: del, stock: true, want: "allow-nobody"},
		{name: "no rule on the path", from: "F10", method: "POST", host: "x.example", path: "/public/x", body: del, stock: true,
			rules: []URLRuleCfg{{Name: "no-admin-delete", Hosts: []string{"x.example"}, Methods: []string{"DELETE"}, PathPrefix: "/admin/", Action: "deny"}},
			want:  "allow-nobody"},
		{name: "text/plain is not a form", from: "F10", method: "POST", host: "api.github.com", path: "/repos/acme/web", ct: []string{"text/plain"}, body: del, stock: true, want: "allow-nobody"},
		{name: "PUT form is not overridden", from: "F10", method: "PUT", host: "api.github.com", path: "/repos/acme/web", ct: []string{formCT}, body: del, stock: true, want: "allow-nobody"},
	}
}

func TestMethodOverrideTableGAP0046(t *testing.T) {
	ctx := context.Background()
	for _, c := range ovCases() {
		t.Run(c.from+"/"+c.name, func(t *testing.T) {
			rules := c.rules
			if rules == nil {
				rules = ovTableRules
			}
			h := newHarness(t, func(cfg *Config, _ *Options) {
				cfg.Profiles[0].URLRules = rules
				if c.mode != "" {
					cfg.FailureMode = c.mode
				}
				if c.inspect != "" {
					cfg.BodyInspection = c.inspect
				}
				cfg.Managed = c.managed
			})
			if !c.stock && c.inspect != BodyOff {
				// The egress filter has sent a body before (#3817 body mode).
				h.eng.body.arrived()
			}
			r := req("eng-web", c.method, c.host, c.path, c.hdr...)
			for _, ct := range c.ct {
				r.Headers = append(r.Headers, Header{"content-type", ct})
				r.ContentType = ct
			}
			if c.body != nil {
				r.EndOfStream = false
				r.ContentLength = int64(len(c.body))
				if c.contentLength != 0 {
					r.ContentLength = c.contentLength
				}
			}
			v := h.eng.DecideHeaders(ctx, r)
			askedBody := v.Allow && v.WantBody
			if askedBody && !c.stock {
				v = h.eng.DecideBody(ctx, r, v, c.body)
			}
			findings := strings.Join(v.Findings, ",")
			kind, cat, _ := strings.Cut(c.want, ":")
			switch kind {
			case "deny":
				if v.Allow || v.Category != cat {
					t.Fatalf("want refused (%s), got allow=%v category=%q rule=%q findings=%q", cat, v.Allow, v.Category, v.Rule, findings)
				}
			case "alert":
				if !v.Allow || !v.Alert || !strings.Contains(findings, cat) {
					t.Fatalf("want allowed with alert %q, got allow=%v alert=%v category=%q findings=%q", cat, v.Allow, v.Alert, v.Category, findings)
				}
			case "unchecked":
				// Open mode on a stock filter: the body is asked for and never
				// comes; Server.end records it.
				if !v.Allow || !askedBody {
					t.Fatalf("want allowed awaiting the body, got allow=%v wantBody=%v category=%q", v.Allow, askedBody, v.Category)
				}
			case "allow":
				if !v.Allow {
					t.Fatalf("want allowed, got category=%q rule=%q reason=%q", v.Category, v.Rule, v.Reason)
				}
			case "allow-nobody":
				if !v.Allow || askedBody {
					t.Fatalf("want allowed without a body, got allow=%v wantBody=%v category=%q", v.Allow, askedBody, v.Category)
				}
			default:
				t.Fatalf("bad want %q", c.want)
			}
			if c.wantAsks > 0 && len(h.asks.got) != c.wantAsks {
				t.Fatalf("want %d asks, got %+v", c.wantAsks, h.asks.got)
			}
			if c.noAsk && len(h.asks.got) != 0 {
				t.Fatalf("an ask was raised for a refused request: %+v", h.asks.got)
			}
			if c.wantAskMethod != "" {
				named := false
				for _, a := range h.asks.got {
					if strings.Contains(a.Method, c.wantAskMethod) && strings.Contains(a.Rule, a.Method) {
						named = true
					}
				}
				if !named {
					t.Fatalf("no ask named %q: %+v", c.wantAskMethod, h.asks.got)
				}
			}
		})
	}
}

// TestSameNameRulesKeepTheirOwnApprovalGAP0177: two different url rules
// with one name (substrate.admin's and a profile's are added together) ask
// under different keys, so approving one never answers the other; the
// same rule given twice keeps its name.
func TestSameNameRulesKeepTheirOwnApprovalGAP0177(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {
		c.Profiles[0].URLRules = []URLRuleCfg{
			{Name: "writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/uploads/", Action: "ask"},
			{Name: "writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/admin/", Action: "ask"},
			{Name: "writes", Hosts: []string{"api.github.com"}, Methods: []string{"POST"}, PathPrefix: "/uploads/", Action: "ask"},
		}
	})
	ctx := context.Background()
	h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/uploads/a"))
	h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/admin/x"))
	if len(h.asks.got) != 2 || h.asks.got[0].Rule == h.asks.got[1].Rule {
		t.Fatalf("asks %+v", h.asks.got)
	}
	if h.asks.got[0].Rule != "url_rules:writes POST" || h.asks.got[1].Rule != "url_rules:writes#2 POST" {
		t.Fatalf("keys %q %q", h.asks.got[0].Rule, h.asks.got[1].Rule)
	}
}
