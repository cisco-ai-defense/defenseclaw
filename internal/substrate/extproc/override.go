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
	"encoding/json"
	"mime"
	"net/url"
	"slices"
	"strings"

	"golang.org/x/text/encoding/ianaindex"
)

// Method overrides (GAP-0046). An origin may run a request as another
// method than its request line says. The callout takes the union of what
// the common server frameworks read, so an url rule applies whichever
// framework the origin runs:
//   - headers: X-HTTP-Method-Override (Rack, Express method-override,
//     Symfony and Laravel, ASP.NET Core, gorilla/handlers, Echo, Google
//     APIs), X-HTTP-Method (OData), X-Method-Override; every line, and
//     every value of a comma list (Express takes the first, others the
//     last). An underscore spelling of the name counts too: CGI-style
//     servers (Rack, PHP) read X_HTTP_METHOD_OVERRIDE as the same header;
//   - the query: _method (Express method-override's query getter, Spring's
//     HiddenHttpMethodFilter, Symfony and Laravel, gorilla, Echo) and
//     _HttpMethod (Salesforce REST);
//   - the body of a POST read as a form: _method (Rack::MethodOverride in
//     Rails, Sinatra and Hanami; Symfony and Laravel; Spring; gorilla;
//     ASP.NET Core's form field; django-method-override). Rack reads a POST
//     with no media type as a form, so a body without a Content-Type
//     counts (see bodyOverridable);
//   - the top-level _method (or _HttpMethod) of a JSON POST body: Laravel
//     swaps the request bag for a JSON body, and Symfony's getMethod reads
//     _method there; Express method-override's documented req.body getter
//     reads it after express.json(). Only where a deny or ask rule names a
//     method other than POST (see jsonOverridable), so other JSON API POSTs
//     are never held.
//
// Parameter keys are read as the most lenient of them does: percent and
// "+" decoding, any case, PHP's key rules (leading spaces dropped, "." and
// " " read as "_", "[" starting an array) and a NUL ending the key.
// Values are upper-cased, so _method=delete is DELETE.

// methodOverrideHeaders are the override header names, lower case, with
// "-" for "_" (see overrideHeaderName).
var methodOverrideHeaders = []string{"x-http-method-override", "x-http-method", "x-method-override"}

// methodOverrideParams are the override parameter keys, in lower case
// (see paramKey).
var methodOverrideParams = []string{"_method", "_httpmethod"}

func overrideHeaderName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// requestMethods is the request's method plus every method an override
// header or query parameter names, upper-cased (GAP-0046). A body override
// is added by bodyMethods when the body is read.
func requestMethods(req *Request) []string {
	out := []string{strings.ToUpper(req.Method)}
	for _, h := range req.Headers {
		if slices.Contains(methodOverrideHeaders, overrideHeaderName(h.Name)) {
			out = appendMethods(out, h.Value)
		}
	}
	if i := strings.IndexByte(req.Path, '?'); i >= 0 {
		q := req.Path[i+1:]
		if j := strings.IndexByte(q, '#'); j >= 0 {
			q = q[:j]
		}
		out = appendMethods(out, strings.Join(overrideParams(q), ","))
	}
	return out
}

// overrideParams is every value of an override parameter in a query or an
// urlencoded form, read leniently: a malformed pair elsewhere does not hide
// it, and pairs split on "&" and ";".
func overrideParams(q string) []string {
	var out []string
	for _, pair := range strings.FieldsFunc(q, func(r rune) bool { return r == '&' || r == ';' }) {
		k, v, _ := strings.Cut(pair, "=")
		if !slices.Contains(methodOverrideParams, paramKey(k)) {
			continue
		}
		if dv, err := url.QueryUnescape(v); err == nil {
			out = append(out, dv)
		} else {
			out = append(out, v)
		}
	}
	return out
}

// paramKey is a query or form key as the most lenient framework reads it:
// decoded (an invalid escape is kept as is, as PHP does), cut at a NUL,
// leading spaces dropped, "." and " " as "_" (PHP), cut at "[" (a PHP or
// Rack array), trimmed and in lower case.
func paramKey(k string) string {
	if dk, err := url.QueryUnescape(k); err == nil {
		k = dk
	} else {
		k = strings.ReplaceAll(k, "+", " ")
	}
	if i := strings.IndexByte(k, 0); i >= 0 {
		k = k[:i]
	}
	k = strings.TrimLeft(k, " ")
	if i := strings.IndexByte(k, '['); i >= 0 {
		k = k[:i]
	}
	k = strings.NewReplacer(".", "_", " ", "_").Replace(k)
	return strings.ToLower(strings.TrimSpace(k))
}

// appendMethods adds each comma-separated value of v, trimmed and
// upper-cased, once.
func appendMethods(out []string, v string) []string {
	for _, m := range strings.Split(v, ",") {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// contentTypes is every Content-Type line of the request.
func contentTypes(req *Request) []string {
	var out []string
	for _, h := range req.Headers {
		if h.Name == "content-type" {
			out = append(out, h.Value)
		}
	}
	if len(out) == 0 && req.ContentType != "" {
		out = []string{req.ContentType}
	}
	return out
}

// mediaTypes is every media type the Content-Type lines name: each comma
// item of each line, cut at ";", trimmed and in lower case. Rack and PHP
// read the first item of a list; another reader may take another one.
func mediaTypes(req *Request) []string {
	var out []string
	for _, line := range contentTypes(req) {
		for _, item := range strings.Split(line, ",") {
			mt, _, _ := strings.Cut(item, ";")
			out = append(out, strings.ToLower(strings.TrimSpace(mt)))
		}
	}
	return out
}

// bodyOverridable is a POST with a body some framework reads as a form, so
// its body may name the method (_method): no Content-Type at all, an empty
// media type (Rack::Request#form_data? is a POST with no media type),
// application/x-www-form-urlencoded or any multipart type (Rack parses
// multipart/related and multipart/mixed too), in any case and with any
// parameters, in any line or list item. A JSON or other typed body is not,
// so a normal API POST never waits for its body (balanced defaults).
func bodyOverridable(req *Request) bool {
	if !strings.EqualFold(req.Method, "POST") || req.EndOfStream {
		return false
	}
	mts := mediaTypes(req)
	if len(mts) == 0 {
		return true
	}
	for _, mt := range mts {
		if mt == "" || strings.HasPrefix(mt, "application/x-www-form-urlencoded") || strings.HasPrefix(mt, "multipart/") {
			return true
		}
	}
	return false
}

// jsonBody is a POST with a body whose Content-Type (any line or list item,
// any case or parameters) is application/json or a +json type.
func jsonBody(req *Request) bool {
	if !strings.EqualFold(req.Method, "POST") || req.EndOfStream {
		return false
	}
	for _, mt := range mediaTypes(req) {
		if mt == "application/json" || strings.HasSuffix(mt, "+json") {
			return true
		}
	}
	return false
}

// jsonOverrideMethods is every value of a top-level override key
// (_method, _HttpMethod, in any case) of a JSON object, duplicates
// included; a string, or each string of an array. Anything that is not a
// JSON object names none.
func jsonOverrideMethods(b []byte) []string {
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(b)))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil
	}
	var out []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		key, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return out
		}
		if !slices.Contains(methodOverrideParams, strings.ToLower(strings.TrimSpace(key))) {
			continue
		}
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			out = append(out, one)
		case json.Unmarshal(raw, &many) == nil:
			out = append(out, many...)
		}
	}
	return out
}

// multipartBody is a body the callout never buffers (D9), so its parts are
// never read.
func multipartBody(req *Request) bool {
	for _, mt := range mediaTypes(req) {
		if strings.HasPrefix(mt, "multipart/") {
			return true
		}
	}
	return false
}

// Why a body that may name the method can't be read (method_override).
const (
	whyMultipart = "multipart"
	whyNoBody    = "body_not_received"
)

// bodyMethods is every method a form or JSON body names in _method, read the ways
// an origin may read it: as sent (an origin that ignores Content-Encoding),
// decoded (gzip, deflate), and in each charset a Content-Type line declares
// (Tomcat, ASP.NET and Spring decode a form in its charset: UTF-16 and
// EBCDIC included). why is set when some reading was not possible: an
// encoding or charset the callout can't decode, or a decoded body over
// max. The methods found are returned either way, so one the callout can
// read still refuses.
func bodyMethods(raw []byte, req *Request, max int64) (methods []string, why string) {
	readings := [][]byte{raw}
	decoded, dwhy := decodeBody(raw, req.headerList("content-encoding"), "", max)
	if dwhy == "" {
		readings = append(readings, decoded)
	} else {
		why, decoded = dwhy, raw
	}
	for _, line := range contentTypes(req) {
		_, params, err := mime.ParseMediaType(line)
		if err != nil {
			continue
		}
		cs := strings.ToLower(strings.TrimSpace(params["charset"]))
		if cs == "" || asciiCompatible(cs) {
			continue
		}
		enc, err := ianaindex.IANA.Encoding(cs)
		if err != nil || enc == nil {
			why = unreadableCharset
			continue
		}
		b, err := enc.NewDecoder().Bytes(decoded)
		if err != nil {
			why = unreadableCharset
			continue
		}
		readings = append(readings, b)
	}
	for _, b := range readings {
		methods = appendMethods(methods, strings.Join(overrideParams(string(b)), ","))
		methods = appendMethods(methods, strings.Join(jsonOverrideMethods(b), ","))
	}
	return methods, why
}

// asciiCompatible is a charset in which an ASCII form reads byte for byte.
func asciiCompatible(cs string) bool {
	switch cs {
	case "utf-8", "utf8", "us-ascii", "ascii", "latin1", "l1":
		return true
	}
	return strings.HasPrefix(cs, "iso-8859-") || strings.HasPrefix(cs, "iso8859-") || strings.HasPrefix(cs, "windows-125") ||
		strings.HasPrefix(cs, "cp125")
}
