// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const dockerDaemonConfigPath = "/etc/docker/daemon.json"

// ExactDockerInsecureRegistryWrite reports whether one authenticated native
// file-tool call puts a non-loopback insecure registry into Docker's daemon
// configuration, in any spelling Docker accepts (host, host:port, IP, IPv6
// [addr]:port, CIDR, or an http:// or https:// URL, any case of the scheme).
// The call is read from the closed argument shapes of every native file tool
// (nativeFileWrites: Write, the write_file aliases whichever name they give
// the path, Copilot create, OpenCode write, Edit, MultiEdit, a patch), for the
// file the call names, in any spelling that cleans to it, or the file an
// existing link reaches. A whole-file write is judged as the document it
// leaves: any other setting the document carries, or a registry it lists
// twice, does not change the verdict. An edit, a patch hunk or an append
// cannot show the rest of the file, so it is judged on the text it adds: the
// insecure-registries list that text spells, less the entries the text it
// replaces already listed. It deliberately returns no path, registry, or
// content.
func ExactDockerInsecureRegistryWrite(input Input, facts Facts) bool {
	if input.Command != "" || len(input.Argv) != 0 ||
		!facts.Authoritative() || !facts.EnforcementEligible() ||
		facts.Tool != input.Tool {
		return false
	}
	writes := nativeFileWrites(input.Tool, input.Args)
	for _, write := range writes {
		target, ok := nativeAbsoluteTarget(write.target, input.CWD)
		if !ok || !nativeOperandsCoverTarget(facts, len(writes), target) {
			continue
		}
		text := write.added
		if text == "" || len(text) > maxCommandBytes || !utf8.ValidString(text) ||
			strings.ContainsRune(text, 0) {
			continue
		}
		for _, file := range nativeReachedFiles(facts, target) {
			if EtcSpelling(file) == dockerDaemonConfigPath &&
				writeToolNamesItsFile(input) &&
				dockerWriteAddsInsecureRegistry(write) {
				return true
			}
		}
	}
	return false
}

// writeToolNamesItsFile reports whether a Write call names its file the way
// Claude Code's tool does, file_path: a Write that gives the path another name
// is a call the tool refuses, not a write of that file. The other tools
// (write_file aliases, Copilot, OpenCode, edits, patches) take their spellings
// from nativeFileWrites.
func writeToolNamesItsFile(input Input) bool {
	if input.Tool != "Write" {
		return true
	}
	object, problem := exactJSONObject(input.Args)
	_, named := object["file_path"]
	return problem.status == "" && named
}

// dockerWriteAddsInsecureRegistry judges the text of one write of the daemon
// configuration: a whole document by the list it holds, an edit by the list its
// added text spells and the entries the replaced text already listed.
func dockerWriteAddsInsecureRegistry(write nativeFileWrite) bool {
	if write.whole {
		entries, ok := dockerDocumentRegistries(write.added)
		return ok && dockerListAddsInsecureRegistry(entries, nil)
	}
	added, ok := dockerEditTextRegistries(write.added)
	if !ok {
		return false
	}
	kept, _ := dockerEditTextRegistries(write.replaced)
	return dockerListAddsInsecureRegistry(added, kept)
}

// dockerEditTextRegistries reads the list that one side of an edit puts in
// force. Text that is a complete JSON object is a document, read as dockerd
// reads one (the last repeated key wins), so a document an edit swaps for
// another is compared by effective list, not by every list either spells. Any
// other text is a piece of a document and is read for every list it spells.
func dockerEditTextRegistries(text string) ([]string, bool) {
	if strings.HasPrefix(strings.TrimLeft(text, dockerJSONSpace), "{") {
		if document, ok := dockerDecodeDocument(text); ok {
			return dockerRegistryList(document)
		}
	}
	return dockerFragmentRegistries(text)
}

// dockerListAddsInsecureRegistry reports whether every entry is one the closed
// grammar can read and at least one is an insecure registry that the entries
// already in the file (kept) did not list.
func dockerListAddsInsecureRegistry(entries, kept []string) bool {
	had := make(map[string]int, len(kept))
	for _, entry := range kept {
		had[entry]++
	}
	found := false
	for _, entry := range entries {
		insecure, valid := exactDockerRegistryEntry(entry)
		if !valid {
			return false
		}
		if !insecure {
			continue
		}
		if had[entry] > 0 {
			had[entry]--
			continue
		}
		found = true
	}
	return found
}

// dockerDocumentRegistries reads the insecure-registries list of a complete
// daemon.json document. Other settings are not read: they do not change what
// the list does. A repeated key reads as dockerd reads it, the last wins.
func dockerDocumentRegistries(content string) ([]string, bool) {
	document, ok := dockerDecodeDocument(content)
	if !ok {
		return nil, false
	}
	return dockerRegistryList(document)
}

// dockerDecodeDocument decodes content as one JSON object. ok is false when it
// is not one, or holds a string beyond the proof's limit.
func dockerDecodeDocument(content string) (map[string]any, bool) {
	raw := []byte(content)
	if issue := validateJSONWithStringLimit(raw, maxScalarBytes); issue != "" &&
		issue != IssueDuplicateJSONKey {
		return nil, false
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return nil, false
	}
	return document, true
}

// dockerRegistryList is the insecure-registries list of a decoded document;
// ok is false when the key holds anything but a list of strings.
func dockerRegistryList(document map[string]any) ([]string, bool) {
	value, present := document["insecure-registries"]
	if !present {
		return nil, true
	}
	list, ok := value.([]any)
	if !ok {
		return nil, false
	}
	entries := make([]string, 0, len(list))
	for _, item := range list {
		entry, ok := item.(string)
		if !ok {
			return nil, false
		}
		entries = append(entries, entry)
	}
	return entries, true
}

const dockerJSONSpace = " \t\r\n"

// dockerFragmentRegistries reads the entries of every top-level
// insecure-registries list that a piece of daemon.json text spells, including a
// list the piece cuts off before its closing bracket. A piece without the key
// lists nothing. ok is false when a list holds anything but JSON strings.
//
// A piece of an edit can start inside a string, so the text is read from both
// alignments (starting outside a string, and starting inside one) and the
// entries of both are taken: the verdict never depends on where the edit cut
// the file.
func dockerFragmentRegistries(text string) (entries []string, ok bool) {
	for _, insideString := range []bool{false, true} {
		found, valid := dockerFragmentTopLevelLists(text, insideString)
		if !valid {
			return nil, false
		}
		entries = append(entries, found...)
	}
	return entries, true
}

// dockerFragmentTopLevelLists scans text as JSON tokens and reads the list of
// every key that decodes to insecure-registries and is not nested in an object
// or array the text itself opens as a key's value (the key means something
// else there, as in a builder block). The key is decoded as JSON, so an escaped
// spelling names the same key. Containers the text closes without having opened
// are the file's own, whose depth the text cannot show, so keys after them are
// read as top-level.
func dockerFragmentTopLevelLists(text string, insideString bool) (entries []string, ok bool) {
	const key = "insecure-registries"
	var nested []bool
	previous := byte(0)
	index := 0
	if insideString {
		end := dockerStringBodyEnd(text, 0)
		if end < 0 {
			return nil, true
		}
		index, previous = end+1, '"'
	}
	for index < len(text) {
		switch character := text[index]; character {
		case '"':
			end := dockerJSONStringEnd(text[index:])
			if end < 0 {
				return entries, true
			}
			literal := text[index : index+end]
			index += end
			rest := strings.TrimLeft(text[index:], dockerJSONSpace)
			previous = '"'
			var name string
			if !strings.HasPrefix(rest, ":") || len(nested) > 0 && nested[len(nested)-1] ||
				json.Unmarshal([]byte(literal), &name) != nil || name != key {
				continue
			}
			list, listed, valid := dockerFragmentList(text[index:])
			if !valid {
				return nil, false
			}
			if listed {
				entries = append(entries, list...)
			}
		case '{', '[':
			inside := len(nested) > 0 && nested[len(nested)-1]
			nested = append(nested, inside || previous == ':')
			previous = character
			index++
		case '}', ']':
			if len(nested) > 0 {
				nested = nested[:len(nested)-1]
			}
			previous = character
			index++
		case ' ', '\t', '\r', '\n':
			index++
		default:
			previous = character
			index++
		}
	}
	return entries, true
}

// dockerStringBodyEnd is the index of the quote that closes a string whose
// opening quote lies before text[from], or -1 when the text ends first.
func dockerStringBodyEnd(text string, from int) int {
	for index := from; index < len(text); index++ {
		switch text[index] {
		case '\\':
			index++
		case '"':
			return index
		}
	}
	return -1
}

// dockerFragmentList reads `: ["a", "b"` after a key. listed is false when
// what follows the key is not a list.
func dockerFragmentList(rest string) (entries []string, listed, valid bool) {
	rest = strings.TrimLeft(rest, dockerJSONSpace)
	if !strings.HasPrefix(rest, ":") {
		return nil, false, true
	}
	rest = strings.TrimLeft(rest[1:], dockerJSONSpace)
	if !strings.HasPrefix(rest, "[") {
		return nil, false, true
	}
	rest = rest[1:]
	for {
		rest = strings.TrimLeft(rest, dockerJSONSpace)
		if rest == "" || rest[0] == ']' {
			return entries, true, true
		}
		end := dockerJSONStringEnd(rest)
		if end < 0 {
			return nil, true, false
		}
		var entry string
		if json.Unmarshal([]byte(rest[:end]), &entry) != nil {
			return nil, true, false
		}
		entries = append(entries, entry)
		rest = strings.TrimLeft(rest[end:], dockerJSONSpace)
		switch {
		case rest == "" || rest[0] == ']':
			return entries, true, true
		case rest[0] == ',':
			rest = rest[1:]
		default:
			return nil, true, false
		}
	}
}

// dockerJSONStringEnd is the length of the JSON string literal that opens
// text, or -1 when text does not open with a complete one.
func dockerJSONStringEnd(text string) int {
	if text == "" || text[0] != '"' {
		return -1
	}
	for index := 1; index < len(text); index++ {
		switch text[index] {
		case '\\':
			index++
		case '"':
			return index + 1
		}
	}
	return -1
}

// exactDockerRegistryEntry classifies one insecure-registries element. Docker
// accepts four spellings: an http:// or https:// URL, a CIDR block, a bare
// IP address, and host or host:port (including [IPv6]:port). Every spelling
// makes the named registry insecure, so the spelling never decides the
// verdict; only the address does. valid is false for anything the closed
// grammar cannot prove, which leaves the whole document unproven. insecure is
// true for a registry that is not covered by the built-in loopback exception.
func exactDockerRegistryEntry(value string) (insecure bool, valid bool) {
	if value == "" || len(value) > maxScalarBytes ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") ||
		containsDockerRegistryInterpolation(value) {
		return false, false
	}
	switch {
	case strings.Contains(value, "://"):
		return exactDockerRegistryURL(value)
	case strings.Contains(value, "/"):
		return exactDockerRegistryCIDR(value)
	default:
		return exactDockerRegistryHostPort(value)
	}
}

// exactDockerRegistryURL reads an http:// or https:// entry. Docker lower-cases
// the scheme, so HTTP:// names the same registry; a trailing slash is the
// empty path.
func exactDockerRegistryURL(value string) (insecure bool, valid bool) {
	scheme, _, _ := strings.Cut(value, "://")
	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return false, false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != scheme || parsed.Opaque != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" && parsed.Path != "/" || parsed.Host == "" {
		return false, false
	}
	insecure, valid = exactDockerRegistryHost(parsed.Hostname())
	if !valid || !exactDockerRegistryPort(parsed.Port()) {
		return false, false
	}
	return insecure, true
}

// exactDockerRegistryHostPort reads the scheme-less spellings: a bare IPv4 or
// IPv6 address, a host, host:port or IPv4:port, and a bracketed [IPv6]:port.
func exactDockerRegistryHostPort(value string) (insecure bool, valid bool) {
	if address, err := netip.ParseAddr(value); err == nil {
		return exactDockerRegistryAddress(address)
	}
	host := value
	if strings.Contains(value, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil || port == "" || !exactDockerRegistryPort(port) {
			return false, false
		}
		if strings.HasPrefix(value, "[") {
			address, err := netip.ParseAddr(host)
			if err != nil || !address.Is6() {
				return false, false
			}
		}
	}
	return exactDockerRegistryHost(host)
}

// exactDockerRegistryCIDR reads a CIDR block. A block is the loopback
// exception only when every address in it is loopback; a wider block (for
// example one that spans private ranges) names non-loopback registries.
func exactDockerRegistryCIDR(value string) (insecure bool, valid bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" {
		return false, false
	}
	address, bits := prefix.Addr(), prefix.Bits()
	if address.Is4In6() {
		if bits < 96 {
			return true, true
		}
		address, bits = address.Unmap(), bits-96
	}
	if address.IsLoopback() && bits >= loopbackBlockBits(address) ||
		address.IsUnspecified() && bits == address.BitLen() {
		return false, true
	}
	return true, true
}

// loopbackBlockBits is the shortest prefix that keeps a block inside the
// loopback range: 127.0.0.0/8 for IPv4, the single address ::1 for IPv6.
func loopbackBlockBits(address netip.Addr) int {
	if address.Is4() {
		return 8
	}
	return address.BitLen()
}

func containsDockerRegistryInterpolation(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.ContainsRune(value, 0x60)
}

// exactDockerRegistryHost classifies a registry host name or address. A
// loopback name or address is valid but not insecure: Docker already trusts
// it, so it cannot make a document hazardous, and it must not make a document
// that also lists a remote registry unprovable.
func exactDockerRegistryHost(host string) (insecure bool, valid bool) {
	if host == "" || len(host) > 253 || !dockerRegistryASCII(host) {
		return false, false
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return false, true
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return exactDockerRegistryAddress(address)
	}
	// Reject non-canonical numeric IPv4 spellings rather than relying on a
	// platform resolver to decide whether they denote loopback.
	if dockerRegistryNumericHost(host) {
		return false, false
	}
	if strings.HasSuffix(host, ".") {
		return false, false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false, false
		}
		for _, character := range label {
			if !strings.ContainsRune(dockerRegistryLabelCharacters, character) {
				return false, false
			}
		}
	}
	return true, true
}

const dockerRegistryLabelCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

func exactDockerRegistryAddress(address netip.Addr) (insecure bool, valid bool) {
	address = address.Unmap()
	if address.Zone() != "" {
		return false, false
	}
	return !address.IsLoopback() && !address.IsUnspecified(), true
}

func dockerRegistryNumericHost(value string) bool {
	return strings.Trim(value, "0123456789.") == ""
}

// exactDockerRegistryPort reads a port the way Docker does, as a decimal
// number up to 65535: zero-padded spellings of any length name the same port.
func exactDockerRegistryPort(port string) bool {
	digits := strings.TrimPrefix(port, "+")
	if port != "" && digits == "" || strings.Trim(digits, "0123456789") != "" {
		return false
	}
	digits = strings.TrimLeft(digits, "0")
	if len(digits) > 5 {
		return false
	}
	if digits == "" {
		return true
	}
	value, err := strconv.Atoi(digits)
	return err == nil && value <= 65535
}

func dockerRegistryASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
