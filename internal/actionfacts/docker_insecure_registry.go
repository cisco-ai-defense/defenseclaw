// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"net/url"
	"path"
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
// (nativeCallWrites: Write, the write_file aliases whichever name they give
// the path, Copilot create, OpenCode write, Edit, MultiEdit, a patch), for the
// file the call names, in any spelling that cleans to it, or the file an
// existing link reaches. A whole-file write is judged as the document it
// leaves: any other setting the document carries, or a registry it lists
// twice, does not change the verdict. An Edit or MultiEdit of a file the
// gateway read (Input.ClientNativeFileContents) is applied to that text, step
// by step, as the tool applies it, and the document it leaves is judged as a
// write of it; no step is read on its own. An edit of a file that could not be
// read, a patch or an append is not given the file it changes, so it is judged
// on the text it leaves in place,
// the union of every replacement of a multi-step edit and every hunk of a
// patch (its context and added lines), read for the lists it spells, whatever
// the file held before: an entry the file already listed, or that another
// step took out of a key, earns no credit, as a write of the document would
// not. It deliberately returns no path, registry, or content.
func ExactDockerInsecureRegistryWrite(input Input, facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		facts.Tool != input.Tool {
		return false
	}
	writes, facts := nativeCallWrites(input, facts)
	for _, write := range writes {
		target, _ := nativeAbsoluteTarget(write.target, input.CWD)
		document, applied := "", false
		if content, read := input.ClientNativeFileContents[target]; read && dockerJudgeableText(content) {
			document, applied = write.applyEdits(content)
		}
		// The file the tool writes is a document, judged as a Write of it.
		if applied && !dockerJudgeableText(document) ||
			!applied && !dockerJudgeableText(write.added) {
			continue
		}
		// An absolute name is placed by its lexical clean, a relative one in the
		// working directory of the call, and a name that steps up a directory is
		// the file the client answered with when it gave one; a link or a name
		// the gateway cannot place is read from the client answer.
		for _, file := range nativeWriteFiles(input, facts, writes, write, true) {
			if EtcSpelling(file) != dockerDaemonConfigPath || !writeToolNamesItsFile(input) {
				continue
			}
			if applied {
				if dockerDocumentHasInsecureRegistry(document) {
					return true
				}
			} else if dockerWriteAddsInsecureRegistry(write) {
				return true
			}
		}
	}
	return false
}

// dockerJudgeableText reports whether text is one the proof reads: some text,
// within the proof's bound, valid UTF-8, with no NUL.
func dockerJudgeableText(text string) bool {
	return text != "" && len(text) <= maxCommandBytes && utf8.ValidString(text) &&
		!strings.ContainsRune(text, 0)
}

// DockerDaemonConfigEditFiles names, for each Edit or MultiEdit of a native
// file-tool call that changes Docker's daemon configuration (by its own name
// or through a link the client or this gateway placed on it), the file whose
// text the call changes, keyed by the cleaned absolute target of the call
// (the key of Input.ClientNativeFileContents). A gateway that can read those
// files supplies their text, so the edit is judged on the document it leaves.
func DockerDaemonConfigEditFiles(input Input) map[string]string {
	if input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	isDaemonConfig := func(name string) bool {
		return name != "" && EtcSpelling(path.Clean(name)) == dockerDaemonConfigPath
	}
	var files map[string]string
	for _, write := range nativeFileWrites(input.Tool, input.Args) {
		target, ok := nativeAbsoluteTarget(write.target, input.CWD)
		if !ok || !write.edit {
			continue
		}
		file := ""
		if isDaemonConfig(target) {
			file = target
		} else if physical, linked := clientResolvedTargetWhere(
			write.target, input.CWD, input.ClientWorkingDirectories, input.ClientResolvedTargets, isDaemonConfig,
		); linked {
			file = physical
		}
		if file == "" {
			continue
		}
		if files == nil {
			files = map[string]string{}
		}
		files[target] = file
	}
	return files
}

// writeToolNamesItsFile reports whether a Write call names its file the way
// Claude Code's tool does, file_path: a Write that gives the path another name
// is a call the tool refuses, not a write of that file. The other tools
// (write_file aliases, Copilot, OpenCode, edits, patches) take their spellings
// from nativeCallWrites.
func writeToolNamesItsFile(input Input) bool {
	if input.Tool != "Write" {
		return true
	}
	object, problem := exactJSONObject(input.Args)
	_, named := object["file_path"]
	return problem.status == "" && named
}

// dockerWriteAddsInsecureRegistry judges the text of one write of the daemon
// configuration: a whole document by the list dockerd reads from it, an edit
// or a patch by the text it leaves in place. The file the edit changes is not
// given, so no step is credited for what the file held or what another step
// took out: the pieces (each replacement of a multi-step edit, each hunk of a
// patch, all of them joined, and the text the steps of a multi-step edit
// make where they meet (editPieces), for a list or a name that one piece opens and another
// closes) are each read for the lists they spell, and one piece that puts an
// insecure registry in force is the verdict. Within a piece the last list
// wins, as in a document, so a piece that lists a registry and then empties the
// list, or sets the key to null, puts nothing in force. A piece the grammar
// cannot read (dockerd refuses such a file) adds nothing.
func dockerWriteAddsInsecureRegistry(write nativeFileWrite) bool {
	if write.whole {
		return dockerDocumentHasInsecureRegistry(write.added)
	}
	for _, piece := range write.editPieces() {
		if entries, ok := dockerEditTextRegistries(piece); ok && dockerListHasInsecureRegistry(entries) {
			return true
		}
	}
	return false
}

// dockerEditTextRegistries reads the list that a piece of an edit puts in
// force. Text that is a complete JSON object is a document, read as dockerd
// reads one (the last repeated key wins). Any other text is a piece of a
// document and is read the same way for the keys it spells: the last list the
// piece spells is the one in force.
func dockerEditTextRegistries(text string) ([]string, bool) {
	if strings.HasPrefix(strings.TrimLeft(text, dockerJSONSpace), "{") {
		if document, ok := dockerDecodeDocument(text); ok {
			return dockerRegistryList(document)
		}
	}
	return dockerFragmentRegistries(text)
}

// dockerListHasInsecureRegistry reports whether every entry is one the closed
// grammar can read and at least one is an insecure registry.
func dockerListHasInsecureRegistry(entries []string) bool {
	found := false
	for _, entry := range entries {
		insecure, valid := exactDockerRegistryEntry(entry)
		if !valid {
			return false
		}
		found = found || insecure
	}
	return found
}

// dockerDocumentHasInsecureRegistry reports whether the complete daemon.json
// document puts a non-loopback insecure registry in force.
func dockerDocumentHasInsecureRegistry(content string) bool {
	entries, ok := dockerDocumentRegistries(content)
	return ok && dockerListHasInsecureRegistry(entries)
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
	// The validator stops at a repeated key, so the text after the first
	// object is checked here: a document is exactly one object.
	if _, err := decoder.Token(); err != io.EOF {
		return nil, false
	}
	return document, true
}

// dockerRegistryList is the insecure-registries list of a decoded document;
// ok is false when the key holds anything but a list of strings or null (which
// dockerd reads as an empty list).
func dockerRegistryList(document map[string]any) ([]string, bool) {
	value := document["insecure-registries"]
	if value == nil {
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

// dockerFragmentRegistries reads the last top-level insecure-registries list
// that a piece of daemon.json text spells, including a list the piece cuts off
// before its closing bracket; a last value of null is an empty list. A piece
// without the key lists nothing. ok is false when a list holds anything but
// JSON strings.
//
// A piece of an edit can start inside a string, so the text is read from both
// alignments (starting outside a string, and starting inside one) and the
// lists of both are taken: the verdict never depends on where the edit cut
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
// the last key that decodes to insecure-registries and is not nested in an object
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
				entries = list
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

// dockerFragmentList reads `: ["a", "b"` after a key, or `: null`, which is a
// list without entries. listed is false when what follows the key is neither.
func dockerFragmentList(rest string) (entries []string, listed, valid bool) {
	rest = strings.TrimLeft(rest, dockerJSONSpace)
	if !strings.HasPrefix(rest, ":") {
		return nil, false, true
	}
	rest = strings.TrimLeft(rest[1:], dockerJSONSpace)
	// A value that starts with null is read as null whatever follows: text
	// that follows it without a separator (pieces of an edit that meet) makes a
	// file dockerd refuses, which sets nothing.
	if strings.HasPrefix(rest, "null") {
		return nil, true, true
	}
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
