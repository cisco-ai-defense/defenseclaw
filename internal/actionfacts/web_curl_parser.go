// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"math"
	"strconv"
	"strings"
)

// curlOptionArity describes lexical operand ownership. In particular, a
// required operand owns the next argv element even when it is empty or starts
// with '-'. Curl stops expanding a short-option bundle once such an option is
// reached; the remainder of that token is the joined operand.
type curlOptionArity uint8

const (
	curlOptionNoValue curlOptionArity = iota
	curlOptionRequiredValue
	curlOptionOptionalValue
)

// curlOptionRole captures only behavior needed to project transfer ownership.
// Callers can use Canonical on curlOptionToken for more detailed classification
// without re-parsing argv.
type curlOptionRole uint8

const (
	curlOptionNeutral curlOptionRole = iota
	curlOptionConfig
	curlOptionTarget
	curlOptionOutput
	curlOptionRemoteName
	curlOptionRemoteNameAll
	curlOptionNoRemoteName
	curlOptionNoRemoteNameAll
	curlOptionMethod
	curlOptionUpload
	curlOptionHead
	curlOptionNoHead
	curlOptionPreview
	curlOptionNetworkOverride
	// curlOptionTelnetProof owns curl 8.7.1 grammar that is closed for the
	// exact direct-Telnet projector. Generic curl classification must remain
	// partial until another protocol lane proves the same option semantics.
	curlOptionTelnetProof
)

type curlOptionSpec struct {
	canonical string
	arity     curlOptionArity
	role      curlOptionRole
}

func curlFlag(canonical string, role curlOptionRole) curlOptionSpec {
	return curlOptionSpec{canonical: canonical, role: role}
}

func curlValue(canonical string, role curlOptionRole) curlOptionSpec {
	return curlOptionSpec{
		canonical: canonical,
		arity:     curlOptionRequiredValue,
		role:      role,
	}
}

func curlOptionalValue(canonical string, role curlOptionRole) curlOptionSpec {
	return curlOptionSpec{
		canonical: canonical,
		arity:     curlOptionOptionalValue,
		role:      role,
	}
}

// curlLongOptionSpecs is intentionally metadata, rather than parser control
// flow. Short and long aliases resolve to the same canonical name and role.
// Adding a known option therefore updates lexical ownership for control-mode,
// classification, and exact-output consumers together when they integrate
// with parseCurlArgv.
var curlLongOptionSpecs = map[string]curlOptionSpec{
	// These curl 8.7.1 options are owned for the exact direct-Telnet proof.
	// Keeping their role distinct prevents parser ownership from silently
	// broadening generic HTTP/FTP authority.
	"--alpn":                          curlFlag("--alpn", curlOptionTelnetProof),
	"--no-alpn":                       curlFlag("--alpn", curlOptionTelnetProof),
	"--anyauth":                       curlFlag("--anyauth", curlOptionTelnetProof),
	"--no-anyauth":                    curlFlag("--anyauth", curlOptionTelnetProof),
	"--basic":                         curlFlag("--basic", curlOptionTelnetProof),
	"--no-basic":                      curlFlag("--basic", curlOptionTelnetProof),
	"--ca-native":                     curlFlag("--ca-native", curlOptionTelnetProof),
	"--no-ca-native":                  curlFlag("--ca-native", curlOptionTelnetProof),
	"--cert-status":                   curlFlag("--cert-status", curlOptionTelnetProof),
	"--no-cert-status":                curlFlag("--cert-status", curlOptionTelnetProof),
	"--clobber":                       curlFlag("--clobber", curlOptionTelnetProof),
	"--no-clobber":                    curlFlag("--clobber", curlOptionTelnetProof),
	"--compressed-ssh":                curlFlag("--compressed-ssh", curlOptionTelnetProof),
	"--no-compressed-ssh":             curlFlag("--compressed-ssh", curlOptionTelnetProof),
	"--create-dirs":                   curlFlag("--create-dirs", curlOptionTelnetProof),
	"--no-create-dirs":                curlFlag("--create-dirs", curlOptionTelnetProof),
	"--digest":                        curlFlag("--digest", curlOptionTelnetProof),
	"--no-digest":                     curlFlag("--digest", curlOptionTelnetProof),
	"--disallow-username-in-url":      curlFlag("--disallow-username-in-url", curlOptionTelnetProof),
	"--no-disallow-username-in-url":   curlFlag("--disallow-username-in-url", curlOptionTelnetProof),
	"--doh-cert-status":               curlFlag("--doh-cert-status", curlOptionTelnetProof),
	"--no-doh-cert-status":            curlFlag("--doh-cert-status", curlOptionTelnetProof),
	"--doh-insecure":                  curlFlag("--doh-insecure", curlOptionTelnetProof),
	"--no-doh-insecure":               curlFlag("--doh-insecure", curlOptionTelnetProof),
	"--fail-early":                    curlFlag("--fail-early", curlOptionTelnetProof),
	"--no-fail-early":                 curlFlag("--fail-early", curlOptionTelnetProof),
	"--false-start":                   curlFlag("--false-start", curlOptionTelnetProof),
	"--no-false-start":                curlFlag("--false-start", curlOptionTelnetProof),
	"--form-escape":                   curlFlag("--form-escape", curlOptionTelnetProof),
	"--no-form-escape":                curlFlag("--form-escape", curlOptionTelnetProof),
	"--haproxy-protocol":              curlFlag("--haproxy-protocol", curlOptionTelnetProof),
	"--no-haproxy-protocol":           curlFlag("--haproxy-protocol", curlOptionTelnetProof),
	"--http0.9":                       curlFlag("--http0.9", curlOptionTelnetProof),
	"--no-http0.9":                    curlFlag("--http0.9", curlOptionTelnetProof),
	"--http1.1":                       curlFlag("--http1.1", curlOptionTelnetProof),
	"--http2":                         curlFlag("--http2", curlOptionTelnetProof),
	"--http2-prior-knowledge":         curlFlag("--http2-prior-knowledge", curlOptionTelnetProof),
	"--http3":                         curlFlag("--http3", curlOptionTelnetProof),
	"--http3-only":                    curlFlag("--http3-only", curlOptionTelnetProof),
	"--keepalive":                     curlFlag("--keepalive", curlOptionTelnetProof),
	"--no-keepalive":                  curlFlag("--keepalive", curlOptionTelnetProof),
	"--location-trusted":              curlFlag("--location-trusted", curlOptionTelnetProof),
	"--no-location-trusted":           curlFlag("--location-trusted", curlOptionTelnetProof),
	"--metalink":                      curlFlag("--metalink", curlOptionTelnetProof),
	"--no-metalink":                   curlFlag("--metalink", curlOptionTelnetProof),
	"--negotiate":                     curlFlag("--negotiate", curlOptionTelnetProof),
	"--no-negotiate":                  curlFlag("--negotiate", curlOptionTelnetProof),
	"--ntlm":                          curlFlag("--ntlm", curlOptionTelnetProof),
	"--no-ntlm":                       curlFlag("--ntlm", curlOptionTelnetProof),
	"--ntlm-wb":                       curlFlag("--ntlm-wb", curlOptionTelnetProof),
	"--no-ntlm-wb":                    curlFlag("--ntlm-wb", curlOptionTelnetProof),
	"--parallel-immediate":            curlFlag("--parallel-immediate", curlOptionTelnetProof),
	"--no-parallel-immediate":         curlFlag("--parallel-immediate", curlOptionTelnetProof),
	"--post301":                       curlFlag("--post301", curlOptionTelnetProof),
	"--no-post301":                    curlFlag("--post301", curlOptionTelnetProof),
	"--post302":                       curlFlag("--post302", curlOptionTelnetProof),
	"--no-post302":                    curlFlag("--post302", curlOptionTelnetProof),
	"--post303":                       curlFlag("--post303", curlOptionTelnetProof),
	"--no-post303":                    curlFlag("--post303", curlOptionTelnetProof),
	"--proxy-anyauth":                 curlFlag("--proxy-anyauth", curlOptionTelnetProof),
	"--no-proxy-anyauth":              curlFlag("--proxy-anyauth", curlOptionTelnetProof),
	"--proxy-basic":                   curlFlag("--proxy-basic", curlOptionTelnetProof),
	"--no-proxy-basic":                curlFlag("--proxy-basic", curlOptionTelnetProof),
	"--proxy-ca-native":               curlFlag("--proxy-ca-native", curlOptionTelnetProof),
	"--no-proxy-ca-native":            curlFlag("--proxy-ca-native", curlOptionTelnetProof),
	"--proxy-digest":                  curlFlag("--proxy-digest", curlOptionTelnetProof),
	"--no-proxy-digest":               curlFlag("--proxy-digest", curlOptionTelnetProof),
	"--proxy-http2":                   curlFlag("--proxy-http2", curlOptionTelnetProof),
	"--no-proxy-http2":                curlFlag("--proxy-http2", curlOptionTelnetProof),
	"--proxy-insecure":                curlFlag("--proxy-insecure", curlOptionTelnetProof),
	"--no-proxy-insecure":             curlFlag("--proxy-insecure", curlOptionTelnetProof),
	"--proxy-negotiate":               curlFlag("--proxy-negotiate", curlOptionTelnetProof),
	"--no-proxy-negotiate":            curlFlag("--proxy-negotiate", curlOptionTelnetProof),
	"--proxy-ntlm":                    curlFlag("--proxy-ntlm", curlOptionTelnetProof),
	"--no-proxy-ntlm":                 curlFlag("--proxy-ntlm", curlOptionTelnetProof),
	"--proxy-ssl-allow-beast":         curlFlag("--proxy-ssl-allow-beast", curlOptionTelnetProof),
	"--no-proxy-ssl-allow-beast":      curlFlag("--proxy-ssl-allow-beast", curlOptionTelnetProof),
	"--proxy-ssl-auto-client-cert":    curlFlag("--proxy-ssl-auto-client-cert", curlOptionTelnetProof),
	"--no-proxy-ssl-auto-client-cert": curlFlag("--proxy-ssl-auto-client-cert", curlOptionTelnetProof),
	"--proxy-tlsv1":                   curlFlag("--proxy-tlsv1", curlOptionTelnetProof),
	"--raw":                           curlFlag("--raw", curlOptionTelnetProof),
	"--no-raw":                        curlFlag("--raw", curlOptionTelnetProof),
	"--remote-header-name":            curlFlag("--remote-header-name", curlOptionTelnetProof),
	"--no-remote-header-name":         curlFlag("--remote-header-name", curlOptionTelnetProof),
	"--remove-on-error":               curlFlag("--remove-on-error", curlOptionTelnetProof),
	"--no-remove-on-error":            curlFlag("--remove-on-error", curlOptionTelnetProof),
	"--retry-all-errors":              curlFlag("--retry-all-errors", curlOptionTelnetProof),
	"--no-retry-all-errors":           curlFlag("--retry-all-errors", curlOptionTelnetProof),
	"--retry-connrefused":             curlFlag("--retry-connrefused", curlOptionTelnetProof),
	"--no-retry-connrefused":          curlFlag("--retry-connrefused", curlOptionTelnetProof),
	"--sasl-ir":                       curlFlag("--sasl-ir", curlOptionTelnetProof),
	"--no-sasl-ir":                    curlFlag("--sasl-ir", curlOptionTelnetProof),
	"--sessionid":                     curlFlag("--sessionid", curlOptionTelnetProof),
	"--no-sessionid":                  curlFlag("--sessionid", curlOptionTelnetProof),
	"--ssl-allow-beast":               curlFlag("--ssl-allow-beast", curlOptionTelnetProof),
	"--no-ssl-allow-beast":            curlFlag("--ssl-allow-beast", curlOptionTelnetProof),
	"--ssl-auto-client-cert":          curlFlag("--ssl-auto-client-cert", curlOptionTelnetProof),
	"--no-ssl-auto-client-cert":       curlFlag("--ssl-auto-client-cert", curlOptionTelnetProof),
	"--ssl-no-revoke":                 curlFlag("--ssl-no-revoke", curlOptionTelnetProof),
	"--no-ssl-no-revoke":              curlFlag("--ssl-no-revoke", curlOptionTelnetProof),
	"--ssl-revoke-best-effort":        curlFlag("--ssl-revoke-best-effort", curlOptionTelnetProof),
	"--no-ssl-revoke-best-effort":     curlFlag("--ssl-revoke-best-effort", curlOptionTelnetProof),
	"--styled-output":                 curlFlag("--styled-output", curlOptionTelnetProof),
	"--no-styled-output":              curlFlag("--styled-output", curlOptionTelnetProof),
	"--suppress-connect-headers":      curlFlag("--suppress-connect-headers", curlOptionTelnetProof),
	"--no-suppress-connect-headers":   curlFlag("--suppress-connect-headers", curlOptionTelnetProof),
	"--tcp-fastopen":                  curlFlag("--tcp-fastopen", curlOptionTelnetProof),
	"--no-tcp-fastopen":               curlFlag("--tcp-fastopen", curlOptionTelnetProof),
	"--tcp-nodelay":                   curlFlag("--tcp-nodelay", curlOptionTelnetProof),
	"--no-tcp-nodelay":                curlFlag("--tcp-nodelay", curlOptionTelnetProof),
	"--test-event":                    curlFlag("--test-event", curlOptionTelnetProof),
	"--no-test-event":                 curlFlag("--test-event", curlOptionTelnetProof),
	"--tftp-no-options":               curlFlag("--tftp-no-options", curlOptionTelnetProof),
	"--no-tftp-no-options":            curlFlag("--tftp-no-options", curlOptionTelnetProof),
	"--tlsv1.0":                       curlFlag("--tlsv1.0", curlOptionTelnetProof),
	"--tlsv1.1":                       curlFlag("--tlsv1.1", curlOptionTelnetProof),
	"--tlsv1.2":                       curlFlag("--tlsv1.2", curlOptionTelnetProof),
	"--tlsv1.3":                       curlFlag("--tlsv1.3", curlOptionTelnetProof),
	"--tr-encoding":                   curlFlag("--tr-encoding", curlOptionTelnetProof),
	"--no-tr-encoding":                curlFlag("--tr-encoding", curlOptionTelnetProof),
	"--trace-ids":                     curlFlag("--trace-ids", curlOptionTelnetProof),
	"--no-trace-ids":                  curlFlag("--trace-ids", curlOptionTelnetProof),
	"--trace-time":                    curlFlag("--trace-time", curlOptionTelnetProof),
	"--no-trace-time":                 curlFlag("--trace-time", curlOptionTelnetProof),
	"--wdebug":                        curlFlag("--wdebug", curlOptionTelnetProof),
	"--no-wdebug":                     curlFlag("--wdebug", curlOptionTelnetProof),
	"--xattr":                         curlFlag("--xattr", curlOptionTelnetProof),
	"--no-xattr":                      curlFlag("--xattr", curlOptionTelnetProof),

	"--append":        curlFlag("--append", curlOptionNeutral),
	"--no-append":     curlFlag("--append", curlOptionNeutral),
	"--buffer":        curlFlag("--no-buffer", curlOptionNeutral),
	"--compressed":    curlFlag("--compressed", curlOptionNeutral),
	"--no-compressed": curlFlag("--compressed", curlOptionNeutral),
	"--disable":       curlFlag("--disable", curlOptionNeutral),
	"--disable-eprt":  curlFlag("--disable-eprt", curlOptionNeutral),
	"--no-disable-eprt": curlFlag(
		"--disable-eprt",
		curlOptionNeutral,
	),
	"--eprt":         curlFlag("--disable-eprt", curlOptionNeutral),
	"--no-eprt":      curlFlag("--disable-eprt", curlOptionNeutral),
	"--disable-epsv": curlFlag("--disable-epsv", curlOptionNeutral),
	"--no-disable-epsv": curlFlag(
		"--disable-epsv",
		curlOptionNeutral,
	),
	"--epsv":           curlFlag("--disable-epsv", curlOptionNeutral),
	"--no-epsv":        curlFlag("--disable-epsv", curlOptionNeutral),
	"--fail":           curlFlag("--fail", curlOptionNeutral),
	"--no-fail":        curlFlag("--fail", curlOptionNeutral),
	"--fail-with-body": curlFlag("--fail-with-body", curlOptionNeutral),
	"--no-fail-with-body": curlFlag(
		"--fail-with-body",
		curlOptionNeutral,
	),
	"--get":         curlFlag("--get", curlOptionNeutral),
	"--no-get":      curlFlag("--get", curlOptionNeutral),
	"--globoff":     curlFlag("--globoff", curlOptionNeutral),
	"--no-globoff":  curlFlag("--globoff", curlOptionNeutral),
	"--head":        curlFlag("--head", curlOptionHead),
	"--http1.0":     curlFlag("--http1.0", curlOptionNeutral),
	"--help":        curlOptionalValue("--help", curlOptionPreview),
	"--include":     curlFlag("--include", curlOptionNeutral),
	"--no-include":  curlFlag("--include", curlOptionNeutral),
	"--insecure":    curlFlag("--insecure", curlOptionNeutral),
	"--no-insecure": curlFlag("--insecure", curlOptionNeutral),
	"--ipv4":        curlFlag("--ipv4", curlOptionNeutral),
	"--ipv6":        curlFlag("--ipv6", curlOptionNeutral),
	"--crlf":        curlFlag("--crlf", curlOptionNeutral),
	"--no-crlf":     curlFlag("--crlf", curlOptionNeutral),
	"--ftp-create-dirs": curlFlag(
		"--ftp-create-dirs",
		curlOptionNeutral,
	),
	"--no-ftp-create-dirs": curlFlag(
		"--ftp-create-dirs",
		curlOptionNeutral,
	),
	"--ftp-pasv":         curlFlag("--ftp-pasv", curlOptionNeutral),
	"--no-ftp-pasv":      curlFlag("--ftp-pasv", curlOptionNeutral),
	"--ftp-pret":         curlFlag("--ftp-pret", curlOptionNeutral),
	"--no-ftp-pret":      curlFlag("--ftp-pret", curlOptionNeutral),
	"--ftp-skip-pasv-ip": curlFlag("--ftp-skip-pasv-ip", curlOptionNeutral),
	"--no-ftp-skip-pasv-ip": curlFlag(
		"--ftp-skip-pasv-ip",
		curlOptionNeutral,
	),
	"--ftp-ssl-ccc":    curlFlag("--ftp-ssl-ccc", curlOptionNeutral),
	"--no-ftp-ssl-ccc": curlFlag("--ftp-ssl-ccc", curlOptionNeutral),
	"--ignore-content-length": curlFlag(
		"--ignore-content-length",
		curlOptionNeutral,
	),
	"--no-ignore-content-length": curlFlag(
		"--ignore-content-length",
		curlOptionNeutral,
	),
	"--ssl":                curlFlag("--ssl", curlOptionNeutral),
	"--no-ssl":             curlFlag("--ssl", curlOptionNeutral),
	"--ftp-ssl":            curlFlag("--ssl", curlOptionNeutral),
	"--no-ftp-ssl":         curlFlag("--ssl", curlOptionNeutral),
	"--ssl-reqd":           curlFlag("--ssl-reqd", curlOptionNeutral),
	"--no-ssl-reqd":        curlFlag("--ssl-reqd", curlOptionNeutral),
	"--ftp-ssl-reqd":       curlFlag("--ssl-reqd", curlOptionNeutral),
	"--no-ftp-ssl-reqd":    curlFlag("--ssl-reqd", curlOptionNeutral),
	"--ftp-ssl-control":    curlFlag("--ftp-ssl-control", curlOptionNeutral),
	"--no-ftp-ssl-control": curlFlag("--ftp-ssl-control", curlOptionNeutral),
	"--junk-session-cookies": curlFlag(
		"--junk-session-cookies",
		curlOptionNeutral,
	),
	"--no-junk-session-cookies": curlFlag(
		"--junk-session-cookies",
		curlOptionNeutral,
	),
	"--list-only":          curlFlag("--list-only", curlOptionNeutral),
	"--no-list-only":       curlFlag("--list-only", curlOptionNeutral),
	"--location":           curlFlag("--location", curlOptionNeutral),
	"--no-location":        curlFlag("--location", curlOptionNeutral),
	"--manual":             curlFlag("--manual", curlOptionPreview),
	"--no-buffer":          curlFlag("--no-buffer", curlOptionNeutral),
	"--no-head":            curlFlag("--no-head", curlOptionNoHead),
	"--netrc":              curlFlag("--netrc", curlOptionNeutral),
	"--no-netrc":           curlFlag("--netrc", curlOptionNeutral),
	"--netrc-optional":     curlFlag("--netrc-optional", curlOptionNeutral),
	"--no-netrc-optional":  curlFlag("--netrc-optional", curlOptionNeutral),
	"--no-progress-meter":  curlFlag("--no-progress-meter", curlOptionNeutral),
	"--npn":                curlFlag("--npn", curlOptionNeutral),
	"--no-npn":             curlFlag("--npn", curlOptionNeutral),
	"--no-remote-name":     curlFlag("--no-remote-name", curlOptionNoRemoteName),
	"--no-remote-name-all": curlFlag("--no-remote-name-all", curlOptionNoRemoteNameAll),
	"--parallel":           curlFlag("--parallel", curlOptionNeutral),
	"--no-parallel":        curlFlag("--parallel", curlOptionNeutral),
	"--path-as-is":         curlFlag("--path-as-is", curlOptionNeutral),
	"--no-path-as-is":      curlFlag("--path-as-is", curlOptionNeutral),
	"--progress-bar":       curlFlag("--progress-bar", curlOptionNeutral),
	"--no-progress-bar":    curlFlag("--progress-bar", curlOptionNeutral),
	"--progress-meter":     curlFlag("--no-progress-meter", curlOptionNeutral),
	"--proxytunnel":        curlFlag("--proxytunnel", curlOptionNeutral),
	"--no-proxytunnel":     curlFlag("--proxytunnel", curlOptionNeutral),
	"--remote-name":        curlFlag("--remote-name", curlOptionRemoteName),
	"--remote-name-all":    curlFlag("--remote-name-all", curlOptionRemoteNameAll),
	"--remote-time":        curlFlag("--remote-time", curlOptionNeutral),
	"--no-remote-time":     curlFlag("--remote-time", curlOptionNeutral),
	"--show-error":         curlFlag("--show-error", curlOptionNeutral),
	"--no-show-error":      curlFlag("--show-error", curlOptionNeutral),
	"--silent":             curlFlag("--silent", curlOptionNeutral),
	"--no-silent":          curlFlag("--silent", curlOptionNeutral),
	"--socks5-basic":       curlFlag("--socks5-basic", curlOptionNeutral),
	"--no-socks5-basic":    curlFlag("--socks5-basic", curlOptionNeutral),
	"--socks5-gssapi":      curlFlag("--socks5-gssapi", curlOptionNeutral),
	"--no-socks5-gssapi":   curlFlag("--socks5-gssapi", curlOptionNeutral),
	"--socks5-gssapi-nec": curlFlag(
		"--socks5-gssapi-nec",
		curlOptionNeutral,
	),
	"--no-socks5-gssapi-nec": curlFlag(
		"--socks5-gssapi-nec",
		curlOptionNeutral,
	),
	"--sslv2":        curlFlag("--sslv2", curlOptionNeutral),
	"--sslv3":        curlFlag("--sslv3", curlOptionNeutral),
	"--tlsv1":        curlFlag("--tlsv1", curlOptionNeutral),
	"--use-ascii":    curlFlag("--use-ascii", curlOptionNeutral),
	"--no-use-ascii": curlFlag("--use-ascii", curlOptionNeutral),
	"--verbose":      curlFlag("--verbose", curlOptionNeutral),
	"--no-verbose":   curlFlag("--verbose", curlOptionNeutral),
	"--version":      curlFlag("--version", curlOptionPreview),

	"--abstract-unix-socket": curlValue(
		"--abstract-unix-socket",
		curlOptionTelnetProof,
	),
	"--alt-svc":                   curlValue("--alt-svc", curlOptionTelnetProof),
	"--aws-sigv4":                 curlValue("--aws-sigv4", curlOptionTelnetProof),
	"--capath":                    curlValue("--capath", curlOptionTelnetProof),
	"--cert-type":                 curlValue("--cert-type", curlOptionTelnetProof),
	"--ciphers":                   curlValue("--ciphers", curlOptionTelnetProof),
	"--create-file-mode":          curlValue("--create-file-mode", curlOptionTelnetProof),
	"--crlfile":                   curlValue("--crlfile", curlOptionTelnetProof),
	"--curves":                    curlValue("--curves", curlOptionTelnetProof),
	"--delegation":                curlValue("--delegation", curlOptionTelnetProof),
	"--dns-interface":             curlValue("--dns-interface", curlOptionTelnetProof),
	"--dns-ipv4-addr":             curlValue("--dns-ipv4-addr", curlOptionTelnetProof),
	"--dns-ipv6-addr":             curlValue("--dns-ipv6-addr", curlOptionTelnetProof),
	"--engine":                    curlValue("--engine", curlOptionTelnetProof),
	"--etag-compare":              curlValue("--etag-compare", curlOptionTelnetProof),
	"--etag-save":                 curlValue("--etag-save", curlOptionTelnetProof),
	"--expect100-timeout":         curlValue("--expect100-timeout", curlOptionTelnetProof),
	"--happy-eyeballs-timeout-ms": curlValue("--happy-eyeballs-timeout-ms", curlOptionTelnetProof),
	"--haproxy-clientip":          curlValue("--haproxy-clientip", curlOptionTelnetProof),
	"--hostpubmd5":                curlValue("--hostpubmd5", curlOptionTelnetProof),
	"--hostpubsha256":             curlValue("--hostpubsha256", curlOptionTelnetProof),
	"--hsts":                      curlValue("--hsts", curlOptionTelnetProof),
	"--ipfs-gateway":              curlValue("--ipfs-gateway", curlOptionTelnetProof),
	"--keepalive-time":            curlValue("--keepalive-time", curlOptionTelnetProof),
	"--key-type":                  curlValue("--key-type", curlOptionTelnetProof),
	"--krb":                       curlValue("--krb", curlOptionTelnetProof),
	"--krb4":                      curlValue("--krb4", curlOptionTelnetProof),
	"--libcurl":                   curlValue("--libcurl", curlOptionTelnetProof),
	"--limit-rate":                curlValue("--limit-rate", curlOptionTelnetProof),
	"--local-port":                curlValue("--local-port", curlOptionTelnetProof),
	"--login-options":             curlValue("--login-options", curlOptionTelnetProof),
	"--max-filesize":              curlValue("--max-filesize", curlOptionTelnetProof),
	"--max-redirs":                curlValue("--max-redirs", curlOptionTelnetProof),
	"--parallel-max":              curlValue("--parallel-max", curlOptionTelnetProof),
	"--pass":                      curlValue("--pass", curlOptionTelnetProof),
	"--pinnedpubkey":              curlValue("--pinnedpubkey", curlOptionTelnetProof),
	"--proto":                     curlValue("--proto", curlOptionTelnetProof),
	"--proto-redir":               curlValue("--proto-redir", curlOptionTelnetProof),
	"--proxy-cacert":              curlValue("--proxy-cacert", curlOptionTelnetProof),
	"--proxy-capath":              curlValue("--proxy-capath", curlOptionTelnetProof),
	"--proxy-cert":                curlValue("--proxy-cert", curlOptionTelnetProof),
	"--proxy-cert-type":           curlValue("--proxy-cert-type", curlOptionTelnetProof),
	"--proxy-ciphers":             curlValue("--proxy-ciphers", curlOptionTelnetProof),
	"--proxy-crlfile":             curlValue("--proxy-crlfile", curlOptionTelnetProof),
	"--proxy-key":                 curlValue("--proxy-key", curlOptionTelnetProof),
	"--proxy-key-type":            curlValue("--proxy-key-type", curlOptionTelnetProof),
	"--proxy-pass":                curlValue("--proxy-pass", curlOptionTelnetProof),
	"--proxy-pinnedpubkey":        curlValue("--proxy-pinnedpubkey", curlOptionTelnetProof),
	"--proxy-service-name":        curlValue("--proxy-service-name", curlOptionTelnetProof),
	"--proxy-tls13-ciphers":       curlValue("--proxy-tls13-ciphers", curlOptionTelnetProof),
	"--proxy-tlsauthtype":         curlValue("--proxy-tlsauthtype", curlOptionTelnetProof),
	"--proxy-tlspassword":         curlValue("--proxy-tlspassword", curlOptionTelnetProof),
	"--proxy-tlsuser":             curlValue("--proxy-tlsuser", curlOptionTelnetProof),
	"--pubkey":                    curlValue("--pubkey", curlOptionTelnetProof),
	"--rate":                      curlValue("--rate", curlOptionTelnetProof),
	"--sasl-authzid":              curlValue("--sasl-authzid", curlOptionTelnetProof),
	"--service-name":              curlValue("--service-name", curlOptionTelnetProof),
	"--tftp-blksize":              curlValue("--tftp-blksize", curlOptionTelnetProof),
	"--tls-max":                   curlValue("--tls-max", curlOptionTelnetProof),
	"--tls13-ciphers":             curlValue("--tls13-ciphers", curlOptionTelnetProof),
	"--tlsauthtype":               curlValue("--tlsauthtype", curlOptionTelnetProof),
	"--tlspassword":               curlValue("--tlspassword", curlOptionTelnetProof),
	"--tlsuser":                   curlValue("--tlsuser", curlOptionTelnetProof),
	"--trace":                     curlValue("--trace", curlOptionTelnetProof),
	"--trace-ascii":               curlValue("--trace-ascii", curlOptionTelnetProof),
	"--trace-config":              curlValue("--trace-config", curlOptionTelnetProof),
	"--variable":                  curlValue("--variable", curlOptionTelnetProof),

	"--cacert":          curlValue("--cacert", curlOptionNeutral),
	"--cert":            curlValue("--cert", curlOptionNeutral),
	"--config":          curlValue("--config", curlOptionConfig),
	"--connect-timeout": curlValue("--connect-timeout", curlOptionNeutral),
	"--connect-to":      curlValue("--connect-to", curlOptionNetworkOverride),
	"--continue-at":     curlValue("--continue-at", curlOptionNeutral),
	"--cookie":          curlValue("--cookie", curlOptionNeutral),
	"--cookie-jar":      curlValue("--cookie-jar", curlOptionNeutral),
	"--data":            curlValue("--data", curlOptionNeutral),
	"--data-ascii":      curlValue("--data-ascii", curlOptionNeutral),
	"--data-binary":     curlValue("--data-binary", curlOptionNeutral),
	"--data-raw":        curlValue("--data-raw", curlOptionNeutral),
	"--data-urlencode":  curlValue("--data-urlencode", curlOptionNeutral),
	"--dns-servers":     curlValue("--dns-servers", curlOptionNetworkOverride),
	"--doh-url":         curlValue("--doh-url", curlOptionNetworkOverride),
	"--dump-header":     curlValue("--dump-header", curlOptionNeutral),
	"--egd-file":        curlValue("--egd-file", curlOptionNeutral),
	"--form":            curlValue("--form", curlOptionNeutral),
	"--form-string":     curlValue("--form-string", curlOptionNeutral),
	"--ftp-account":     curlValue("--ftp-account", curlOptionNeutral),
	"--ftp-alternative-to-user": curlValue(
		"--ftp-alternative-to-user",
		curlOptionNeutral,
	),
	"--ftp-port":   curlValue("--ftp-port", curlOptionNeutral),
	"--ftp-method": curlValue("--ftp-method", curlOptionNeutral),
	"--ftp-ssl-ccc-mode": curlValue(
		"--ftp-ssl-ccc-mode",
		curlOptionNeutral,
	),
	"--header":    curlValue("--header", curlOptionNeutral),
	"--interface": curlValue("--interface", curlOptionNetworkOverride),
	"--json":      curlValue("--json", curlOptionNeutral),
	"--key":       curlValue("--key", curlOptionNeutral),
	"--mail-auth": curlValue("--mail-auth", curlOptionNeutral),
	"--mail-from": curlValue("--mail-from", curlOptionNeutral),
	"--mail-rcpt": curlValue("--mail-rcpt", curlOptionNeutral),
	"--mail-rcpt-allowfails": curlFlag(
		"--mail-rcpt-allowfails",
		curlOptionNeutral,
	),
	"--no-mail-rcpt-allowfails": curlFlag(
		"--mail-rcpt-allowfails",
		curlOptionNeutral,
	),
	"--max-time":        curlValue("--max-time", curlOptionNeutral),
	"--netrc-file":      curlValue("--netrc-file", curlOptionNeutral),
	"--noproxy":         curlValue("--noproxy", curlOptionNetworkOverride),
	"--oauth2-bearer":   curlValue("--oauth2-bearer", curlOptionNeutral),
	"--output":          curlValue("--output", curlOptionOutput),
	"--output-dir":      curlValue("--output-dir", curlOptionNeutral),
	"--preproxy":        curlValue("--preproxy", curlOptionNetworkOverride),
	"--proto-default":   curlValue("--proto-default", curlOptionNeutral),
	"--proxy":           curlValue("--proxy", curlOptionNetworkOverride),
	"--proxy-header":    curlValue("--proxy-header", curlOptionNeutral),
	"--proxy-user":      curlValue("--proxy-user", curlOptionNeutral),
	"--proxy1.0":        curlValue("--proxy1.0", curlOptionNetworkOverride),
	"--quote":           curlValue("--quote", curlOptionNeutral),
	"--random-file":     curlValue("--random-file", curlOptionNeutral),
	"--range":           curlValue("--range", curlOptionNeutral),
	"--referer":         curlValue("--referer", curlOptionNeutral),
	"--request":         curlValue("--request", curlOptionMethod),
	"--request-target":  curlValue("--request-target", curlOptionNeutral),
	"--resolve":         curlValue("--resolve", curlOptionNetworkOverride),
	"--retry":           curlValue("--retry", curlOptionNeutral),
	"--retry-delay":     curlValue("--retry-delay", curlOptionNeutral),
	"--retry-max-time":  curlValue("--retry-max-time", curlOptionNeutral),
	"--socks4":          curlValue("--socks4", curlOptionNetworkOverride),
	"--socks4a":         curlValue("--socks4a", curlOptionNetworkOverride),
	"--socks5":          curlValue("--socks5", curlOptionNetworkOverride),
	"--socks5-hostname": curlValue("--socks5-hostname", curlOptionNetworkOverride),
	"--socks5-gssapi-service": curlValue(
		"--socks5-gssapi-service",
		curlOptionNeutral,
	),
	"--speed-limit":   curlValue("--speed-limit", curlOptionNeutral),
	"--speed-time":    curlValue("--speed-time", curlOptionNeutral),
	"--stderr":        curlValue("--stderr", curlOptionNeutral),
	"--telnet-option": curlValue("--telnet-option", curlOptionNeutral),
	"--time-cond":     curlValue("--time-cond", curlOptionNeutral),
	"--unix-socket":   curlValue("--unix-socket", curlOptionNetworkOverride),
	"--upload-file":   curlValue("--upload-file", curlOptionUpload),
	"--url":           curlValue("--url", curlOptionTarget),
	"--url-query":     curlValue("--url-query", curlOptionNeutral),
	"--user":          curlValue("--user", curlOptionNeutral),
	"--user-agent":    curlValue("--user-agent", curlOptionNeutral),
	"--write-out":     curlValue("--write-out", curlOptionNeutral),
}

var curlShortOptionSpecs = map[byte]curlOptionSpec{
	'#': curlFlag("--progress-bar", curlOptionNeutral),
	'0': curlFlag("--http1.0", curlOptionNeutral),
	'1': curlFlag("--tlsv1", curlOptionNeutral),
	'2': curlFlag("--sslv2", curlOptionNeutral),
	'3': curlFlag("--sslv3", curlOptionNeutral),
	'4': curlFlag("--ipv4", curlOptionNeutral),
	'6': curlFlag("--ipv6", curlOptionNeutral),
	'a': curlFlag("--append", curlOptionNeutral),
	'B': curlFlag("--use-ascii", curlOptionNeutral),
	'f': curlFlag("--fail", curlOptionNeutral),
	'G': curlFlag("--get", curlOptionNeutral),
	'g': curlFlag("--globoff", curlOptionNeutral),
	'I': curlFlag("--head", curlOptionHead),
	'i': curlFlag("--include", curlOptionNeutral),
	'J': curlFlag("--remote-header-name", curlOptionTelnetProof),
	'j': curlFlag("--junk-session-cookies", curlOptionNeutral),
	'k': curlFlag("--insecure", curlOptionNeutral),
	'L': curlFlag("--location", curlOptionNeutral),
	'l': curlFlag("--list-only", curlOptionNeutral),
	'M': curlFlag("--manual", curlOptionPreview),
	'N': curlFlag("--no-buffer", curlOptionNeutral),
	'n': curlFlag("--netrc", curlOptionNeutral),
	'O': curlFlag("--remote-name", curlOptionRemoteName),
	'p': curlFlag("--proxytunnel", curlOptionNeutral),
	'q': curlFlag("--disable", curlOptionNeutral),
	'R': curlFlag("--remote-time", curlOptionNeutral),
	'S': curlFlag("--show-error", curlOptionNeutral),
	's': curlFlag("--silent", curlOptionNeutral),
	'V': curlFlag("--version", curlOptionPreview),
	'v': curlFlag("--verbose", curlOptionNeutral),
	'Z': curlFlag("--parallel", curlOptionNeutral),

	'A': curlValue("--user-agent", curlOptionNeutral),
	'b': curlValue("--cookie", curlOptionNeutral),
	'c': curlValue("--cookie-jar", curlOptionNeutral),
	'C': curlValue("--continue-at", curlOptionNeutral),
	'd': curlValue("--data", curlOptionNeutral),
	'D': curlValue("--dump-header", curlOptionNeutral),
	'e': curlValue("--referer", curlOptionNeutral),
	'E': curlValue("--cert", curlOptionNeutral),
	'F': curlValue("--form", curlOptionNeutral),
	'H': curlValue("--header", curlOptionNeutral),
	'h': curlOptionalValue("--help", curlOptionPreview),
	'K': curlValue("--config", curlOptionConfig),
	'm': curlValue("--max-time", curlOptionNeutral),
	'o': curlValue("--output", curlOptionOutput),
	'P': curlValue("--ftp-port", curlOptionNeutral),
	'Q': curlValue("--quote", curlOptionNeutral),
	'r': curlValue("--range", curlOptionNeutral),
	't': curlValue("--telnet-option", curlOptionNeutral),
	'T': curlValue("--upload-file", curlOptionUpload),
	'u': curlValue("--user", curlOptionNeutral),
	'U': curlValue("--proxy-user", curlOptionNeutral),
	'w': curlValue("--write-out", curlOptionNeutral),
	'x': curlValue("--proxy", curlOptionNetworkOverride),
	'X': curlValue("--request", curlOptionMethod),
	'y': curlValue("--speed-time", curlOptionNeutral),
	'Y': curlValue("--speed-limit", curlOptionNeutral),
	'z': curlValue("--time-cond", curlOptionNeutral),
}

// curlOptionToken retains both the source spelling and canonical ownership.
// ValuePresent distinguishes a present empty value from a missing operand.
type curlOptionToken struct {
	ArgvIndex      int
	ValueArgvIndex int
	ShortOffset    int
	Group          int
	Raw            string
	Name           string
	Canonical      string
	Known          bool
	TakesValue     bool
	ValuePresent   bool
	ValueJoined    bool
	Value          string
	Role           curlOptionRole
}

type curlArgvUnresolved struct {
	ArgvIndex int
	Raw       string
	Reason    string
}

type curlOutputKind uint8

const (
	curlOutputUnknown curlOutputKind = iota
	curlOutputStdout
	curlOutputFile
	curlOutputRemoteName
)

type curlTransferTarget struct {
	ArgvIndex          int
	Group              int
	Value              string
	ViaURLOption       bool
	Output             curlOutputKind
	OutputValue        string
	Method             string
	Head               bool
	Preview            bool
	ResponseBodyStdout bool
	UploadSet          bool
	UploadValue        string
}

type curlResponseStdoutState uint8

const (
	curlResponseStdoutUnknown curlResponseStdoutState = iota
	curlResponseStdoutNone
	curlResponseStdoutPresent
)

// curlArgvParse is a lossless-enough curl command-line projection for later
// classifiers. Complete means output/method/target ownership is known. A
// syntactically complete invocation with no targets remains Complete and has a
// known no-stdout result. ConfigOpaque and Unresolved explain incomplete cases.
type curlArgvParse struct {
	Complete           bool
	ConfigOpaque       bool
	Preview            bool
	EmptyTransferGroup bool
	Options            []curlOptionToken
	Targets            []curlTransferTarget
	Unresolved         []curlArgvUnresolved
}

func (parsed curlArgvParse) responseStdoutState() curlResponseStdoutState {
	if !parsed.Complete || parsed.ConfigOpaque {
		return curlResponseStdoutUnknown
	}
	for _, target := range parsed.Targets {
		if target.ResponseBodyStdout {
			return curlResponseStdoutPresent
		}
	}
	return curlResponseStdoutNone
}

func (parsed curlArgvParse) provesResponseStdout() bool {
	if parsed.responseStdoutState() != curlResponseStdoutPresent ||
		!parsed.hasValidOptionValues() {
		return false
	}
	for _, target := range parsed.Targets {
		if !target.ResponseBodyStdout {
			continue
		}
		if _, ok := webTargetFact(0, target.Value, NetworkDownload); ok {
			return true
		}
	}
	return false
}

func (parsed curlArgvParse) hasValidOptionValues() bool {
	for _, option := range parsed.Options {
		if !option.TakesValue || !option.ValuePresent {
			continue
		}
		if option.Value == "" && !curlOptionAllowsEmptyValue(option.Canonical) {
			return false
		}
		switch option.Canonical {
		case "--connect-timeout", "--expect100-timeout", "--max-time":
			if !validCurlDecimal(option.Value) {
				return false
			}
		case "--retry-delay", "--retry-max-time":
			parsed, valid := curlUnsignedLong(option.Value)
			if !valid || parsed > curlPortableLongMaximum()/1000 {
				return false
			}
		case "--retry", "--speed-limit", "--speed-time":
			if !validCurlUnsignedInteger(option.Value) {
				return false
			}
		}
	}
	return true
}

func curlOptionAllowsEmptyValue(option string) bool {
	switch option {
	case "--cert", "--connect-to", "--cookie", "--data",
		"--data-ascii", "--data-binary", "--data-raw",
		"--data-urlencode", "--doh-url", "--header", "--json",
		"--ftp-method", "--ftp-ssl-ccc-mode", "--mail-rcpt", "--noproxy",
		"--login-options", "--proxy", "--proxy-cert", "--proxy-header",
		"--proxy-key", "--proxy-pass", "--proxy-user", "--upload-file",
		"--quote", "--random-file", "--egd-file", "--referer",
		"--telnet-option", "--time-cond", "--user",
		"--trace-config", "--url-query", "--user-agent", "--write-out":
		return true
	default:
		return false
	}
}

func validCurlDecimal(value string) bool {
	_, valid := curlSecondsMilliseconds(value)
	return valid
}

func validCurlUnsignedInteger(value string) bool {
	_, valid := curlUnsignedLong(value)
	return valid
}

func curlUnsignedLong(value string) (uint64, bool) {
	value = strings.TrimLeftFunc(value, curlCWhitespace)
	if value == "" {
		return 0, false
	}
	negative := false
	switch value[0] {
	case '+':
		value = value[1:]
	case '-':
		negative = true
		value = value[1:]
	}
	if value == "" {
		return 0, false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed > curlPortableLongMaximum() || negative && parsed != 0 {
		return 0, false
	}
	return parsed, true
}

func curlSecondsMilliseconds(value string) (int64, bool) {
	value = strings.TrimLeftFunc(value, curlCWhitespace)
	if value == "" {
		return 0, false
	}
	normalized, significandNonzero, valid := curlCLocaleFloatSyntax(value)
	if !valid {
		return 0, false
	}
	seconds, err := strconv.ParseFloat(normalized, 64)
	// Curl rejects strtod ERANGE before converting seconds to milliseconds.
	// CRTs can detect tininess before or after rounding, so a subnormal subject
	// that rounds up to the minimum normal float is not portable. Exclude that
	// boundary too; the parsed float alone cannot distinguish it from an exact
	// minimum-normal subject.
	portableRangeError := significandNonzero && math.Abs(seconds) <= 0x1p-1022
	if err != nil || math.IsInf(seconds, 0) || math.IsNaN(seconds) ||
		portableRangeError ||
		seconds < 0 || seconds > float64(curlPortableLongMaximum())/1000 {
		return 0, false
	}
	return int64(seconds * 1000), true
}

// curlCLocaleFloatSyntax accepts the finite numeric subject sequences that C
// strtod recognizes in the C locale, excluding implementation-specific
// infinity/NaN and locale spellings. strconv.ParseFloat then performs the
// range conversion; this lexical gate notably rejects Go-only underscores.
// The second result distinguishes exact zero significands from nonzero values
// that ParseFloat rounds to zero, and from nonzero subnormals whose ERANGE
// treatment varies between the C libraries used by supported curl builds.
func curlCLocaleFloatSyntax(value string) (string, bool, bool) {
	index := 0
	if index < len(value) && (value[index] == '+' || value[index] == '-') {
		index++
	}
	if index >= len(value) {
		return "", false, false
	}
	if index+2 <= len(value) && value[index] == '0' &&
		(value[index+1] == 'x' || value[index+1] == 'X') {
		index += 2
		digits := 0
		significandNonzero := false
		for index < len(value) && curlHexDigit(value[index]) {
			significandNonzero = significandNonzero || value[index] != '0'
			index++
			digits++
		}
		if index < len(value) && value[index] == '.' {
			index++
			for index < len(value) && curlHexDigit(value[index]) {
				significandNonzero = significandNonzero || value[index] != '0'
				index++
				digits++
			}
		}
		if digits == 0 {
			return "", false, false
		}
		if index == len(value) {
			// C strtod accepts a hexadecimal significand without an explicit
			// binary exponent, while Go's ParseFloat requires one.
			return value + "p0", significandNonzero, true
		}
		if value[index] != 'p' && value[index] != 'P' {
			return "", false, false
		}
		index++
		if !curlDecimalExponentConsumesRemainder(value, index) {
			return "", false, false
		}
		return value, significandNonzero, true
	}
	digits := 0
	significandNonzero := false
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		significandNonzero = significandNonzero || value[index] != '0'
		index++
		digits++
	}
	if index < len(value) && value[index] == '.' {
		index++
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			significandNonzero = significandNonzero || value[index] != '0'
			index++
			digits++
		}
	}
	if digits == 0 {
		return "", false, false
	}
	if index < len(value) && (value[index] == 'e' || value[index] == 'E') {
		index++
		if !curlDecimalExponentConsumesRemainder(value, index) {
			return "", false, false
		}
		return value, significandNonzero, true
	}
	return value, significandNonzero, index == len(value)
}

func curlDecimalExponentConsumesRemainder(value string, index int) bool {
	if index < len(value) && (value[index] == '+' || value[index] == '-') {
		index++
	}
	start := index
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	return index > start && index == len(value)
}

func curlHexDigit(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}

func curlCWhitespace(character rune) bool {
	switch character {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

func curlPortableLongMaximum() uint64 {
	// The parsed command does not identify whether curl is a 32- or 64-bit
	// executable. Stay within the signed-long range accepted by both builds.
	return uint64(math.MaxInt32)
}

type curlTargetOperand struct {
	argvIndex    int
	value        string
	viaURLOption bool
	remoteName   bool
}

type curlOutputSlot struct {
	kind  curlOutputKind
	value string
}

type curlUploadSlot struct {
	value string
}

type curlArgvGroup struct {
	index         int
	targets       []curlTargetOperand
	outputs       []curlOutputSlot
	uploads       []curlUploadSlot
	remoteNameAll bool
	method        string
	head          bool
}

func parseCurlArgv(argv []string) curlArgvParse {
	parsed := curlArgvParse{Complete: true}
	if len(argv) == 0 {
		parsed.markUnresolved(-1, "", "missing curl executable")
		return parsed
	}

	groups := []curlArgvGroup{{index: 0}}
	group := &groups[0]
	options := true
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if options && (argument == "--next" || argument == "-:") {
			parsed.Options = append(parsed.Options, curlOptionToken{
				ArgvIndex:      index,
				ValueArgvIndex: -1,
				ShortOffset:    -1,
				Group:          group.index,
				Raw:            argument,
				Name:           argument,
				Canonical:      "--next",
				Known:          true,
				Role:           curlOptionNeutral,
			})
			groups = append(groups, curlArgvGroup{index: len(groups)})
			group = &groups[len(groups)-1]
			options = true
			continue
		}
		if options && argument == "--" {
			parsed.Options = append(parsed.Options, curlOptionToken{
				ArgvIndex:      index,
				ValueArgvIndex: -1,
				ShortOffset:    -1,
				Group:          group.index,
				Raw:            argument,
				Name:           argument,
				Canonical:      "--",
				Known:          true,
				Role:           curlOptionNeutral,
			})
			options = false
			continue
		}
		if !options || argument == "-" || !strings.HasPrefix(argument, "-") {
			parsed.appendTarget(group, index, argument, false)
			continue
		}
		if strings.HasPrefix(argument, "--") {
			parsed.parseLongOption(argv, &index, group)
			continue
		}
		parsed.parseShortOptions(argv, &index, group)
	}

	for groupIndex := range groups {
		if len(groups) > 1 && len(groups[groupIndex].targets) == 0 {
			parsed.EmptyTransferGroup = true
			if groupIndex != len(groups)-1 {
				// Curl validates a leading or interior empty transfer before it
				// starts any group. A trailing empty group is diagnosed only after
				// earlier transfers have already emitted their output.
				parsed.Targets = nil
			}
			break
		}
		parsed.finalizeGroup(&groups[groupIndex])
	}
	return parsed
}

func (parsed *curlArgvParse) parseLongOption(
	argv []string,
	index *int,
	group *curlArgvGroup,
) {
	argument := argv[*index]
	name, joinedValue, joined := strings.Cut(argument, "=")
	spec, known := curlLongOptionSpecs[name]
	option := curlOptionToken{
		ArgvIndex:      *index,
		ValueArgvIndex: -1,
		ShortOffset:    -1,
		Group:          group.index,
		Raw:            argument,
		Name:           name,
		Canonical:      name,
		Known:          known,
	}
	if !known {
		parsed.Options = append(parsed.Options, option)
		parsed.markUnresolved(*index, argument, "unknown long option grammar")
		return
	}
	option.Canonical = spec.canonical
	option.Role = spec.role
	option.TakesValue = spec.arity != curlOptionNoValue
	if joined {
		parsed.Options = append(parsed.Options, option)
		parsed.markUnresolved(
			*index,
			argument,
			"joined value is not accepted for this curl option",
		)
		return
	}

	switch spec.arity {
	case curlOptionNoValue:
		if joined {
			parsed.markUnresolved(*index, argument, "value supplied to no-value option")
		}
	case curlOptionRequiredValue:
		switch {
		case joined:
			option.ValuePresent = true
			option.ValueJoined = true
			option.Value = joinedValue
		case *index+1 < len(argv):
			*index++
			option.ValuePresent = true
			option.ValueArgvIndex = *index
			option.Value = argv[*index]
		default:
			parsed.markUnresolved(option.ArgvIndex, argument, "missing required option value")
		}
	case curlOptionOptionalValue:
		if joined {
			option.ValuePresent = true
			option.ValueJoined = true
			option.Value = joinedValue
		} else if *index+1 < len(argv) && argv[*index+1] != "--" &&
			!strings.HasPrefix(argv[*index+1], "-") {
			*index++
			option.ValuePresent = true
			option.ValueArgvIndex = *index
			option.Value = argv[*index]
		}
	}
	parsed.Options = append(parsed.Options, option)
	parsed.applyOption(group, option)
}

func (parsed *curlArgvParse) parseShortOptions(
	argv []string,
	index *int,
	group *curlArgvGroup,
) {
	argument := argv[*index]
	for offset := 1; offset < len(argument); offset++ {
		short := argument[offset]
		spec, known := curlShortOptionSpecs[short]
		option := curlOptionToken{
			ArgvIndex:      *index,
			ValueArgvIndex: -1,
			ShortOffset:    offset,
			Group:          group.index,
			Raw:            argument,
			Name:           "-" + string(short),
			Canonical:      "-" + string(short),
			Known:          known,
		}
		if !known {
			parsed.Options = append(parsed.Options, option)
			parsed.markUnresolved(*index, argument, "unknown short option grammar")
			return
		}
		option.Canonical = spec.canonical
		option.Role = spec.role
		option.TakesValue = spec.arity != curlOptionNoValue

		switch spec.arity {
		case curlOptionNoValue:
			parsed.Options = append(parsed.Options, option)
			parsed.applyOption(group, option)
			continue
		case curlOptionRequiredValue:
			if offset+1 < len(argument) {
				option.ValuePresent = true
				option.ValueJoined = true
				option.Value = argument[offset+1:]
			} else if *index+1 < len(argv) {
				*index++
				option.ValuePresent = true
				option.ValueArgvIndex = *index
				option.Value = argv[*index]
			} else {
				parsed.markUnresolved(option.ArgvIndex, argument, "missing required option value")
			}
			parsed.Options = append(parsed.Options, option)
			parsed.applyOption(group, option)
			return
		case curlOptionOptionalValue:
			if offset+1 < len(argument) {
				option.ValuePresent = true
				option.ValueJoined = true
				option.Value = argument[offset+1:]
			} else if *index+1 < len(argv) && argv[*index+1] != "--" &&
				!strings.HasPrefix(argv[*index+1], "-") {
				*index++
				option.ValuePresent = true
				option.ValueArgvIndex = *index
				option.Value = argv[*index]
			}
			parsed.Options = append(parsed.Options, option)
			parsed.applyOption(group, option)
			return
		}
	}
}

func (parsed *curlArgvParse) applyOption(
	group *curlArgvGroup,
	option curlOptionToken,
) {
	switch option.Role {
	case curlOptionConfig:
		parsed.ConfigOpaque = true
		parsed.markUnresolved(
			option.ArgvIndex,
			option.Raw,
			"curl configuration can alter transfer semantics",
		)
	case curlOptionTarget:
		if !option.ValuePresent || option.Value == "" {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "empty URL option value")
			return
		}
		valueIndex := option.ValueArgvIndex
		if option.ValueJoined {
			valueIndex = option.ArgvIndex
		}
		parsed.appendTarget(group, valueIndex, option.Value, true)
	case curlOptionOutput:
		if !option.ValuePresent || option.Value == "" {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "empty output option value")
			group.outputs = append(group.outputs, curlOutputSlot{kind: curlOutputUnknown})
			return
		}
		kind := curlOutputFile
		if option.Value == "-" {
			kind = curlOutputStdout
		}
		group.outputs = append(group.outputs, curlOutputSlot{
			kind:  kind,
			value: option.Value,
		})
	case curlOptionRemoteName:
		group.outputs = append(group.outputs, curlOutputSlot{
			kind: curlOutputRemoteName,
		})
	case curlOptionRemoteNameAll:
		group.remoteNameAll = true
	case curlOptionNoRemoteName:
		if group.remoteNameAll {
			group.outputs = append(group.outputs, curlOutputSlot{
				kind: curlOutputStdout,
			})
		}
	case curlOptionNoRemoteNameAll:
		group.remoteNameAll = false
	case curlOptionMethod:
		if !option.ValuePresent || option.Value == "" {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "empty request method")
			return
		}
		group.method = option.Value
	case curlOptionUpload:
		if !option.ValuePresent {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "missing upload file")
			return
		}
		group.uploads = append(group.uploads, curlUploadSlot{
			value: option.Value,
		})
	case curlOptionHead:
		group.head = true
	case curlOptionNoHead:
		group.head = false
	case curlOptionPreview:
		parsed.Preview = true
	}
}

func (parsed *curlArgvParse) appendTarget(
	group *curlArgvGroup,
	argvIndex int,
	value string,
	viaURLOption bool,
) {
	if value == "" {
		parsed.markUnresolved(argvIndex, value, "empty transfer target")
		return
	}
	group.targets = append(group.targets, curlTargetOperand{
		argvIndex:    argvIndex,
		value:        value,
		viaURLOption: viaURLOption,
		remoteName:   group.remoteNameAll,
	})
}

func (parsed *curlArgvParse) finalizeGroup(group *curlArgvGroup) {
	for targetIndex, target := range group.targets {
		output := curlOutputSlot{kind: curlOutputStdout}
		if target.remoteName {
			output.kind = curlOutputRemoteName
		}
		if targetIndex < len(group.outputs) {
			output = group.outputs[targetIndex]
		}
		responseBodyStdout := output.kind == curlOutputStdout &&
			!parsed.Preview && !group.head &&
			!strings.EqualFold(group.method, "HEAD")
		transfer := curlTransferTarget{
			ArgvIndex:          target.argvIndex,
			Group:              group.index,
			Value:              target.value,
			ViaURLOption:       target.viaURLOption,
			Output:             output.kind,
			OutputValue:        output.value,
			Method:             group.method,
			Head:               group.head,
			Preview:            parsed.Preview,
			ResponseBodyStdout: responseBodyStdout,
		}
		if targetIndex < len(group.uploads) {
			transfer.UploadSet = true
			transfer.UploadValue = group.uploads[targetIndex].value
		}
		parsed.Targets = append(parsed.Targets, transfer)
	}
}

func (parsed *curlArgvParse) markUnresolved(
	argvIndex int,
	raw string,
	reason string,
) {
	parsed.Complete = false
	parsed.Unresolved = append(parsed.Unresolved, curlArgvUnresolved{
		ArgvIndex: argvIndex,
		Raw:       raw,
		Reason:    reason,
	})
}
