// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestProviderTokenExactFormsAndBounds(t *testing.T) {
	t.Parallel()
	type form struct {
		name, prefix, alphabet string
		minSuffix, maxSuffix   int
	}
	forms := []form{}
	for _, prefix := range []string{"AKIA", "ASIA", "AROA", "AGPA", "AIDA", "AIPA", "ANPA", "ANVA"} {
		forms = append(forms, form{"aws-" + prefix, prefix, "A", 16, 16})
	}
	for _, prefix := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		forms = append(forms, form{"github-" + prefix, prefix, "A", 36, 36})
	}
	forms = append(forms,
		form{"gitlab", "glpat-", "A", 20, 255},
		form{"google", "AIza", "A", 35, 35},
	)
	for _, prefix := range []string{"xoxp-", "xoxa-", "xoxr-", "xoxs-"} {
		forms = append(forms, form{"slack-" + prefix, prefix, "A", 24, 200})
	}
	for _, prefix := range []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_"} {
		forms = append(forms, form{"stripe-" + prefix, prefix, "A", 20, 128})
	}
	for _, item := range []form{
		{"openai-project", "sk-proj-", "A", 16, 248},
		{"anthropic", "sk-ant-", "A", 17, 249},
		{"openrouter", "sk-or-", "A", 18, 250},
		{"generic-sk", "sk-", "A", 21, 253},
	} {
		forms = append(forms, item)
	}

	for _, item := range forms {
		item := item
		t.Run(item.name, func(t *testing.T) {
			lengths := []int{item.minSuffix}
			if item.maxSuffix != item.minSuffix {
				lengths = append(lengths, item.maxSuffix)
			}
			for _, length := range lengths {
				token := item.prefix + strings.Repeat(item.alphabet, length)
				assertDetectorExact(t, "credentials.api_token", "before "+token+" after", token)
			}
			short := item.prefix + strings.Repeat(item.alphabet, item.minSuffix-1)
			assertDetectorAbsent(t, "credentials.api_token", short)
			long := item.prefix + strings.Repeat(item.alphabet, item.maxSuffix+1)
			assertDetectorAbsent(t, "credentials.api_token", long)
			assertDetectorAbsent(t, "credentials.api_token", "X"+item.prefix+strings.Repeat(item.alphabet, item.minSuffix))
		})
	}

	pat := "github_pat_" + strings.Repeat("A", 22) + "_" + strings.Repeat("B", 59)
	assertDetectorExact(t, "credentials.api_token", pat, pat)
	assertDetectorAbsent(t, "credentials.api_token", "github_pat_"+strings.Repeat("A", 21)+"_"+strings.Repeat("B", 59))
	assertDetectorAbsent(t, "credentials.api_token", "github_pat_"+strings.Repeat("A", 22)+"_"+strings.Repeat("B", 60))

	for _, digits := range []int{10, 13} {
		for _, suffix := range []int{24, 128} {
			token := "xoxb-" + strings.Repeat("1", digits) + "-" + strings.Repeat("2", digits) + "-" + strings.Repeat("A", suffix)
			assertDetectorExact(t, "credentials.api_token", token, token)
		}
	}
	assertDetectorAbsent(t, "credentials.api_token", "xoxb-"+strings.Repeat("1", 9)+"-"+strings.Repeat("2", 10)+"-"+strings.Repeat("A", 24))
	assertDetectorAbsent(t, "credentials.api_token", "AKIA"+strings.Repeat("a", 16))
	assertDetectorAbsent(t, "credentials.api_token", "AIza"+strings.Repeat("A", 34)+"!")
	for _, value := range []string{
		"ghp_" + repeatToLength("aZ0", 36),
		"github_pat_" + repeatToLength("aZ0", 22) + "_" + repeatToLength("0Za", 59),
		"glpat-" + repeatToLength("aZ0_-", 20),
		"xoxb-1234567890-1234567890-" + repeatToLength("aZ0", 24),
		"xoxp-" + repeatToLength("aZ0-", 24),
		"sk_live_" + repeatToLength("aZ0", 20),
		"AIza" + repeatToLength("aZ0_-", 35),
		"sk-proj-" + repeatToLength("aZ0_+=.-", 16),
	} {
		assertDetectorExact(t, "credentials.api_token", value, value)
	}
	for _, value := range []string{
		"ghx_" + strings.Repeat("A", 36),
		"glpat_" + strings.Repeat("A", 20),
		"xoxc-" + strings.Repeat("A", 24),
		"AIza" + strings.Repeat("A", 34) + "!",
	} {
		assertDetectorAbsent(t, "credentials.api_token", value)
	}
}

func TestProviderJWTGrammarAndSemanticBounds(t *testing.T) {
	t.Parallel()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"fixture":true}`))
	token := header + "." + payload + ".AA"
	assertDetectorExact(t, "credentials.api_token", token, token)

	paddedHeader := base64.URLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	paddedPayload := base64.URLEncoding.EncodeToString([]byte(`{"fixture":true}`))
	padded := paddedHeader + "." + paddedPayload + ".AA=="
	assertDetectorExact(t, "credentials.api_token", padded, padded)
	maximumSegment := jwtObjectSegmentOfLength(t, 1024)
	maximum := maximumSegment + "." + maximumSegment + "." + strings.Repeat("A", 1024)
	if len(maximum) != 3074 {
		t.Fatalf("maximum JWT length=%d, want 3074", len(maximum))
	}
	assertDetectorExact(t, "credentials.api_token", maximum, maximum)

	deep := `{}`
	for range 17 {
		deep = `{"a":` + deep + `}`
	}
	members := make([]string, 257)
	for index := range members {
		members[index] = fmt.Sprintf(`"k%d":%d`, index, index)
	}

	invalid := []string{
		header + "." + payload + ".",
		header + "." + base64.RawURLEncoding.EncodeToString([]byte(`[]`)) + ".AA",
		header + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"a":1,"a":2}`)) + ".AA",
		header + "." + payload + ".AA=",
		"e30." + payload + ".AA",
		header + "." + strings.Repeat("A", 1025) + ".AA",
		header + "." + base64.RawURLEncoding.EncodeToString([]byte(deep)) + ".AA",
		header + "." + base64.RawURLEncoding.EncodeToString([]byte(`{`+strings.Join(members, ",")+`}`)) + ".AA",
	}
	for _, value := range invalid {
		assertDetectorAbsent(t, "credentials.api_token", value)
	}
}

func jwtObjectSegmentOfLength(t *testing.T, length int) string {
	t.Helper()
	for filler := 0; filler < 2000; filler++ {
		encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"fixture":"` + strings.Repeat("A", filler) + `"}`))
		if len(encoded) == length {
			return encoded
		}
	}
	t.Fatalf("could not construct a synthetic JSON-object segment of length %d", length)
	return ""
}

func TestPrivateKeyAllLabelsLineEndingsAndExclusions(t *testing.T) {
	t.Parallel()
	for _, label := range []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY"} {
		for _, newline := range []string{"\n", "\r\n"} {
			for _, payload := range []string{"QUJD", strings.Repeat("A", 64)} {
				block := "-----BEGIN " + label + "-----" + newline + payload + newline + "-----END " + label + "-----"
				assertDetectorExact(t, "credentials.private_key", "prefix\n"+block+"\nsuffix", block)
			}
		}
	}
	for _, value := range []string{
		"-----BEGIN PUBLIC KEY-----\nQUJDRA==\n-----END PUBLIC KEY-----",
		"-----BEGIN CERTIFICATE-----\nQUJDRA==\n-----END CERTIFICATE-----",
		"-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\n%%%INVALID%%%\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\nQUJDRA==\nQUJD\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\r\nQUJDRA==\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\n\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 65) + "\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY----- trailing\nQUJDRA==\n-----END PRIVATE KEY-----",
		"-----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY----- trailing",
		"-----BEGIN PRIVATE KEY-----\nQUJDRA==",
		"prose -----BEGIN PRIVATE KEY-----\nQUJDRA==\n-----END PRIVATE KEY-----",
	} {
		assertDetectorAbsent(t, "credentials.private_key", value)
	}
	oversize := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat(strings.Repeat("A", 64)+"\n", 1024) + "-----END PRIVATE KEY-----"
	assertDetectorAbsent(t, "credentials.private_key", oversize)
}

func TestAuthorizationEveryHeaderSchemeAndBound(t *testing.T) {
	t.Parallel()
	for _, header := range []string{"Authorization", "Proxy-Authorization"} {
		for _, scheme := range []string{"Bearer", "Basic", "Digest", "Token", "ApiKey"} {
			for _, separator := range []string{":", "="} {
				line := strings.ToUpper(header) + "\t" + separator + " \t" + strings.ToLower(scheme) + "\treserved-fixture"
				assertDetectorExact(t, "credentials.authorization", "safe\n"+line+"\nsafe", "reserved-fixture")
			}
		}
	}
	for _, value := range []string{
		"Authorization: Bearer",
		"Authorization: Unknown fixture",
		"X-Authorization: Bearer fixture",
		"prose Authorization: Bearer fixture",
		"Authorization: Bearer fixture\x01tail",
	} {
		assertDetectorAbsent(t, "credentials.authorization", value)
	}
	prefix := "Authorization: Bearer "
	boundaryCredential := strings.Repeat("A", 8192-len(prefix))
	assertDetectorExact(t, "credentials.authorization", prefix+boundaryCredential, boundaryCredential)
	assertDetectorAbsent(t, "credentials.authorization", "Authorization: Bearer "+strings.Repeat("A", 8192))
}

func TestCookieEverySensitiveNameAndHeaderGrammar(t *testing.T) {
	t.Parallel()
	names := []string{"session", "sessionid", "sid", "auth", "authorization", "token", "access_token", "refresh_token", "jwt", "csrf"}
	for _, name := range names {
		assertDetectorExact(t, "credentials.cookie", "Cookie: safe=ok; "+strings.ToUpper(name)+"=reserved-fixture", "reserved-fixture")
		assertDetectorExact(t, "credentials.cookie", "Set-Cookie: "+name+"=reserved-fixture; Path=/; Secure=yes", "reserved-fixture")
		assertDetectorAbsent(t, "credentials.cookie", "Set-Cookie: safe=ok; "+name+"=reserved-fixture")
	}
	assertDetectorExact(t, "credentials.cookie", `Cookie: session="reserved\"fixture"`, `reserved\"fixture`)
	cookiePrefix := "Cookie: session="
	boundaryValue := strings.Repeat("A", 8192-len(cookiePrefix))
	assertDetectorExact(t, "credentials.cookie", cookiePrefix+boundaryValue, boundaryValue)
	for _, value := range []string{
		"Cookie: theme=safe",
		"Cookie: session=",
		"Cookie: session=bad,value",
		"Cookie: session=\"unterminated",
		"Set-Cookie: safe=ok; token=attribute-value",
	} {
		assertDetectorAbsent(t, "credentials.cookie", value)
	}
	assertDetectorAbsent(t, "credentials.cookie", "Cookie: session="+strings.Repeat("A", 8192))
}

func TestConnectionStringEverySchemeAndForm(t *testing.T) {
	t.Parallel()
	schemes := []string{"postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps", "kafka", "sqlserver", "snowflake"}
	for _, scheme := range schemes {
		uri := scheme + "://fixture:reserved-pass@example.test/db"
		assertDetectorExact(t, "credentials.connection_string", uri, "reserved-pass")
		query := scheme + "://example.test/db?password=reserved%2Dpass"
		assertDetectorExact(t, "credentials.connection_string", query, "reserved%2Dpass")
	}
	queryKeys := []string{"token", "access_token", "refresh_token", "api_key", "apikey", "key", "secret", "client_secret", "password", "passwd", "pwd", "signature", "sig", "x-amz-signature", "x-goog-signature", "code", "credential"}
	for _, key := range queryKeys {
		assertDetectorExact(t, "credentials.connection_string", "POSTGRES://example.test/db?"+key+"=reserved%2Dquery", "reserved%2Dquery")
	}
	keys := []string{"password", "passwd", "pwd", "pass", "secret", "client_secret", "api_key", "apikey", "access_token", "refresh_token", "token", "signature", "credential"}
	for _, key := range keys {
		assertDetectorExact(t, "credentials.connection_string", "host=example.test;"+key+`="reserved\nvalue"`, `reserved\nvalue`)
		assertDetectorExact(t, "credentials.connection_string", "host=example.test \t"+key+"=reserved-value", "reserved-value")
	}
	assertDetectorExact(t, "credentials.connection_string", "postgres://fixture:reserved%2Dpass@example.test/db", "reserved%2Dpass")
	for _, value := range []string{
		"postgres://example.test/db",
		"postgres://fixture@example.test/db",
		"postgres://fixture:@example.test/db",
		"ftp://fixture:reserved-pass@example.test/db",
		"ftp://example.test/?password=reserved-pass",
		"postgres:fixture:reserved-pass@example.test/db",
		"postgres://example.test:/db",
		`"password"="reserved-fixture"`,
	} {
		assertDetectorAbsent(t, "credentials.connection_string", value)
	}
}

func TestConnectionStringURIExclusionLookupRemainsBounded(t *testing.T) {
	t.Parallel()
	const items = 2048
	var input strings.Builder
	for index := 0; index < items; index++ {
		fmt.Fprintf(&input, "ftp://example.test/path?password=value%d ", index)
	}
	candidates, err := recognizeConnectionStrings(input.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 0 {
		t.Fatalf("unsupported URI content escaped into DSN fallback: %d candidates", len(candidates))
	}
}

func TestAssignmentEveryKeySeparatorAndExclusion(t *testing.T) {
	t.Parallel()
	keys := []string{"password", "passwd", "pwd", "secret", "client_secret", "api_key", "apikey", "access_token", "refresh_token", "private_key", "signing_key"}
	for _, key := range keys {
		for _, separator := range []string{"=", ":"} {
			assertDetectorExact(t, "secrets.assignment", strings.ToUpper(key)+" \t"+separator+" \treserved-fixture", "reserved-fixture")
		}
		assertDetectorExact(t, "secrets.assignment", `"`+key+`":"reserved\nfixture"`, `reserved\nfixture`)
	}
	for _, excluded := range []string{"", "true", "FALSE", "null", "example", "sample", "dummy", "changeme", "redacted", "*****", "${FIXTURE}"} {
		assertDetectorAbsent(t, "secrets.assignment", "password="+excluded)
	}
	assertDetectorAbsent(t, "secrets.assignment", "not_password=reserved-fixture")
	assignmentPrefix := "password="
	assignmentBoundary := strings.Repeat("A", 8192-len(assignmentPrefix))
	assertDetectorExact(t, "secrets.assignment", assignmentPrefix+assignmentBoundary, assignmentBoundary)
	assertDetectorAbsent(t, "secrets.assignment", "password="+strings.Repeat("A", 8193))
}

func TestHighEntropyExactBoundsAlphabetsAndExclusions(t *testing.T) {
	t.Parallel()
	for _, length := range []int{20, 256} {
		value := syntheticEntropyValue(length)
		assertDetectorExactWithClass(t, "secrets.high_entropy", value, value, observability.FieldClassContent, nil)
	}
	hex := "0123456789abcdefABCD"
	assertDetectorExactWithClass(t, "secrets.high_entropy", hex, hex, observability.FieldClassContent, nil)
	standard := "Aa0+Bb1/Cc2+Dd3/Ee4+"
	assertDetectorExactWithClass(t, "secrets.high_entropy", standard, standard, observability.FieldClassContent, nil)
	urlSafe := "Aa0_Bb1-Cc2_Dd3-Ee4_"
	assertDetectorExactWithClass(t, "secrets.high_entropy", urlSafe, urlSafe, observability.FieldClassContent, nil)

	for _, value := range []string{
		syntheticEntropyValue(19), syntheticEntropyValue(257),
		strings.Repeat("A", 20), strings.Repeat("Ab3_", 8),
		"550e8400-e29b-41d4-a716-446655440000",
		"0123456789abcdef0123456789abcdef",
		"sampleexamplesampleexample", strings.Repeat("redacted", 4),
	} {
		assertDetectorAbsentWithClass(t, "secrets.high_entropy", value, observability.FieldClassContent, nil)
	}
	hash := strings.Repeat("0123456789abcdef", 4)
	assertDetectorAbsentWithClass(t, "secrets.high_entropy", hash, observability.FieldClassIdentifier, nil)
	credential := syntheticEntropyValue(32)
	prior := []acceptedMatch{{start: 0, end: len(credential), id: "credentials.api_token", group: DetectorGroupCredentials, order: 1}}
	assertDetectorAbsentWithClass(t, "secrets.high_entropy", credential, observability.FieldClassContent, prior)
}

func TestURLQueryEveryKeyEncodedOffsetsAndMalformedInput(t *testing.T) {
	t.Parallel()
	keys := []string{"token", "access_token", "refresh_token", "api_key", "apikey", "key", "secret", "client_secret", "password", "passwd", "pwd", "signature", "sig", "x-amz-signature", "x-goog-signature", "code", "credential"}
	for _, key := range keys {
		uri := "https://example.test/path?safe=ok&" + strings.ToUpper(key) + "=reserved%2Dvalue"
		assertDetectorExact(t, "secrets.url_query", uri, "reserved%2Dvalue")
	}
	repeated := "https://example.test/?token=first&safe=ok;token=second#fragment"
	assertDetectorExact(t, "secrets.url_query", repeated, "first")
	assertDetectorExact(t, "secrets.url_query", repeated, "second")
	for _, value := range []string{
		"https://example.test/?safe=value",
		"https://example.test/?token=",
		"https://example.test/?token=%zz",
		"https:///?token=value",
	} {
		candidates, err := recognize("secrets.url_query", value, observability.FieldClassContent, nil)
		if strings.Contains(value, "%zz") || strings.HasPrefix(value, "https:///?") {
			if err == nil {
				t.Fatalf("malformed sensitive URI %q did not fail safely", value)
			}
			continue
		}
		if err != nil || acceptedCandidates("secrets.url_query", value, candidates) != 0 {
			t.Fatalf("unexpected query match for %q: %+v, %v", value, candidates, err)
		}
	}
}

func TestCloudIdentifierEveryContextAndExclusion(t *testing.T) {
	t.Parallel()
	values := []struct{ input, match string }{
		{"aws_account_id=123456789012", "123456789012"},
		{"arn:aws:iam::123456789012:role/fixture", "123456789012"},
		{"azure_tenant_id=01234567-89ab-cdef-0123-456789abcdef", "01234567-89ab-cdef-0123-456789abcdef"},
		{"azure_subscription_id=abcdef01-2345-6789-abcd-ef0123456789", "abcdef01-2345-6789-abcd-ef0123456789"},
		{"/subscriptions/abcdef01-2345-6789-abcd-ef0123456789/resourceGroups/fixture", "abcdef01-2345-6789-abcd-ef0123456789"},
		{"/tenants/01234567-89ab-cdef-0123-456789abcdef/fixture", "01234567-89ab-cdef-0123-456789abcdef"},
		{"gcp_project_number=123456", "123456"},
		{"gcp_project_number=1234567890123456789", "1234567890123456789"},
		{"gcp_project_id=fixture-project1", "fixture-project1"},
		{"projects/fixture-project1/resources", "fixture-project1"},
		{"fixture@fixture-project1.iam.gserviceaccount.com", "fixture-project1"},
	}
	for _, value := range values {
		assertDetectorExact(t, "secrets.cloud_account_identifier", value.input, value.match)
	}
	for _, value := range []string{
		"123456789012",
		"01234567-89ab-cdef-0123-456789abcdef",
		"fixture-project1.example.test",
		"gcp_project_number=12345",
		"gcp_project_id=1fixture-project",
		"aws_account=123456789012",
		"notaws_account_id=123456789012",
		"xarn:aws:iam::123456789012:role/fixture",
	} {
		assertDetectorAbsent(t, "secrets.cloud_account_identifier", value)
	}
}

func TestEmailExactComponentAndTotalBounds(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"fixture@example.test",
		"first.last+tag@example.invalid",
		strings.Repeat("a", 64) + "@example.test",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
	} {
		assertDetectorExact(t, "pii.email", value, value)
	}
	for _, value := range []string{
		strings.Repeat("a", 65) + "@example.test",
		"fixture@example",
		"fixture@example.12",
		"fixture@-example.test",
		"fixture@example-.test",
		"fixture@" + strings.Repeat("a", 64) + ".test",
		"first..last@example.test",
		`"fixture"@example.test`,
		"fïxture@example.test",
		strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
	} {
		assertDetectorAbsent(t, "pii.email", value)
	}
}

func TestTelephoneEveryFormSeparatorAndExclusion(t *testing.T) {
	t.Parallel()
	for _, separator := range []string{" ", ".", "-"} {
		for _, value := range []string{
			"212" + separator + "555" + separator + "0100",
			"(212)" + separator + "555" + separator + "0100",
			"+1" + separator + "212" + separator + "555" + separator + "0100",
			"+1" + separator + "(212)" + separator + "555" + separator + "0100",
		} {
			assertDetectorExact(t, "pii.telephone", value, value)
		}
	}
	for _, value := range []string{
		"2125550100", "012-555-0100", "212-155-0100", "212-555.0100",
		"212-555-0100 x123", "+44 212-555-0100", "+2 212-555-0100",
		"1212-555-01000", "2026-07-03", "1.212.555.0100",
	} {
		assertDetectorAbsent(t, "pii.telephone", value)
	}
}

func TestNationalIdentifierAllStructuralExclusions(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"321-54-9876", "899-99-9998"} {
		assertDetectorExact(t, "pii.national_identifier", value, value)
	}
	excluded := []string{
		"000-12-3456", "666-12-3456", "900-12-3456", "999-12-3456",
		"321-00-9876", "321-54-0000", "111-11-1111",
		"078-05-1120", "123-45-6789", "219-09-9999", "987-65-4321",
		"321549876", "1321-54-98760",
	}
	for _, value := range excluded {
		assertDetectorAbsent(t, "pii.national_identifier", value)
	}
}

func TestPaymentCardEveryLengthSeparatorAndLuhnExclusion(t *testing.T) {
	t.Parallel()
	for length := 13; length <= 19; length++ {
		digits := syntheticLuhn(length)
		assertDetectorExact(t, "pii.payment_card", digits, digits)
		for _, separator := range []string{" ", "-"} {
			separated := strings.Join(strings.Split(digits, ""), separator)
			assertDetectorExact(t, "pii.payment_card", separated, separated)
		}
		last := digits[len(digits)-1]
		negative := digits[:len(digits)-1] + string('0'+((last-'0'+1)%10))
		assertDetectorAbsent(t, "pii.payment_card", negative)
	}
	for _, value := range []string{
		strings.Repeat("1", 16), "4242 4242-4242 4242", "14242424242424242",
	} {
		assertDetectorAbsent(t, "pii.payment_card", value)
	}
}

func TestIPAddressIPv4IPv6AndExactExclusions(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"192.0.2.1", "2001:db8::1", "::1", "::ffff:192.0.2.1"} {
		assertDetectorExact(t, "pii.ip_address", value, value)
	}
	for _, value := range []string{
		"192.168.001.1", "192.0.2.999", "192.0.2.1:443", "[2001:db8::1]:443",
		"192.0.2.1/24", "2001:db8::1/64", "fe80::1%fixture", "2001:::1", "x192.0.2.1x",
	} {
		assertDetectorAbsent(t, "pii.ip_address", value)
	}
}

func assertDetectorExact(t *testing.T, id DetectorID, input, expected string) {
	t.Helper()
	assertDetectorExactWithClass(t, id, input, expected, observability.FieldClassContent, nil)
}

func assertDetectorExactWithClass(t *testing.T, id DetectorID, input, expected string, class observability.FieldClass, prior []acceptedMatch) {
	t.Helper()
	candidates, err := recognize(id, input, class, prior)
	if err != nil {
		t.Fatalf("%s recognize: %v", id, err)
	}
	definition, _ := catalogDefinitionFor(id)
	for _, item := range candidates {
		if validCandidate(item, len(input), definition.candidateBound) && item.accepted && input[item.start:item.end] == expected {
			return
		}
	}
	t.Fatalf("%s did not recognize exact %q in %q: %+v", id, expected, input, candidates)
}

func assertDetectorAbsent(t *testing.T, id DetectorID, input string) {
	t.Helper()
	assertDetectorAbsentWithClass(t, id, input, observability.FieldClassContent, nil)
}

func assertDetectorAbsentWithClass(t *testing.T, id DetectorID, input string, class observability.FieldClass, prior []acceptedMatch) {
	t.Helper()
	candidates, err := recognize(id, input, class, prior)
	if err != nil {
		t.Fatalf("%s unexpected recognizer failure: %v", id, err)
	}
	if count := acceptedCandidates(id, input, candidates); count != 0 {
		t.Fatalf("%s unexpectedly accepted %q: %+v", id, input, candidates)
	}
}

func acceptedCandidates(id DetectorID, input string, candidates []candidate) int {
	definition, _ := catalogDefinitionFor(id)
	count := 0
	for _, item := range candidates {
		if validCandidate(item, len(input), definition.candidateBound) && item.accepted {
			count++
		}
	}
	return count
}

func syntheticEntropyValue(length int) string {
	const alphabet = "Aa0_Bb1-Cc2_Dd3-Ee4_Ff5-Gg6_Hh7-Ii8_Jj9-Kk0_Ll1-Mm2_Nn3-Oo4_Pp5-Qq6_Rr7-Ss8_Tt9-"
	return strings.Repeat(alphabet, (length+len(alphabet)-1)/len(alphabet))[:length]
}

func repeatToLength(pattern string, length int) string {
	return strings.Repeat(pattern, (length+len(pattern)-1)/len(pattern))[:length]
}

func syntheticLuhn(length int) string {
	prefix := strings.Repeat("42", (length+1)/2)[:length-1]
	for digit := byte('0'); digit <= '9'; digit++ {
		candidate := prefix + string(digit)
		if validPaymentCard(candidate) {
			return candidate
		}
	}
	panic(fmt.Sprintf("could not build synthetic Luhn value of length %d", length))
}
