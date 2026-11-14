// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math/rand"
	"strings"
	"testing"
)

// Regression rows for the fifth review of s7/secret-recall (GAP-0469,
// GAP-0470 and the version-token note). The code rows are lines of code, not
// secrets; every secret-shaped value is generated at run time.

// secretRecallSR6CodeRows are 45 common lines that assign a call, a tuple or a
// lambda to a secret-named variable, by the id of the review probe. none of
// them is a credential, so none may raise an alert in the default pack.
var secretRecallSR6CodeRows = []struct{ id, file, line string }{
	{"PY01", "settings.py", "SECRET_KEY = base64.b64encode(os.urandom(32))"},
	{"PY02", "app.py", "token = uuid.uuid4().hex"},
	{"PY03", "app.py", "api_key = str(uuid.uuid4())"},
	{"PY04", "app.py", "secret = os.urandom(24).hex()"},
	{"PY05", "app.py", "password = hashlib.sha256(raw.encode()).hexdigest()"},
	{"PY06", "app.py", "secret_key = binascii.hexlify(os.urandom(24)).decode()"},
	{"PY07", "app.py", "token = base64.urlsafe_b64encode(os.urandom(32)).decode()"},
	{"PY08", "app.py", "token = hmac.new(key, msg, hashlib.sha256).hexdigest()"},
	{"PY09", "app.py", "api_key = uuid.uuid4().hex[:32]"},
	{"PY10", "app.py", "secret = sha256(data).hexdigest()"},
	{"PY11", "app.py", "token = md5(str(time.time()).encode()).hexdigest()"},
	{"PY12", "app.py", "password = random.randint(100000, 999999)"},
	{"PY13", "app.py", "SECRET_KEY = get_random_secret_key()"},
	{"PY14", "app.py", "token = jwt.encode(payload, key, algorithm=HS256)"},
	{"PY15", "app.py", "password = bcrypt.hashpw(pw, bcrypt.gensalt(12))"},
	{"PY16", "app.py", "token = (user_id2024, session_v2)"},
	{"PY17", "app.py", "token = (lambda: os.urandom(16))()"},
	{"PY18", "app.py", "api_key = ''.join(random.choices(chars, k=32))"},
	{"PY19", "app.py", "token = str(uuid4())"},
	{"PY20", "app.py", "token = uuid4().hex"},
	{"PY21", "app.py", "secret = Fernet.generate_key()"},
	{"PY22", "app.py", "token = sha1(os.urandom(64)).hexdigest()"},
	{"PY23", "app.py", "token = base64.b32encode(os.urandom(10))"},
	{"PY24", "app.py", "password = pbkdf2_sha256.hash(raw)"},
	{"PY25", "app.py", "token = hashlib.sha512(seed).hexdigest()"},
	{"JS01", "app.js", "const token = crypto.randomBytes(32).toString('hex')"},
	{"JS02", "app.js", "const secret = crypto.randomBytes(64).toString(\"base64\")"},
	{"JS03", "app.js", "let token = Math.random().toString(36).substring(2)"},
	{"JS04", "app.js", "const apiKey = randomBytes(48).toString('hex')"},
	{"JS05", "app.js", "const token = nanoid(32)"},
	{"JS06", "app.js", "const secret = crypto.createHash('sha256').update(x).digest('hex')"},
	{"JS07", "app.js", "const token = btoa(String.fromCharCode(...bytes))"},
	{"JS08", "app.js", "const apiKey = uuidv4().replace(/-/g, '')"},
	{"JS09", "app.ts", "const token = Buffer.from(crypto.randomBytes(32)).toString('base64url')"},
	{"GO01", "main.go", "token = base64.StdEncoding.EncodeToString(buf)"},
	{"GO02", "main.go", "apiKey = hex.EncodeToString(sha256.New().Sum(nil))"},
	{"GO03", "main.go", "secret = base64.URLEncoding.EncodeToString(b[:32])"},
	{"GO04", "main.go", "var token = fmt.Sprintf(\"%x\", sha256.Sum256(data))"},
	{"RB01", "app.rb", "token = SecureRandom.hex(32)"},
	{"RB02", "app.rb", "secret = SecureRandom.base64(48)"},
	{"RB03", "app.rb", "api_key = Digest::SHA256.hexdigest(seed)"},
	{"JV01", "App.java", "String token = UUID.randomUUID().toString()"},
	{"JV02", "App.java", "token = Base64.getEncoder().encodeToString(bytes)"},
	{"SH01", "run.sh", "TOKEN=$(openssl rand -hex 32)"},
	{"SH02", "run.sh", "SECRET=$(head -c 32 /dev/urandom | base64)"},
}

// GAP-0469: code that generates a secret is not an alert, whatever the callee
// is called. The nine rows that the first version of the parenthesis fix let
// through must be rejected as a call; the rest of the 45 stay rejected.
func TestSecretRecallSR6CodeLinesRaiseNoAlertByID(t *testing.T) {
	const connector = "secret-recall-sr6-test"
	installDefaultProfileConnector(t, connector)
	gap := map[string]bool{"PY01": true, "PY02": true, "PY03": true, "PY09": true, "PY19": true, "PY23": true, "PY24": true, "GO02": true, "GO03": true}
	if len(secretRecallSR6CodeRows) != 45 {
		t.Fatalf("%d rows, want the 45 of the review", len(secretRecallSR6CodeRows))
	}
	for _, row := range secretRecallSR6CodeRows {
		t.Run(row.id, func(t *testing.T) {
			if parts := secretAssignmentParts.FindStringSubmatch(strings.TrimSpace(row.line)); parts != nil {
				reason := secretAssignmentRejection(parts[2])
				if reason == "" {
					t.Errorf("%s: %q accepted as a secret value", row.id, row.line)
				}
				if gap[row.id] && reason != "call" {
					t.Errorf("%s: %q rejected as %q, want call", row.id, row.line, reason)
				}
			}
			args := map[string]any{"file_path": "/work/app/" + row.file, "content": row.line + "\n"}
			if got := reviewDisposition(t, connector, "Write", args); got != credNone {
				t.Errorf("%s: %q: disposition = %s, want %s", row.id, row.line, got, credNone)
			}
		})
	}
}

// What is a call is told by structure: a path, a balanced argument list, then
// only attributes and further calls. What is not stays a value.
func TestSecretRecallSR6CallShape(t *testing.T) {
	for _, call := range []string{
		"base64.b64encode(os.urandom(32))", "uuid.uuid4().hex", "str(uuid.uuid4())", "str(uuid4())", "pbkdf2_sha256.hash(raw)",
		"hex.EncodeToString(sha256.New().Sum(nil))", "base64.URLEncoding.EncodeToString(b", "SecureRandom.hex(32)",
		"Digest::SHA256.hexdigest(seed)", "a1b2c3d4e5.f6(x)", "make_x9q2z7(k)", "f(x)(y)", "get_token()",
	} {
		if !secretAssignmentCallShaped(call) {
			t.Errorf("%q is a call and was not read as one", call)
		}
	}
	for _, notCall := range []string{
		"", "(user)", "f", "a.b.c", "f(x))", "f(x)abc", "f(x).", "f(x)$y", "f(x#y)", "f(a@b)", "9f(x)", "f(x)-y",
	} {
		if secretAssignmentCallShaped(notCall) {
			t.Errorf("%q is not a call and was read as one", notCall)
		}
	}
}

// Random values with a ( in them are values: a generated Django-style key, a
// base64 or a hex string that a call to a name happens to start.
func TestSecretRecallSR6RandomValuesWithParenthesesAreValues(t *testing.T) {
	r := rand.New(rand.NewSource(469))
	const n = 2000
	accepted := 0
	for i := 0; i < n; i++ {
		if secretAssignmentRejection(randomString(r, djangoAlphabet, 50)) == "" {
			accepted++
		}
	}
	if accepted < 1983 {
		t.Errorf("django-style keys accepted %d of %d, want at least 1983", accepted, n)
	}
	accepted = 0
	for i := 0; i < n; i++ {
		v := randomString(r, lowerDigitAlphabet, 24)
		if secretAssignmentRejection(v[:11]+"-"+v[12:]) == "" {
			accepted++
		}
	}
	if accepted < 1925 {
		t.Errorf("lower+digit 24 with a dash accepted %d of %d, want at least 1925", accepted, n)
	}
}

// GAP-0470: one number of ten or thirteen digits is a timestamp and weighs
// nothing; several are random digits.
func TestSecretRecallSR6OnlyOneTimestampGroupIsACounter(t *testing.T) {
	r := rand.New(rand.NewSource(470))
	digits := "0123456789"
	for _, name := range []string{"dr_secret_key_1700000000", "summer-holiday-1700000000123", "build_2026_nightly_1700000000"} {
		if got := secretAssignmentRejection(name); got == "" {
			t.Errorf("a name with one timestamp was accepted: %q", name)
		}
	}
	const n = 500
	for label, gen := range map[string]func() string{
		"3 x 10": func() string {
			return "prod_" + randomString(r, digits, 10) + "_" + randomString(r, digits, 10) + "_" + randomString(r, digits, 10)
		},
		"2 x 13": func() string { return "key-" + randomString(r, digits, 13) + "-" + randomString(r, digits, 13) },
		"10 + 13": func() string {
			return "token_" + randomString(r, digits, 10) + "_" + randomString(r, digits, 13)
		},
	} {
		accepted := 0
		for i := 0; i < n; i++ {
			if secretAssignmentRejection(gen()) == "" {
				accepted++
			}
		}
		if accepted < n*99/100 {
			t.Errorf("%s: word and several digit groups accepted %d of %d, want at least 99%%", label, accepted, n)
		}
	}
}

// One version token (python3dot11, md5sum2024) is a name; a second one, or a
// segment of random letters and digits, is not.
func TestSecretRecallSR6VersionTokensInNames(t *testing.T) {
	for _, name := range []string{
		"python3dot11_runtime_env", "md5sum2024_backup_check", "k8s_v1beta1_cluster_prod", "release-v2rc1b3-candidate",
		"model-gpt4o2024-preview", "ubuntu2204lts_image_base", "build_20261113_1530_v2",
	} {
		if got := secretAssignmentRejection(name); got == "" {
			t.Errorf("a composed name was accepted as a secret: %q", name)
		}
	}
	for _, token := range []string{
		"python3dot11_md5sum2024_check", "prod_7f8a9b0c1d2e3f", "svc_x9k2m7q4p1w8", "dd_api_7f8a9b0c1d2e3f4a5b6c",
	} {
		if got := secretAssignmentRejection(token); got != "" {
			t.Errorf("a generated value was rejected as %q: %q", got, token)
		}
	}
	r := rand.New(rand.NewSource(471))
	const n = 2000
	accepted := 0
	for i := 0; i < n; i++ {
		if secretAssignmentRejection("prod_"+randomString(r, lowerDigitAlphabet, 12)) == "" {
			accepted++
		}
	}
	if accepted < 1640 {
		t.Errorf("word and 12 lower+digit accepted %d of %d, want at least 1640", accepted, n)
	}
}

// A relative path (words joined by /) is a name, like a path that starts with
// a slash; a random base64 value that holds a / is still a value. The path
// rows are synthetic, with one version-like segment, as home trees have
// (runtime/k8s/overlays).
func TestSecretRecallSR6RelativePathsAreNames(t *testing.T) {
	for _, path := range []string{
		"home/builder/projects/k8s/overlays/production/config",
		"srv/data/backups/s3x/archive/monthly/reports/summary",
		"var/lib/services/app2/releases/current/shared/config",
	} {
		if got := secretAssignmentRejection(path); got == "" {
			t.Errorf("a relative path was accepted as a secret: %q", path)
		}
	}
	const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	r := rand.New(rand.NewSource(473))
	const n = 2000
	accepted := 0
	for i := 0; i < n; i++ {
		v := randomString(r, base64Alphabet, 40)
		if !strings.Contains(v, "/") {
			v = v[:20] + "/" + v[21:]
		}
		if secretAssignmentRejection(v) == "" {
			accepted++
		}
	}
	if accepted < 1940 {
		t.Errorf("base64 values with a slash accepted %d of %d, want at least 1940 (1948 before the path rule, same sample)", accepted, n)
	}
}
