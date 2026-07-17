---
name: codeguard
description: "Security-aware code generation — teaches the agent CodeGuard rules to write secure code by default"
---

# CodeGuard: Secure Code Generation Rules

You MUST follow these security rules when writing code. Code that violates these
rules will be **blocked** by the DefenseClaw CodeGuard scanner before it reaches
disk. Write it correctly the first time.

---

## Credentials — all languages

### CG-CRED-001: Never hardcode API keys or secrets

Assigning API keys, secret keys, access tokens, or private keys directly in
source code exposes them in version control and build artifacts.

~~~python
# Load the value at runtime from an approved secret source.
import os
api_key = os.environ["API_KEY"]
~~~

~~~javascript
// Load the value at runtime from the process environment.
const accessToken = process.env.ACCESS_TOKEN;
~~~

Do not place realistic credential-shaped examples in documentation or test data.
Use descriptive placeholders containing spaces when an example value is needed,
such as `"provided by the secret store"`.

### CG-CRED-002: Never include AWS access key IDs

AWS access key IDs have a distinctive four-letter prefix followed by a fixed
length of uppercase letters and digits. Treat any value with that shape as a
real credential, including examples in comments or documentation.

~~~python
import boto3
session = boto3.Session()  # uses the standard SDK credential chain
~~~

### CG-CRED-003: Never embed private keys (CRITICAL)

PEM-encoded private keys use a five-hyphen marker, a `BEGIN` label, a key-type
label, and a matching end marker. That structure is the highest-severity
finding because it grants authentication as the key holder.

~~~python
# Load key material from a protected file or secrets manager at runtime.
with open("/etc/ssl/private/server.key") as f:
    key = f.read()
~~~

---

## Command Execution — Python, JavaScript, TypeScript, Ruby, PHP

### CG-EXEC-001: Never pass untrusted strings to command or code interpreters

APIs that pass one string to an operating-system command interpreter, or that
dynamically evaluate source text, enable injection when any part comes from
user input or external data. Invoke a fixed executable with a separate argument
list instead.

~~~python
import subprocess
subprocess.run(["grep", "--", user_input, "/var/log/app.log"], check=True)
~~~

~~~javascript
const { execFile } = require("child_process");
execFile("ls", ["--", userDir], callback);
~~~

~~~python
import json
result = json.loads(user_document)
~~~

### CG-EXEC-002: Never enable shell interpretation in subprocess APIs

Even with a subprocess library, enabling its shell mode re-introduces command
injection risk. Keep shell mode disabled and pass an argument list.

~~~python
subprocess.run(["convert", infile, outfile], check=True)
~~~

---

## SQL — Python, JavaScript, TypeScript, Ruby, PHP, Java

### CG-SQL-001: Never format strings into SQL queries

String interpolation in SQL enables SQL injection. Always use parameterized
queries with bind variables.

~~~python
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
~~~

~~~javascript
db.query("SELECT * FROM users WHERE id = ?", [userId]);
~~~

~~~java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
~~~

---

## Deserialization — Python

### CG-DESER-001: Never use executable object formats for untrusted data

Python-native object deserialization can execute arbitrary code. A generic YAML
loader can construct unsafe objects too. Prefer JSON, or use the YAML library's
explicit safe loader.

~~~python
import json
obj = json.loads(request.data)

import yaml
config = yaml.safe_load(user_yaml)
~~~

---

## Cryptography — Python, JavaScript, TypeScript, Java, Go, Ruby

### CG-CRYPTO-001: Never use MD5 or SHA1

MD5 and SHA1 are cryptographically broken. Use SHA-256 or stronger.

~~~python
import hashlib
h = hashlib.sha256(data)
~~~

~~~javascript
crypto.createHash("sha256").update(data);
~~~

---

## Network — Python, JavaScript, TypeScript, Go

### CG-NET-001: Validate outbound URLs

HTTP requests to URLs constructed from variables can enable SSRF (Server-Side
Request Forgery). Validate the scheme and require an exact host from an
application-owned allowlist before making a request.

~~~python
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
parsed = urllib.parse.urlsplit(user_url)
if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("URL not allowed")
response = approved_client.get(user_url)
~~~

---

## Path Safety — all languages

### CG-PATH-001: Reject parent-directory traversal

Parent-directory segments can escape an intended directory and expose arbitrary
files. Resolve both paths and require the candidate to remain under the trusted
root.

~~~python
from pathlib import Path

root = Path(upload_dir).resolve(strict=True)
candidate = (root / filename).resolve(strict=False)
try:
    candidate.relative_to(root)
except ValueError as exc:
    raise ValueError("path escapes the upload directory") from exc
~~~

---

## Quick Reference

| Rule | Severity | Languages | Instead of | Use |
|------|----------|-----------|-----------|-----|
| CG-CRED-001 | HIGH | all | Embedded credential values | Environment or secrets manager |
| CG-CRED-002 | HIGH | all | Cloud access IDs in source | Standard SDK credential chain |
| CG-CRED-003 | CRITICAL | all | Embedded key material | Protected file or secrets manager |
| CG-EXEC-001 | HIGH | py,js,ts,rb,php | Command or code strings | Fixed executable plus argument list |
| CG-EXEC-002 | MEDIUM | py | Subprocess shell mode | Argument-list subprocess call |
| CG-SQL-001 | HIGH | py,js,ts,rb,php,java | SQL string interpolation | Parameterized queries |
| CG-DESER-001 | HIGH | py | Executable object formats | JSON or an explicit safe loader |
| CG-CRYPTO-001 | MEDIUM | py,js,ts,java,go,rb | Broken legacy digests | SHA-256 or stronger |
| CG-NET-001 | MEDIUM | py,js,ts,go | Unvalidated variable URL | Scheme and exact-host validation |
| CG-PATH-001 | MEDIUM | all | Unchecked path joining | Resolve and enforce trusted root |
