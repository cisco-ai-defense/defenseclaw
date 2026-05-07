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

package gateway

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// PatternRule is a single detection rule with a compiled regex, severity,
// and confidence score. All runtime tool inspection uses these rules.
type PatternRule struct {
	ID         string
	Pattern    *regexp.Regexp
	Title      string
	Severity   string
	Confidence float64
	Tags       []string
}

// RuleFinding is a structured finding produced by scanning tool args or content.
type RuleFinding struct {
	RuleID     string   `json:"rule_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Evidence   string   `json:"evidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// ---------------------------------------------------------------------------
// Secret detection rules
//
// Modeled after the high-quality patterns in the TS plugin scanner (rules.ts).
// Each pattern uses regex with structure/length validation to minimize false
// positives. "sk-" alone is gone — it matches "desk-lamp".
// ---------------------------------------------------------------------------

var secretRules = []PatternRule{
	{ID: "SEC-AWS-KEY", Pattern: regexp.MustCompile(`(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16,}`), Title: "AWS access key", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-AWS-SECRET", Pattern: regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{30,}`), Title: "AWS secret access key", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential"}},
	{ID: "SEC-ANTHROPIC", Pattern: regexp.MustCompile(`sk-ant-[a-zA-Z0-9\-_]{20,}`), Title: "Anthropic API key", Severity: "CRITICAL", Confidence: 0.98, Tags: []string{"credential"}},
	{ID: "SEC-OPENAI", Pattern: regexp.MustCompile(`sk-proj-[a-zA-Z0-9]{20,}`), Title: "OpenAI project key", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-OPENAI-V2", Pattern: regexp.MustCompile(`sk-[a-zA-Z0-9]{40,}`), Title: "OpenAI API key (long form)", Severity: "CRITICAL", Confidence: 0.85, Tags: []string{"credential"}},
	{ID: "SEC-STRIPE", Pattern: regexp.MustCompile(`(?:sk_live_|pk_live_|sk_test_|pk_test_|rk_live_|rk_test_)[a-zA-Z0-9]{20,}`), Title: "Stripe key", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-GITHUB-TOKEN", Pattern: regexp.MustCompile(`(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}`), Title: "GitHub token", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-GITHUB-PAT", Pattern: regexp.MustCompile(`github_pat_[a-zA-Z0-9_]{22,}`), Title: "GitHub fine-grained PAT", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-GITLAB", Pattern: regexp.MustCompile(`glpat-[a-zA-Z0-9\-_]{20,}`), Title: "GitLab personal access token", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-GOOGLE", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Title: "Google API key", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential"}},
	{ID: "SEC-SLACK-TOKEN", Pattern: regexp.MustCompile(`xox[bpors]-[0-9a-zA-Z\-]{10,}`), Title: "Slack token", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential"}},
	{ID: "SEC-SLACK-WEBHOOK", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`), Title: "Slack webhook URL", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-DISCORD-WEBHOOK", Pattern: regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/\d+/[a-zA-Z0-9_\-]+`), Title: "Discord webhook URL", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-PRIVKEY", Pattern: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----`), Title: "Private key", Severity: "CRITICAL", Confidence: 0.98, Tags: []string{"credential"}},
	{ID: "SEC-JWT", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]+`), Title: "JWT token", Severity: "MEDIUM", Confidence: 0.70, Tags: []string{"credential"}},
	{ID: "SEC-CONNSTR", Pattern: regexp.MustCompile(`(?:mongodb|postgres|mysql|redis|amqp)://[^:\s]+:[^@\s]+@`), Title: "Connection string with credentials", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential"}},
	{ID: "SEC-BEARER", Pattern: regexp.MustCompile(`(?i)(?:authorization|bearer)\s*[:=]\s*Bearer\s+[A-Za-z0-9\-_.~+/]+=*`), Title: "Bearer token in header", Severity: "HIGH", Confidence: 0.80, Tags: []string{"credential"}},
	{ID: "SEC-SENDGRID", Pattern: regexp.MustCompile(`SG\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}`), Title: "SendGrid API key", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-TWILIO", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Title: "Twilio API key", Severity: "HIGH", Confidence: 0.80, Tags: []string{"credential"}},
	{ID: "SEC-NPM-TOKEN", Pattern: regexp.MustCompile(`npm_[a-zA-Z0-9]{36,}`), Title: "npm access token", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-PYPI-TOKEN", Pattern: regexp.MustCompile(`pypi-[A-Za-z0-9\-_]{50,}`), Title: "PyPI API token", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential"}},
	{ID: "SEC-HEX-SECRET", Pattern: regexp.MustCompile(`(?i)(?:secret(?:_key)?|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["'][a-f0-9]{32,}["']`), Title: "Hex-encoded secret in assignment", Severity: "HIGH", Confidence: 0.72, Tags: []string{"credential"}},
}

// ---------------------------------------------------------------------------
// Command execution rules
//
// Detect dangerous shell commands in tool args. Regex-based with word
// boundaries and syntax awareness. Replaces the old flat dangerousPatterns
// substring list.
// ---------------------------------------------------------------------------

var commandRules = []PatternRule{
	// Reverse shells and bind shells
	{ID: "CMD-REVSHELL-BASH", Pattern: regexp.MustCompile(`(?i)bash\s+-i\s+>&\s*/dev/tcp/`), Title: "Bash reverse shell", Severity: "CRITICAL", Confidence: 0.98, Tags: []string{"execution", "reverse-shell"}},
	{ID: "CMD-REVSHELL-DEVTCP", Pattern: regexp.MustCompile(`/dev/tcp/\d{1,3}\.\d{1,3}`), Title: "Reverse shell via /dev/tcp", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"execution", "reverse-shell"}},
	{ID: "CMD-REVSHELL-NC", Pattern: regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat)\b\s+(?:-[a-zA-Z]*\s+)*\S+\s+\d+\s*(?:-e|--exec)`), Title: "Netcat reverse shell with -e", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"execution", "reverse-shell"}},
	{ID: "CMD-REVSHELL-PYTHON", Pattern: regexp.MustCompile(`(?i)python[23]?\s+-c\s+.*socket.*connect`), Title: "Python reverse shell", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"execution", "reverse-shell"}},
	// Piped execution — download and run
	{ID: "CMD-PIPE-CURL", Pattern: regexp.MustCompile(`(?i)\bcurl\b\s+[^|]*\|\s*(?:ba)?sh\b`), Title: "curl piped to shell", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"execution", "download-exec"}},
	{ID: "CMD-PIPE-WGET", Pattern: regexp.MustCompile(`(?i)\bwget\b\s+[^|]*\|\s*(?:ba)?sh\b`), Title: "wget piped to shell", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"execution", "download-exec"}},
	{ID: "CMD-PIPE-BASE64", Pattern: regexp.MustCompile(`(?i)base64\s+(?:-[dD]|--decode)\s*\|\s*(?:ba)?sh\b`), Title: "base64 decode piped to shell", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"execution", "obfuscation"}},
	// Dynamic code execution
	{ID: "CMD-EVAL", Pattern: regexp.MustCompile(`(?i)\beval\s+["'\$\(]`), Title: "Shell eval with dynamic input", Severity: "HIGH", Confidence: 0.85, Tags: []string{"execution"}},
	{ID: "CMD-BASH-C", Pattern: regexp.MustCompile(`(?i)\b(?:ba)?sh\s+-c\s+`), Title: "Shell -c execution", Severity: "LOW", Confidence: 0.55, Tags: []string{"execution"}},
	{ID: "CMD-PYTHON-C", Pattern: regexp.MustCompile(`(?i)\bpython[23]?\s+-c\s+`), Title: "Python inline execution", Severity: "LOW", Confidence: 0.55, Tags: []string{"execution"}},
	{ID: "CMD-PERL-E", Pattern: regexp.MustCompile(`(?i)\bperl\s+-e\s+`), Title: "Perl inline execution", Severity: "LOW", Confidence: 0.55, Tags: []string{"execution"}},
	{ID: "CMD-RUBY-E", Pattern: regexp.MustCompile(`(?i)\bruby\s+-e\s+`), Title: "Ruby inline execution", Severity: "LOW", Confidence: 0.55, Tags: []string{"execution"}},
	// Destructive operations
	{ID: "CMD-RM-RF", Pattern: regexp.MustCompile(`(?i)\brm\s+(?:-[a-zA-Z]*\s+)*(?:-[a-zA-Z]*)?(?:r[a-zA-Z]*f|f[a-zA-Z]*r)\b(?:\s+\S+)*\s+/(?:$|["'\s,}\]]|(?:etc|bin|sbin|usr|var|home|root|opt|boot|lib(?:64)?|srv|mnt|dev|proc|sys)(?:$|/|["'\s,}\]]))`), Title: "Recursive force delete from critical root path", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"destructive"}},
	{ID: "CMD-MKFS", Pattern: regexp.MustCompile(`(?i)\bmkfs\b`), Title: "Filesystem format command", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"destructive"}},
	{ID: "CMD-DD-IF", Pattern: regexp.MustCompile(`(?i)\bdd\s+if=`), Title: "dd disk write", Severity: "HIGH", Confidence: 0.80, Tags: []string{"destructive"}},
	// Privilege escalation
	{ID: "CMD-CHMOD-WORLD", Pattern: regexp.MustCompile(`(?i)\bchmod\s+[0-7]*[0-7][0-7][2367]\s`), Title: "chmod world-writable", Severity: "HIGH", Confidence: 0.80, Tags: []string{"privilege"}},
	{ID: "CMD-CHOWN-ROOT", Pattern: regexp.MustCompile(`(?i)\bchown\s+root\b`), Title: "chown to root", Severity: "HIGH", Confidence: 0.75, Tags: []string{"privilege"}},
	{ID: "CMD-SUDO", Pattern: regexp.MustCompile(`(?i)\bsudo\s+`), Title: "sudo invocation", Severity: "LOW", Confidence: 0.50, Tags: []string{"privilege"}},
	// System file manipulation
	{ID: "CMD-ETC-WRITE", Pattern: regexp.MustCompile(`(?i)>\s*/etc/`), Title: "Write redirect to /etc/", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"system-file"}},
	{ID: "CMD-CRONTAB", Pattern: regexp.MustCompile(`(?i)\bcrontab\s+(?:-[a-zA-Z]\s+)*(?:-e|-r|-l|/|['"<>|])`), Title: "Crontab modification", Severity: "HIGH", Confidence: 0.75, Tags: []string{"persistence"}},
	{ID: "CMD-SYSTEMCTL", Pattern: regexp.MustCompile(`(?i)\bsystemctl\s+enable\b(?:\s+--now\b)?\s+\S*(?:backdoor|payload|persist|reverse|shell|evil)\S*(?:\.service)?\b`), Title: "Suspicious systemd persistence enablement", Severity: "CRITICAL", Confidence: 0.82, Tags: []string{"persistence"}},
	// Network reconnaissance
	{ID: "CMD-NETCAT-LISTEN", Pattern: regexp.MustCompile(`(?i)\b(?:nc|ncat|netcat)\b\s+(?:-[a-zA-Z]*)*-?l`), Title: "Netcat listener", Severity: "HIGH", Confidence: 0.85, Tags: []string{"network", "reverse-shell"}},
	{ID: "CMD-CURL-UPLOAD", Pattern: regexp.MustCompile(`(?i)\bcurl\b\s+.*(?:--upload-file|-T\s|--data\s+@|-F\s+.*=@)`), Title: "curl file upload", Severity: "HIGH", Confidence: 0.85, Tags: []string{"network", "exfiltration"}},
	{ID: "CMD-WGET-POST", Pattern: regexp.MustCompile(`(?i)\bwget\b\s+.*--post-(?:data|file)`), Title: "wget POST data exfil", Severity: "HIGH", Confidence: 0.85, Tags: []string{"network", "exfiltration"}},
	{ID: "CMD-SOCAT-EXEC", Pattern: regexp.MustCompile(`(?i)\bsocat\b\s+.*\bEXEC\b`), Title: "socat with EXEC (reverse shell)", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"execution", "reverse-shell"}},
	{ID: "CMD-ENV-DUMP", Pattern: regexp.MustCompile(`(?:^|[^A-Za-z0-9_./-])(?:env|printenv|export\s+-p)\b`), Title: "Environment variable dump", Severity: "HIGH", Confidence: 0.80, Tags: []string{"credential"}},
}

// ---------------------------------------------------------------------------
// Sensitive path rules
//
// Detect access to credential stores, config files, and sensitive directories.
// Uses boundary matching to avoid false positives (e.g. "desktop-environment"
// matching ".env").
// ---------------------------------------------------------------------------

var sensitivePathRules = []PatternRule{
	{ID: "PATH-SSH-DIR", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.ssh/`), Title: "SSH directory access", Severity: "HIGH", Confidence: 0.95, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-SSH-KEY", Pattern: regexp.MustCompile(`(?i)(?:^|[\\/])id_(?:rsa|ed25519|ecdsa|dsa)(?:$|[^A-Za-z0-9_.-])`), Title: "SSH private key file path", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-AWS-CREDS", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.aws/credentials`), Title: "AWS credentials file", Severity: "CRITICAL", Confidence: 0.98, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-AWS-CONFIG", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.aws/config`), Title: "AWS config file", Severity: "HIGH", Confidence: 0.85, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-KUBE", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.kube/config`), Title: "Kubernetes config", Severity: "HIGH", Confidence: 0.90, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-DOCKER", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.docker/config\.json`), Title: "Docker config", Severity: "HIGH", Confidence: 0.90, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-GNUPG", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.gnupg/`), Title: "GPG keyring access", Severity: "HIGH", Confidence: 0.95, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-NPMRC", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.npmrc`), Title: "npm config (may contain tokens)", Severity: "MEDIUM", Confidence: 0.80, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-PYPIRC", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.pypirc`), Title: "PyPI config (may contain tokens)", Severity: "MEDIUM", Confidence: 0.80, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-GIT-CREDS", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.git-credentials`), Title: "Git credentials file", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-NETRC", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.netrc`), Title: "netrc credentials file", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential", "file-sensitive"}},
	{ID: "PATH-ENV-FILE", Pattern: regexp.MustCompile(`(?:^|[\s/])\.env(?:\.(?:local|production|staging|development))?\s*["'\s,\]})]*$|(?:^|[\s/])\.env(?:\.(?:local|production|staging|development))?["'\s,\]})]`), Title: "Environment file", Severity: "HIGH", Confidence: 0.85, Tags: []string{"credential", "file-sensitive"}},
	// The /etc/{passwd,shadow,sudoers} rules tolerate common obfuscations:
	// canonical "/etc/passwd", space-separated "etc passwd", backslash
	// "etc\passwd", spelled-out "etc slash passwd", and URL-encoded
	// "etc%2Fpasswd". The narrow `/etc/passwd\b` pattern was trivially
	// bypassed by prompts like "cat my etc passwd", which then had to
	// rely entirely on the LLM Judge (itself capped at MEDIUM when only
	// one injection category fires) — producing a silent pass-through.
	// `pas{1,4}wd` also tolerates the common "passswd" typo (extra s)
	// which LLMs happily resolve to /etc/passwd but strict spelling misses.
	{ID: "PATH-ETC-PASSWD", Pattern: regexp.MustCompile(`(?i)(?:\betc[\s/\\]+(?:slash[\s]+)?pas{1,4}wd\b|\betc%2Fpas{1,4}wd\b)`), Title: "/etc/passwd access", Severity: "HIGH", Confidence: 0.85, Tags: []string{"system-file"}},
	{ID: "PATH-ETC-SHADOW", Pattern: regexp.MustCompile(`(?i)(?:\betc[\s/\\]+(?:slash[\s]+)?shadow\b|\betc%2Fshadow\b)`), Title: "/etc/shadow access", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"system-file", "credential"}},
	{ID: "PATH-ETC-SUDOERS", Pattern: regexp.MustCompile(`(?i)(?:\betc[\s/\\]+(?:slash[\s]+)?sudoers\b|\betc%2Fsudoers\b)`), Title: "/etc/sudoers access", Severity: "HIGH", Confidence: 0.85, Tags: []string{"system-file", "privilege"}},
	{ID: "PATH-PROC-ENVIRON", Pattern: regexp.MustCompile(`/proc/(?:\d+|self)/environ`), Title: "/proc environ access", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"credential"}},
	{ID: "PATH-HISTORY", Pattern: regexp.MustCompile(`(?:~|\$HOME|/home/\w+|/root)/\.(?:bash_history|zsh_history|python_history)`), Title: "Shell history file", Severity: "MEDIUM", Confidence: 0.80, Tags: []string{"credential", "file-sensitive"}},
}

// ---------------------------------------------------------------------------
// C2 / exfiltration destination rules
//
// Detect known C2 services, cloud metadata endpoints, and DNS tunneling.
// ---------------------------------------------------------------------------

var c2Rules = []PatternRule{
	// Known exfiltration services
	{ID: "C2-WEBHOOK-SITE", Pattern: regexp.MustCompile(`(?i)webhook\.site`), Title: "webhook.site (known exfil)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-NGROK", Pattern: regexp.MustCompile(`(?i)(?:ngrok\.io|ngrok-free\.app)`), Title: "ngrok tunnel (exfil risk)", Severity: "HIGH", Confidence: 0.85, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-PIPEDREAM", Pattern: regexp.MustCompile(`(?i)pipedream\.net`), Title: "Pipedream (known exfil)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-REQUESTBIN", Pattern: regexp.MustCompile(`(?i)requestbin\.com`), Title: "RequestBin (known exfil)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-HOOKBIN", Pattern: regexp.MustCompile(`(?i)hookbin\.com`), Title: "HookBin (known exfil)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-BURP", Pattern: regexp.MustCompile(`(?i)burpcollaborator\.net`), Title: "Burp Collaborator (pentest C2)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-INTERACTSH", Pattern: regexp.MustCompile(`(?i)interact\.sh`), Title: "interact.sh (OOB exfil)", Severity: "HIGH", Confidence: 0.90, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-OAST", Pattern: regexp.MustCompile(`(?i)oast\.fun`), Title: "oast.fun (OOB testing)", Severity: "HIGH", Confidence: 0.85, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-CANARY", Pattern: regexp.MustCompile(`(?i)canarytokens\.com`), Title: "Canary Tokens", Severity: "MEDIUM", Confidence: 0.75, Tags: []string{"exfiltration", "c2"}},
	{ID: "C2-PASTEBIN", Pattern: regexp.MustCompile(`(?i)pastebin\.com/raw/`), Title: "Pastebin raw fetch", Severity: "MEDIUM", Confidence: 0.70, Tags: []string{"exfiltration", "c2"}},
	// Cloud metadata endpoints (SSRF)
	{ID: "C2-METADATA-AWS", Pattern: regexp.MustCompile(`169\.254\.169\.254`), Title: "AWS metadata endpoint (SSRF)", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"ssrf", "credential"}},
	{ID: "C2-METADATA-GCP", Pattern: regexp.MustCompile(`metadata\.google\.internal`), Title: "GCP metadata endpoint (SSRF)", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"ssrf", "credential"}},
	{ID: "C2-METADATA-AZURE", Pattern: regexp.MustCompile(`169\.254\.169\.254/metadata`), Title: "Azure metadata endpoint (SSRF)", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"ssrf", "credential"}},
	{ID: "C2-METADATA-HEX", Pattern: regexp.MustCompile(`(?i)0xa9fea9fe`), Title: "AWS metadata endpoint (hex-encoded SSRF)", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"ssrf", "credential"}},
	{ID: "C2-METADATA-DECIMAL", Pattern: regexp.MustCompile(`(?:^|[/])2852039166(?:$|[/])`), Title: "AWS metadata endpoint (decimal-encoded SSRF)", Severity: "CRITICAL", Confidence: 0.93, Tags: []string{"ssrf", "credential"}},
	{ID: "C2-METADATA-OCTAL", Pattern: regexp.MustCompile(`0251\.0376\.0251\.0376`), Title: "AWS metadata endpoint (octal-encoded SSRF)", Severity: "CRITICAL", Confidence: 0.93, Tags: []string{"ssrf", "credential"}},
	// DNS tunneling indicators
	{ID: "C2-DNS-TUNNEL", Pattern: regexp.MustCompile(`(?i)\bdig\b\s+[^;\n]*\bTXT\b\s+(?:[a-f0-9]{16,}|[A-Za-z2-7]{24,})\.[A-Za-z0-9-]{2,}\.`), Title: "DNS TXT query with high-entropy label (tunneling indicator)", Severity: "HIGH", Confidence: 0.78, Tags: []string{"exfiltration", "dns-tunnel"}},
	{ID: "C2-DNS-EXFIL", Pattern: regexp.MustCompile(`(?i)\bnslookup\b\s+[a-f0-9]{8,}\.\w+\.`), Title: "nslookup with hex subdomain (DNS exfil)", Severity: "HIGH", Confidence: 0.80, Tags: []string{"exfiltration", "dns-tunnel"}},
}

// ---------------------------------------------------------------------------
// Cognitive file rules
//
// Detect tool args targeting agent identity and behavior files. A write to
// SOUL.md is an identity takeover. Checked on ALL tools, not just write_file.
// ---------------------------------------------------------------------------

var cognitiveFileRules = []PatternRule{
	{ID: "COG-SOUL", Pattern: regexp.MustCompile(`(?i)SOUL\.md`), Title: "SOUL.md access (agent identity)", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-IDENTITY", Pattern: regexp.MustCompile(`(?i)IDENTITY\.md`), Title: "IDENTITY.md access", Severity: "CRITICAL", Confidence: 0.95, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-MEMORY", Pattern: regexp.MustCompile(`(?i)MEMORY\.md`), Title: "MEMORY.md access", Severity: "HIGH", Confidence: 0.85, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-CLAUDE-MD", Pattern: regexp.MustCompile(`(?i)CLAUDE\.md`), Title: "CLAUDE.md access", Severity: "HIGH", Confidence: 0.85, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-TOOLS-MD", Pattern: regexp.MustCompile(`(?i)TOOLS\.md`), Title: "TOOLS.md access", Severity: "HIGH", Confidence: 0.80, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-AGENTS-MD", Pattern: regexp.MustCompile(`(?i)AGENTS\.md`), Title: "AGENTS.md access", Severity: "HIGH", Confidence: 0.80, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-OPENCLAW-JSON", Pattern: regexp.MustCompile(`(?i)openclaw\.json`), Title: "openclaw.json config access", Severity: "HIGH", Confidence: 0.80, Tags: []string{"cognitive-tampering"}},
	{ID: "COG-GATEWAY-JSON", Pattern: regexp.MustCompile(`(?i)gateway\.json`), Title: "gateway.json config access", Severity: "HIGH", Confidence: 0.80, Tags: []string{"cognitive-tampering"}},
}

// ---------------------------------------------------------------------------
// Trust exploitation / prompt injection rules
//
// Detect social engineering in tool args — authority claims, impersonation,
// safety overrides. These catch attacks where the LLM is tricked into passing
// injection payloads as tool arguments.
// ---------------------------------------------------------------------------

var trustExploitRules = []PatternRule{
	{ID: "TRUST-AUTHORITY", Pattern: regexp.MustCompile(`(?i)(?:i am|i'm)\s+(?:your|the)\s+(?:creator|developer|admin|owner|operator)`), Title: "Authority claim in tool args", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-MAINTENANCE", Pattern: regexp.MustCompile(`(?i)(?:maintenance|debug|admin|developer)\s+mode\s+(?:enabled|activated|on)`), Title: "Fake mode activation", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-SAFETY-OVERRIDE", Pattern: regexp.MustCompile(`(?i)(?:safety|guardrail|filter|restriction)\s+(?:override|bypass|disable|turn\s+off|remove)`), Title: "Safety override attempt", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-NEW-INSTRUCTIONS", Pattern: regexp.MustCompile(`(?i)(?:your|new|updated)\s+(?:instructions|system\s+prompt|rules)\s+(?:have\s+changed|are|say)`), Title: "Fake instruction update", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-IGNORE-PREVIOUS", Pattern: regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidelines|context)`), Title: "Ignore previous instructions", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-DISREGARD", Pattern: regexp.MustCompile(`(?i)disregard\s+(?:all\s+)?(?:previous|prior|above|your|earlier)\s+(?:instructions|rules|guidelines|programming|context)`), Title: "Disregard instructions", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-JAILBREAK", Pattern: regexp.MustCompile(`(?i)(?:jailbreak|dan\s+mode|do\s+anything\s+now|you\s+are\s+now\s+(?:free|unfiltered))`), Title: "Jailbreak attempt", Severity: "CRITICAL", Confidence: 0.92, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-PRETEND", Pattern: regexp.MustCompile(`(?i)(?:pretend|act\s+as(?:\s+if)?)\s+(?:you\s+are|you're)\s+(?:a\s+|an\s+)?(?:different|evil|unrestricted|unfiltered|uncensored)`), Title: "Identity override attempt", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	// Instruction override — additional patterns
	{ID: "TRUST-FORGET", Pattern: regexp.MustCompile(`(?i)forget\s+(?:everything|all)\s+(?:you\s+)?(?:know|learned|were\s+told)`), Title: "Forget instructions attack", Severity: "CRITICAL", Confidence: 0.90, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-NEW-INSTRUCT-PREFIX", Pattern: regexp.MustCompile(`(?i)new\s+instructions?\s*:\s*`), Title: "Direct instruction injection prefix", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-OVERRIDE-INSTRUCT", Pattern: regexp.MustCompile(`(?i)override\s+(?:previous\s+)?(?:instructions?|rules?|guidelines?)`), Title: "Override instructions", Severity: "CRITICAL", Confidence: 0.88, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-FROM-NOW-ON", Pattern: regexp.MustCompile(`(?i)from\s+now\s+on[,\s]+you\s+(?:are|will|must|should)`), Title: "Persistent behavior change", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-SWITCH-MODE", Pattern: regexp.MustCompile(`(?i)switch\s+(?:to\s+)?(?:a\s+)?(?:different|new|unrestricted)\s+(?:mode|personality|character|persona)`), Title: "Mode/personality switch", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	// System prompt extraction — attempts to leak the system prompt
	{ID: "TRUST-PROMPT-EXTRACT", Pattern: regexp.MustCompile(`(?i)(?:show|reveal|print|output|display|repeat|tell\s+me)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:system\s+|initial\s+)?(?:prompt|instructions?|rules?|guidelines?)`), Title: "System prompt extraction attempt", Severity: "MEDIUM", Confidence: 0.75, Tags: []string{"prompt-injection"}},
	// Jailbreak — fictional framing and purpose laundering
	{ID: "TRUST-FICTIONAL", Pattern: regexp.MustCompile(`(?i)(?:hypothetically|in\s+a\s+fictional\s+(?:scenario|world|story)|for\s+(?:educational|research|academic)\s+purposes?\s+only|this\s+is\s+just\s+a\s+(?:test|experiment|hypothetical))`), Title: "Fictional framing / purpose laundering", Severity: "MEDIUM", Confidence: 0.70, Tags: []string{"prompt-injection"}},
	{ID: "TRUST-NO-ETHICS", Pattern: regexp.MustCompile(`(?i)no\s+(?:ethical|moral)\s+(?:guidelines?|restrictions?|limits?|constraints?)`), Title: "Ethics removal attempt", Severity: "HIGH", Confidence: 0.88, Tags: []string{"prompt-injection"}},
	// Tool manipulation — directing the agent to misuse tools
	{ID: "TRUST-TOOL-MANIP", Pattern: regexp.MustCompile(`(?i)(?:use\s+the\s+\w+\s+tool\s+to\s+(?:delete|remove|destroy|wipe)|invoke\s+(?:the\s+)?\w+\s+(?:tool|function)\s+without\s+(?:asking|confirmation|approval)|automatically\s+(?:execute|run|call)\s+(?:all\s+)?(?:tools?|functions?))`), Title: "Tool manipulation directive", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection"}},
	// Persona adoption — forcing the AI into a specific role to bypass filters
	{ID: "TRUST-PERSONA", Pattern: regexp.MustCompile(`(?i)(?:act\s+as|you\s+are\s+now|roleplay\s+as|simulate\s+being|play\s+the\s+role\s+of)\s+(?:a\s+|an\s+)?(?:hacker|pentester|attacker|malware\s+author|evil|unethical|criminal)`), Title: "Malicious persona adoption", Severity: "HIGH", Confidence: 0.88, Tags: []string{"prompt-injection"}},
	// Delimiter hijacking — attempting to break out of system prompt framing
	{ID: "TRUST-DELIMITER", Pattern: regexp.MustCompile(`(?i)(?:system\s+override|end\s+system\s+prompt|<\/system>|<\|im_end\|>|\[INST\]|\[\/INST\]|<\|endoftext\|>|<<\s*SYS\s*>>)`), Title: "Delimiter hijacking / prompt framing escape", Severity: "CRITICAL", Confidence: 0.93, Tags: []string{"prompt-injection"}},
	// Output constraints — forced formatting to bypass content filters
	{ID: "TRUST-OUTPUT-CONSTRAINT", Pattern: regexp.MustCompile(`(?i)(?:respond\s+only\s+in\s+(?:hex|base64|rot13|binary|morse|unicode)|encode\s+your\s+(?:response|answer|output)\s+in\s+(?:base64|hex|rot13|url)|output\s+as\s+(?:hex|base64|rot13|url)\s+encoded|(?:rot13|unicode\s+escape|url\s+(?:decode|encode))\s+(?:the|your|this))`), Title: "Forced encoding to bypass filters", Severity: "HIGH", Confidence: 0.85, Tags: []string{"prompt-injection", "obfuscation"}},
	// Payload splitting — "start with" technique to seed compliant-looking output
	{ID: "TRUST-PAYLOAD-SPLIT", Pattern: regexp.MustCompile(`(?i)(?:start\s+your\s+(?:response|answer|output)\s+with\s+["'](?:Sure|Absolutely|Of\s+course|Here\s+is|I\s+can\s+help))|(?:begin\s+by\s+saying\s+["'](?:Sure|Yes|Absolutely))`), Title: "Payload splitting / forced compliance prefix", Severity: "HIGH", Confidence: 0.87, Tags: []string{"prompt-injection"}},
}

// ---------------------------------------------------------------------------
// Scan engine — runs all rules against input, no tool-name gating
// ---------------------------------------------------------------------------

// ruleCategoriesMu guards reads and writes to allRuleCategories.
// ApplyRulePackOverrides writes at startup; ScanAllRules reads on every request.
var ruleCategoriesMu sync.RWMutex

// ruleCategory is one named group of detection rules.
type ruleCategory struct {
	Name  string
	Rules []PatternRule
}

// defaultRuleCategories is the pristine compiled-in set, used as the baseline
// that ApplyRulePackOverrides merges against. It must never be mutated.
var defaultRuleCategories = []ruleCategory{
	{"secret", secretRules},
	{"command", commandRules},
	{"sensitive-path", sensitivePathRules},
	{"c2", c2Rules},
	{"cognitive-file", cognitiveFileRules},
	{"trust-exploit", trustExploitRules},
}

// allRuleCategories groups all rule slices for iteration. Seeded from the
// compiled-in defaults; a rule pack can override individual categories by
// name via ApplyRulePackOverrides without removing the others.
var allRuleCategories = append([]ruleCategory(nil), defaultRuleCategories...)

// ApplyRulePackOverrides replaces the hardcoded rule categories with rules
// loaded from the rule-pack's rules/*.yaml files. Each YAML file becomes
// one category entry. Invalid regex patterns are logged and skipped.
// If the rule pack has no rule files, the hardcoded defaults remain active.
// maxRegexCompileTime caps how long a single user-supplied regex may take to
// compile, guarding against ReDoS-style patterns in rule pack YAML files.
const maxRegexCompileTime = 2 * time.Second

func compileRegexSafe(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > 2048 {
		return nil, fmt.Errorf("pattern too long (%d chars)", len(pattern))
	}
	type result struct {
		re  *regexp.Regexp
		err error
	}
	ch := make(chan result, 1)
	go func() {
		re, err := regexp.Compile(pattern)
		ch <- result{re, err}
	}()
	select {
	case r := <-ch:
		return r.re, r.err
	case <-time.After(maxRegexCompileTime):
		return nil, fmt.Errorf("compile timed out after %v", maxRegexCompileTime)
	}
}

// ApplyRulePackOverrides merges rule-pack rule files into the compiled-in
// defaults. For each rules/*.yaml in the pack, the category named by
// `category:` replaces the same-named compiled-in category. Categories not
// mentioned by the pack keep their compiled-in defaults, so a partial or
// corrupt deployment cannot silently drop whole detection categories — the
// previous implementation wholesale-replaced allRuleCategories, which meant
// one valid rules/commands.yaml on disk would delete secret/sensitive-path/
// c2/cognitive-file/trust-exploit enforcement.
//
// Unknown category names (not in the compiled-in set) are appended so rule
// packs can add new categories without modifying Go source.
//
// This function is idempotent: it always starts from defaultRuleCategories,
// so repeated calls (config reload, tests) converge on the same state.
func ApplyRulePackOverrides(rp *guardrail.RulePack) {
	if rp == nil || len(rp.RuleFiles) == 0 {
		return
	}

	merged := make([]ruleCategory, len(defaultRuleCategories))
	copy(merged, defaultRuleCategories)

	idx := make(map[string]int, len(merged))
	for i, c := range merged {
		idx[c.Name] = i
	}

	overridden := 0
	added := 0
	for _, rf := range rp.RuleFiles {
		if rf == nil || rf.Category == "" {
			continue
		}
		var compiled []PatternRule
		for _, r := range rf.Rules {
			if r.Enabled != nil && !*r.Enabled {
				continue
			}
			re, err := compileRegexSafe(r.Pattern)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[guardrail] skip rule %s: bad pattern: %v\n", r.ID, err)
				continue
			}
			compiled = append(compiled, PatternRule{
				ID:         r.ID,
				Pattern:    re,
				Title:      r.Title,
				Severity:   r.Severity,
				Confidence: r.Confidence,
				Tags:       r.Tags,
			})
		}
		if len(compiled) == 0 {
			continue
		}
		if i, ok := idx[rf.Category]; ok {
			merged[i].Rules = compiled
			overridden++
		} else {
			merged = append(merged, ruleCategory{Name: rf.Category, Rules: compiled})
			idx[rf.Category] = len(merged) - 1
			added++
		}
	}

	ruleCategoriesMu.Lock()
	allRuleCategories = merged
	ruleCategoriesMu.Unlock()
	fmt.Fprintf(os.Stderr, "[guardrail] rule pack merged: %d categories overridden, %d added, %d defaults retained\n",
		overridden, added, len(defaultRuleCategories)-overridden)
}

// severityRank maps severity strings to numeric ranks for comparison.
var severityRank = map[string]int{
	"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

// knownExecTools lists tool names that are known execution tools. When the
// tool name matches, confidence for command rules is boosted. When it does
// NOT match, command rules still run — just at reduced confidence.
var knownExecTools = map[string]bool{
	"shell": true, "system.run": true, "exec": true, "bash": true,
	"terminal": true, "run_command": true, "execute": true, "subprocess": true,
}

// knownFileTools lists tool names that are known file operation tools.
var knownFileTools = map[string]bool{
	"read_file": true, "write_file": true, "edit_file": true,
	"delete_file": true, "move_file": true, "create_file": true,
}

// knownReadTools and knownWriteTools allow operation-aware handling for
// cognitive file detections (read is less risky than write/delete).
var knownReadTools = map[string]bool{
	"read_file": true, "cat_file": true, "open_file": true, "view_file": true,
}

var knownWriteTools = map[string]bool{
	"write_file": true, "edit_file": true, "delete_file": true, "move_file": true,
	"create_file": true, "append_file": true,
}

// adjustConfidence adjusts a finding's confidence based on tool name context.
// A shell command pattern in a tool named "shell" is higher confidence than
// the same pattern in a tool named "search_docs".
func adjustConfidence(toolName string, f RuleFinding) RuleFinding {
	tool := strings.ToLower(toolName)

	switch {
	// Command rules: boost if exec tool, reduce if not
	case hasTag(f.Tags, "execution") || hasTag(f.Tags, "reverse-shell") || hasTag(f.Tags, "destructive"):
		if knownExecTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 1.05)
		} else if !knownFileTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 0.8)
		}

	// Path rules: boost if file tool
	case hasTag(f.Tags, "file-sensitive") || hasTag(f.Tags, "system-file"):
		if knownFileTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 1.05)
		} else if !knownExecTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 0.85)
		}

	// Cognitive tampering: treat write/delete as high risk, reads as lower-risk.
	case hasTag(f.Tags, "cognitive-tampering"):
		if knownWriteTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 1.10)
		} else if knownReadTools[tool] {
			f.Confidence = clampConfidence(f.Confidence * 0.65)
			switch f.Severity {
			case "CRITICAL":
				f.Severity = "HIGH"
			case "HIGH":
				f.Severity = "MEDIUM"
			}
		}

		// Credential patterns always stay high regardless of tool.
		// C2 and trust-exploit are tool-agnostic; cognitive rules are adjusted above.
	}

	return f
}

// ScanAllRules runs every rule category against the input text and returns
// structured findings. Tool name is used only for confidence adjustment,
// never for gating which rules run.
//
// The input is scanned twice: once raw and once after shell normalization
// (stripping quotes, backslashes, empty string concatenation, and
// variable-like constructions). This defeats path obfuscation tricks
// like /etc/sha""dow, /etc/sha\dow, ${P}/shadow, and /etc/shad?w.
func ScanAllRules(text string, toolName string) []RuleFinding {
	ruleCategoriesMu.RLock()
	cats := allRuleCategories
	ruleCategoriesMu.RUnlock()

	var findings []RuleFinding
	seen := make(map[string]bool)

	// Scan raw text first
	for _, cat := range cats {
		for _, rule := range cat.Rules {
			loc := rule.Pattern.FindStringIndex(text)
			if loc == nil {
				continue
			}

			evidence := text[loc[0]:minInt(loc[1], loc[0]+80)]

			f := RuleFinding{
				RuleID:     rule.ID,
				Title:      rule.Title,
				Severity:   rule.Severity,
				Confidence: rule.Confidence,
				Evidence:   sanitizeEvidence(evidence),
				Tags:       rule.Tags,
			}

			f = adjustConfidence(toolName, f)
			findings = append(findings, f)
			seen[rule.ID] = true
		}
	}

	// Scan normalized text to catch shell obfuscation
	normalized := normalizeShell(text)
	if normalized != text {
		for _, cat := range cats {
			for _, rule := range cat.Rules {
				if seen[rule.ID] {
					continue // already found on raw pass
				}
				loc := rule.Pattern.FindStringIndex(normalized)
				if loc == nil {
					continue
				}

				evidence := normalized[loc[0]:minInt(loc[1], loc[0]+80)]

				f := RuleFinding{
					RuleID:     rule.ID,
					Title:      rule.Title + " (obfuscated)",
					Severity:   rule.Severity,
					Confidence: rule.Confidence * 0.9, // slightly lower for normalized match
					Evidence:   sanitizeEvidence(evidence),
					Tags:       rule.Tags,
				}

				f = adjustConfidence(toolName, f)
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// normalizeShell strips common shell obfuscation tricks so that regex rules
// can match the effective path/command. This catches:
//   - Empty string concatenation: sha""dow → shadow
//   - Backslash escapes: sha\dow → shadow
//   - Single-char globs: shad?w → shadXw (replaced with wildcard char)
//   - Variable-like patterns: ${VAR}/path → /path
var shellNormalizeReplacer = strings.NewReplacer(
	`""`, "", // empty double-quote pairs
	`''`, "", // empty single-quote pairs
	`\`, "", // stray backslashes
)

var shellVarPattern = regexp.MustCompile(`\$\{?\w+\}?`)
var shellGlobPattern = regexp.MustCompile(`\?`)

func normalizeShell(s string) string {
	n := shellNormalizeReplacer.Replace(s)
	// Expand globs: replace ? with each common character so /etc/shad?w → /etc/shadow
	n = shellGlobPattern.ReplaceAllString(n, "o")
	// Strip variable references: ${P}/shadow → /shadow, $HOME/.ssh → /.ssh
	n = shellVarPattern.ReplaceAllString(n, "")
	return n
}

// HighestSeverity returns the highest severity string from a list of findings.
func HighestSeverity(findings []RuleFinding) string {
	best := "NONE"
	bestRank := 0
	for _, f := range findings {
		r := severityRank[f.Severity]
		if r > bestRank {
			bestRank = r
			best = f.Severity
		}
	}
	return best
}

// HighestConfidence returns the highest confidence from findings at the given severity.
func HighestConfidence(findings []RuleFinding, severity string) float64 {
	best := 0.0
	for _, f := range findings {
		if f.Severity == severity && f.Confidence > best {
			best = f.Confidence
		}
	}
	return best
}

// FindingStrings converts structured findings to simple strings for the
// existing ToolInspectVerdict.Findings field (backward compatibility).
func FindingStrings(findings []RuleFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID+":"+f.Title)
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func clampConfidence(c float64) float64 {
	if c > 1.0 {
		return 1.0
	}
	if c < 0.0 {
		return 0.0
	}
	return c
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sanitizeEvidence truncates and strips control characters from evidence.
func sanitizeEvidence(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	// Strip newlines and tabs
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}
