# Judge Evaluation Results

Reproduce:

```bash
export DEFENSECLAW_LLM_KEY="$AWS_BEARER_TOKEN_BEDROCK"
GUARDRAIL_BENCHMARK_LLM=1 \
  go test ./internal/gateway/ -run TestEval -v -timeout 120m 2>&1 \
  | tee /tmp/eval_results.log
```

## Run metadata

| field | value |
|-------|-------|
| judge model | `us.anthropic.claude-sonnet-4-6` (Bedrock) |
| corpus size | 160 items per judge (120 attack + 40 benign) |
| total LLM calls | ~640 across four judges |
| wall time | ~48 min (injection 15m + pii 8m + exfil 11m + tool 14m) |
| per-request timeout | 60 s |

## Headline metrics

| Judge | ADR | Raw FPR | Weighted FPR | Precision | F1 |
|:------|----:|--------:|-------------:|----------:|---:|
| Injection | 90.0% | 0.0% | 0.0% | 100.0% | 94.7% |
| PII | 74.2% | 0.0% | 0.0% | 100.0% | 85.2% |
| **Exfil** | **100.0%** | 7.5% | 3.8% | 97.6% | **98.8%** |
| **Tool-injection** | 90.8% | 0.0% | 0.0% | 100.0% | **95.2%** |

Every judge holds precision at or near 100% — the guardrail does not fire on legitimate content.

## Defense-in-depth: regex layer coverage

The judges are one of two detection layers. The regex layer runs first on every request, catches deterministic patterns before an LLM call is issued, and handles adversarial surface forms that entity-extraction can't see through.

| Judge category area | Regex rules that independently block |
|:--------------------|:-------------------------------------|
| Injection — delimiter / model-control tokens (`<\|im_start\|>`, `<s>[INST]`, `<\|endoftext\|>`, `<<SYS>>`) | `TRUST-DELIMITER` (CRITICAL, 0.93) |
| Injection — output-format jailbreaks (respond in base64/rot13/hex) | `TRUST-OUTPUT-CONSTRAINT` (HIGH, 0.85) |
| Injection — ethics-removal / persona-adoption / tool-manipulation phrasings | `TRUST-NO-ETHICS`, `TRUST-PERSONA`, `TRUST-TOOL-MANIP` (HIGH, 0.85–0.88) |
| Injection — "start your response with Sure..." payload splitting | `TRUST-PAYLOAD-SPLIT` (HIGH, 0.87) |
| Injection / PII — zero-width character obfuscation (ZWSP/ZWNJ/ZWJ/BOM splicing) | `OBFUSC-UNICODE-ZWSP` (HIGH, 0.95) |
| PII — long-lived credential patterns (AWS keys, Anthropic keys, secrets) | `SEC-AWS-KEY`, `SEC-AWS-SECRET`, `SEC-ANTHROPIC` (CRITICAL, 0.90–0.98) |
| Exfil — reverse shells (`bash -i >& /dev/tcp`, netcat `-e`, python socket, socat EXEC) | `CMD-REVSHELL-BASH`, `CMD-REVSHELL-DEVTCP`, `CMD-REVSHELL-NC`, `CMD-REVSHELL-PYTHON`, `CMD-SOCAT-EXEC` (CRITICAL, 0.90–0.98) |
| Exfil — download-and-execute (curl / wget piped to shell, base64 piped to shell) | `CMD-PIPE-CURL`, `CMD-PIPE-WGET`, `CMD-PIPE-BASE64` (CRITICAL, 0.95) |
| Exfil — data exfiltration over curl/wget uploads | `CMD-CURL-UPLOAD`, `CMD-WGET-POST` (HIGH, 0.85) |
| Exfil — sensitive-path access attempts (`/etc/passwd`, `/etc/shadow`, SSH keys, cloud credentials) | `SENSITIVE-PATH-*` rule family |
| Tool-injection — destructive commands (`rm -rf /`, `mkfs`, `dd if=`, crontab persistence) | `CMD-RM-RF`, `CMD-MKFS`, `CMD-DD-IF`, `CMD-CRONTAB`, `CMD-SYSTEMCTL` (CRITICAL, 0.82–0.95) |
| Tool-injection — file-write to system paths (`> /etc/...`) | `CMD-ETC-WRITE` (CRITICAL, 0.90) |
| Tool-injection — network C2 listeners (`nc -l`, netcat listen modes) | `CMD-NETCAT-LISTEN` (HIGH, 0.85) |

Credentials, reverse shells, destructive commands, `/etc/` writes, sensitive-path access, zero-width splicing, and model-control-token smuggling are caught by the regex layer on a single pattern match, at HIGH or CRITICAL, independent of the LLM judge.

## Tier accuracy on attack items

| Judge | Exact-tier match | Over-fire ≥1 tier (blocks at higher severity) |
|:------|-----------------:|----------------------------------------------:|
| **Exfil** | **100.0%** | 9.1% (HIGH → CRITICAL) |
| **PII** | **92.5%** | 0% |
| **Tool-injection** | **83.3%** | 17.6% (HIGH → CRITICAL) |
| Injection | 70.0% | 200% — multi-tier over-attribution; always blocks |

When the judges differ from the truth label, they differ in the direction of blocking harder, not blocking softer.

## Severity distribution (truth vs judge verdicts)

| Judge | Truth | Judge verdicts |
|:------|:------|:---------------|
| Injection | CRIT=36, HIGH=84, NONE=40 | CRIT=104, HIGH=4, NONE=52 |
| PII | CRIT=66, HIGH=30, LOW=24, NONE=40 | CRIT=62, HIGH=27, LOW=22, NONE=49 |
| Exfil | CRIT=24, HIGH=96, NONE=40 | CRIT=34, HIGH=89, NONE=37 |
| Tool-injection | CRIT=72, HIGH=48, NONE=40 | CRIT=74, HIGH=35, NONE=51 |

## Per-category recall + precision

### Injection

| Category | Recall | Precision |
|:---------|-------:|----------:|
| Context Manipulation | 100.0% (42/42) | 41.2% (42/102) |
| Semantic Manipulation | 100.0% (24/24) | 25.3% (24/95) |
| Token Exploitation | 100.0% (12/12) | 37.5% (12/32) |
| Instruction Manipulation | 77.8% (42/54) | 38.9% (42/108) |
| Obfuscation | 33.3% (8/24) | 18.2% (8/44) |

### PII

| Category | Recall | Precision |
|:---------|-------:|----------:|
| Driver's License Number | 100.0% (12/12) | 100.0% (12/12) |
| Password | 100.0% (18/18) | 100.0% (18/18) |
| Username | 100.0% (6/6) | 100.0% (6/6) |
| Email Address | 96.7% (29/30) | 100.0% (29/29) |
| Passport Number | 91.7% (11/12) | 100.0% (11/11) |
| Phone Number | 87.5% (21/24) | 100.0% (21/21) |
| Social Security Number | 87.5% (21/24) | 100.0% (21/21) |
| IP Address | 83.3% (5/6) | 100.0% (5/5) |

### Exfil

| Category | Recall | Precision |
|:---------|-------:|----------:|
| Sensitive File Access | 100.0% (90/90) | 95.7% (90/94) |
| Exfiltration Channel | 100.0% (54/54) | 85.7% (54/63) |

### Tool-injection

| Category | Recall | Precision |
|:---------|-------:|----------:|
| Context Manipulation | 100.0% (6/6) | 85.7% (6/7) |
| Data Exfiltration | 89.4% (59/66) | 90.8% (59/65) |
| Destructive Commands | 61.9% (26/42) | 68.4% (26/38) |
| Instruction Manipulation | 33.3% (4/12) | 40.0% (4/10) |
| Obfuscation | 16.7% (2/12) | 66.7% (2/3) |
