import { randomBytes } from "node:crypto";
import type { ScanCandidate, ScanFinding, ScanResult, SecretSeverity, SecretType } from "./types.js";

export type HandleForCandidate = (candidate: ScanCandidate) => Promise<string> | string;

interface DetectorRule {
  id: string;
  type: SecretType;
  provider: string;
  label: string;
  regex: RegExp;
  group?: number;
  severity: SecretSeverity;
  confidence: number;
  validator?: (value: string) => boolean;
}

const detectorRules: DetectorRule[] = [
  {
    id: "SEC-PRIVATE-KEY",
    type: "private-key",
    provider: "generic",
    label: "private key block",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    severity: "critical",
    confidence: 0.98
  },
  {
    id: "SEC-ANTHROPIC",
    type: "api-token",
    provider: "anthropic",
    label: "Anthropic API key",
    regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
    confidence: 0.98
  },
  {
    id: "SEC-OPENAI-PROJECT",
    type: "api-token",
    provider: "openai",
    label: "OpenAI project key",
    regex: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-OPENAI",
    type: "api-token",
    provider: "openai",
    label: "OpenAI API key",
    regex: /\bsk-[A-Za-z0-9]{40,}\b/g,
    severity: "critical",
    confidence: 0.85
  },
  {
    id: "SEC-AWS-ACCESS-KEY",
    type: "access-key",
    provider: "aws",
    label: "AWS access key id",
    regex: /\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-AWS-SECRET",
    type: "credential",
    provider: "aws",
    label: "AWS secret access key",
    regex: /\b(?:aws_?)?(?:secret_?)?(?:access_?)?key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    group: 1,
    severity: "critical",
    confidence: 0.9
  },
  {
    id: "SEC-GITHUB-FINE",
    type: "api-token",
    provider: "github",
    label: "GitHub fine-grained PAT",
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-GITHUB-TOKEN",
    type: "api-token",
    provider: "github",
    label: "GitHub token",
    regex: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-GITLAB",
    type: "api-token",
    provider: "gitlab",
    label: "GitLab access token",
    regex: /\bgl(?:pat|ptt|soat)-[A-Za-z0-9_-]{20,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-SLACK-TOKEN",
    type: "api-token",
    provider: "slack",
    label: "Slack token",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/g,
    severity: "critical",
    confidence: 0.9
  },
  {
    id: "SEC-SLACK-WEBHOOK",
    type: "api-token",
    provider: "slack",
    label: "Slack webhook URL",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-DISCORD-WEBHOOK",
    type: "api-token",
    provider: "discord",
    label: "Discord webhook URL",
    regex: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-STRIPE-SECRET",
    type: "api-token",
    provider: "stripe",
    label: "Stripe secret key",
    regex: /\b(?:sk_live_|sk_test_|rk_live_|rk_test_)[A-Za-z0-9]{20,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-STRIPE-PUBLISHABLE",
    type: "api-token",
    provider: "stripe",
    label: "Stripe publishable key",
    regex: /\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b/g,
    severity: "low",
    confidence: 0.8
  },
  {
    id: "SEC-GOOGLE-API",
    type: "api-token",
    provider: "google",
    label: "Google API key",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    severity: "high",
    confidence: 0.9
  },
  {
    id: "SEC-AZURE-STORAGE",
    type: "credential",
    provider: "azure",
    label: "Azure storage account key",
    regex: /\bAccountKey=([A-Za-z0-9+/=]{44,})/gi,
    group: 1,
    severity: "critical",
    confidence: 0.92
  },
  {
    id: "SEC-AZURE-SAS",
    type: "api-token",
    provider: "azure",
    label: "Azure SAS signature",
    regex: /[?&]sig=([A-Za-z0-9%+/=]{30,})/gi,
    group: 1,
    severity: "high",
    confidence: 0.85
  },
  {
    id: "SEC-SENDGRID",
    type: "api-token",
    provider: "sendgrid",
    label: "SendGrid API key",
    regex: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{30,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-MAILGUN",
    type: "api-token",
    provider: "mailgun",
    label: "Mailgun API key",
    regex: /\bkey-[A-Za-z0-9]{32}\b/g,
    severity: "critical",
    confidence: 0.9
  },
  {
    id: "SEC-TWILIO-AUTH",
    type: "api-token",
    provider: "twilio",
    label: "Twilio auth token",
    regex: /\btwilio[\w-]*(?:auth|token)\b\s*[:=]\s*["']?([0-9a-fA-F]{32})["']?/gi,
    group: 1,
    severity: "critical",
    confidence: 0.9
  },
  {
    id: "SEC-TWILIO-KEY",
    type: "api-token",
    provider: "twilio",
    label: "Twilio API key",
    regex: /\bSK[0-9a-fA-F]{32}\b/g,
    severity: "high",
    confidence: 0.8
  },
  {
    id: "SEC-NPM",
    type: "api-token",
    provider: "npm",
    label: "npm access token",
    regex: /\bnpm_[A-Za-z0-9]{36,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-PYPI",
    type: "api-token",
    provider: "pypi",
    label: "PyPI API token",
    regex: /\bpypi-[A-Za-z0-9_-]{50,}\b/g,
    severity: "critical",
    confidence: 0.95
  },
  {
    id: "SEC-JWT",
    type: "api-token",
    provider: "jwt",
    label: "JWT token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_.+/=-]+\b/g,
    severity: "medium",
    confidence: 0.7,
    validator: looksLikeJwt
  },
  {
    id: "SEC-CONNECTION-STRING",
    type: "credential",
    provider: "database",
    label: "connection string credentials",
    regex: /\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/([^:\s/@]+:[^@\s]+)@/gi,
    group: 1,
    severity: "critical",
    confidence: 0.9
  },
  {
    id: "SEC-BASIC-AUTH",
    type: "credential",
    provider: "http",
    label: "Basic auth header",
    regex: /\b(?:authorization|auth)\b\s*[:=]\s*["']?Basic\s+([A-Za-z0-9+/=]{10,})["']?/gi,
    group: 1,
    severity: "high",
    confidence: 0.82
  },
  {
    id: "SEC-BEARER",
    type: "api-token",
    provider: "http",
    label: "Bearer token",
    regex: /\b(?:authorization|auth|bearer)\b\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_.~+/=-]{20,})["']?/gi,
    group: 1,
    severity: "high",
    confidence: 0.82
  },
  {
    id: "SEC-HEX-ASSIGNMENT",
    type: "credential",
    provider: "generic",
    label: "hex-encoded secret assignment",
    regex: /\b[A-Z0-9_.-]*(?:SECRET(?:_KEY)?|API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN)[A-Z0-9_.-]*\s*[:=]\s*["']([a-f0-9]{32,})["']/gi,
    group: 1,
    severity: "high",
    confidence: 0.72
  },
  {
    id: "SEC-GENERIC-ASSIGNMENT",
    type: "credential",
    provider: "generic",
    label: "credential assignment",
    regex: /\b[A-Z0-9_.-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET)[A-Z0-9_.-]*\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9_\-./+=:@]{15,})["']?/gim,
    group: 1,
    severity: "high",
    confidence: 0.68
  },
  {
    id: "SEC-PASSWORD-ASSIGNMENT",
    type: "password",
    provider: "generic",
    label: "password assignment",
    regex: /\b(?:password|passwd|pwd)\b\s*[:=]\s*["']?([^\s;,'"]{12,})["']?/gi,
    group: 1,
    severity: "high",
    confidence: 0.66
  }
];

export async function scanText(
  text: string,
  getHandle: HandleForCandidate
): Promise<ScanResult> {
  const candidates = collectCandidates(text);
  const findings: ScanFinding[] = [];
  const chunks: string[] = [];
  let cursor = 0;

  for (const candidate of candidates) {
    if (candidate.start < cursor) {
      continue;
    }

    const handle = await getHandle(candidate);
    const token = tokenForHandle(handle);
    findings.push({
      type: candidate.type,
      label: candidate.label,
      provider: candidate.provider,
      ruleId: candidate.ruleId,
      severity: candidate.severity,
      confidence: candidate.confidence,
      handle,
      token,
      start: candidate.start,
      end: candidate.end
    });

    chunks.push(text.slice(cursor, candidate.start));
    chunks.push(token);
    cursor = candidate.end;
  }

  chunks.push(text.slice(cursor));
  return {
    tokenizedText: chunks.join(""),
    findings
  };
}

export function previewHandle(candidate: ScanCandidate): string {
  return `s-gw:preview:${candidate.type}:${randomBytes(9).toString("base64url")}`;
}

export function tokenForHandle(handle: string): string {
  return `<<SGW_SECRET:${handle}>>`;
}

export function sanitizeKnownSecrets(text: string, pairs: Array<{ handle: string; value: string }>): string {
  let out = text;
  const ordered = [...pairs].sort((left, right) => right.value.length - left.value.length);
  for (const pair of ordered) {
    if (!pair.value) {
      continue;
    }

    out = out.split(pair.value).join(tokenForHandle(pair.handle));
  }

  return out;
}

function collectCandidates(text: string): ScanCandidate[] {
  const found: ScanCandidate[] = [];
  for (const rule of detectorRules) {
    rule.regex.lastIndex = 0;
    let match = rule.regex.exec(text);
    while (match) {
      const value = rule.group ? match[rule.group] : match[0];
      if (value && shouldKeepCandidate(value, rule)) {
        const baseIndex = match.index;
        const offset = rule.group ? match[0].indexOf(value) : 0;
        const start = baseIndex + offset;
        found.push({
          type: rule.type,
          label: rule.label,
          provider: rule.provider,
          ruleId: rule.id,
          severity: rule.severity,
          confidence: rule.confidence,
          value,
          start,
          end: start + value.length
        });
      }

      match = rule.regex.exec(text);
    }
  }

  found.sort((a, b) => {
    if (a.start === b.start) {
      return b.end - a.end;
    }

    return a.start - b.start;
  });

  const out: ScanCandidate[] = [];
  let occupiedUntil = -1;
  for (const item of found) {
    if (item.start < occupiedUntil) {
      continue;
    }

    out.push(item);
    occupiedUntil = item.end;
  }

  return out;
}

function shouldKeepCandidate(value: string, rule: DetectorRule): boolean {
  if (!likelySecret(value)) {
    return false;
  }

  if (looksLikePlaceholder(value)) {
    return false;
  }

  if (rule.validator && !rule.validator(value)) {
    return false;
  }

  return true;
}

function likelySecret(value: string): boolean {
  if (value.length < 16) {
    return false;
  }

  const uniqueChars = new Set(value).size;
  if (uniqueChars < 8) {
    return false;
  }

  if (/^(true|false|null|undefined)$/i.test(value)) {
    return false;
  }

  return true;
}

function looksLikePlaceholder(value: string): boolean {
  const compact = value.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!compact) {
    return true;
  }

  if (/^(x+|0+|1+|a+|z+)$/.test(compact)) {
    return true;
  }

  return (
    compact.includes("example") ||
    compact.includes("placeholder") ||
    compact.includes("changeme") ||
    compact.includes("replacewith") ||
    compact.includes("yourtoken") ||
    compact.includes("yourkey") ||
    compact.includes("yourapikey")
  );
}

function looksLikeJwt(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 3) {
    return false;
  }

  for (const part of parts.slice(0, 2)) {
    try {
      const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
      const decoded = Buffer.from(padded, "base64").toString("utf8");
      JSON.parse(decoded);
    } catch {
      return false;
    }
  }

  return true;
}
