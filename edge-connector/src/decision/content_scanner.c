/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "content_scanner.h"
#include "policy_tables.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
/* === Helper Functions === */

#if DCLAW_CONTENT_SCAN

/**
 * Add a finding to the scan context if there's room.
 * Returns true if added, false if findings array is full.
 */
static bool add_finding(dclaw_scan_context_t *ctx,
                       dclaw_content_category_t category,
                       dclaw_severity_t severity,
                       uint16_t offset) {
    if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) {
        return false;
    }

    ctx->findings[ctx->finding_count].category = category;
    ctx->findings[ctx->finding_count].severity = severity;
    ctx->findings[ctx->finding_count].offset = offset;
    ctx->finding_count++;
    return true;
}

/**
 * Check if a character is a word boundary (whitespace, punctuation, or control char).
 */
static bool is_boundary(char c) {
    return c == '\0' || c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
           c == ',' || c == ';' || c == ':' || c == '.' || c == '!' ||
           c == '?' || c == '"' || c == '\'' || c == '(' || c == ')' ||
           c == '[' || c == ']' || c == '{' || c == '}' || c == '<' ||
           c == '>' || c == '/' || c == '\\' || c == '|' || c == '&' ||
           c == '=' || c == '+' || c == '-' || c == '*' || c == '%' ||
           c == '#' || c == '@' || c == '`' || c == '~';
}

/* ================================================================== */
/*  Aho-Corasick DFA Scanner (O(n) single-pass)                       */
/* ================================================================== */

#ifdef DCLAW_AC_DFA_AVAILABLE

/**
 * Run the compiled Aho-Corasick DFA over the content in a single pass.
 * For each byte the DFA transitions deterministically; when a match
 * state is reached, each emitted pattern is recorded via add_finding().
 *
 * Pattern flags control boundary semantics:
 *   0 = word-boundary required before the match start
 *   1 = substring match (no boundary check)
 *   2 = needs_suffix (reserved, currently unused)
 */
static void scan_dfa(const char *content, uint16_t content_len,
                     dclaw_scan_context_t *ctx) {
    uint16_t state = 0;

    for (uint16_t i = 0; i < content_len; i++) {
        uint8_t byte_val = (uint8_t)tolower((unsigned char)content[i]);
        state = ac_transitions[state][byte_val];

        /* Check for matches at this state */
        if (ac_match_index[state].count > 0) {
            uint16_t off = ac_match_index[state].offset;
            uint8_t  cnt = ac_match_index[state].count;

            for (uint8_t m = 0; m < cnt; m++) {
                uint8_t pid = ac_match_pids[off + m];
                const dclaw_ac_pattern_t *pat = &ac_patterns[pid];

                /* Calculate the start position of this match */
                uint16_t match_start = (i + 1 >= pat->pat_len)
                                     ? (i + 1 - pat->pat_len)
                                     : 0;

                /* For word-boundary patterns (flags==0), verify boundary
                   before the match start position. */
                if (pat->flags == 0 && match_start > 0 &&
                    !is_boundary(content[match_start - 1])) {
                    continue;
                }

                add_finding(ctx,
                           (dclaw_content_category_t)pat->category,
                           (dclaw_severity_t)pat->severity,
                           match_start);

                if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) {
                    return;
                }
            }
        }
    }
}

#endif /* DCLAW_AC_DFA_AVAILABLE */

/* ================================================================== */
/*  Manual (fallback) scanners — used when DFA tables not available    */
/*  or for structural patterns (PII formats, exfil heuristics)        */
/* ================================================================== */

/* Manual keyword scanners — only compiled when DFA is NOT available */
#ifndef DCLAW_AC_DFA_AVAILABLE

/**
 * Check if a pattern matches at the given position with word boundaries.
 */
static bool matches_pattern_at(const char *content, uint16_t pos, uint16_t content_len,
                               const char *pattern, uint16_t pattern_len) {
    /* Check if there's enough space */
    if (pos + pattern_len > content_len) {
        return false;
    }

    /* Check for word boundary before (unless at start) */
    if (pos > 0 && !is_boundary(content[pos - 1])) {
        return false;
    }

    /* Check for word boundary after (unless at end) */
    if (pos + pattern_len < content_len && !is_boundary(content[pos + pattern_len])) {
        return false;
    }

    /* Case-insensitive comparison */
    for (uint16_t i = 0; i < pattern_len; i++) {
        if (tolower((unsigned char)content[pos + i]) != tolower((unsigned char)pattern[i])) {
            return false;
        }
    }

    return true;
}

/**
 * Scan for SECRET patterns (API keys, tokens, private keys).
 */
static void scan_secrets(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    const char *secret_patterns[] = {
        "api_key", "apikey", "api-key",
        "secret_key", "secretkey", "secret-key",
        "private_key", "privatekey", "private-key",
        "access_token", "accesstoken", "access-token",
        "bearer_token", "bearertoken", "bearer-token",
        "password", "passwd",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----"
    };
    const uint8_t num_patterns = sizeof(secret_patterns) / sizeof(secret_patterns[0]);

    for (uint16_t i = 0; i < content_len; i++) {
        for (uint8_t p = 0; p < num_patterns; p++) {
            const char *pattern = secret_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            if (matches_pattern_at(content, i, content_len, pattern, pattern_len)) {
                add_finding(ctx, DCLAW_CONTENT_CATEGORY_SECRET, DCLAW_SEV_HIGH, i);
                i += pattern_len - 1; /* Skip past this match */
                break;
            }
        }
        if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) break;
    }
}

#endif /* !DCLAW_AC_DFA_AVAILABLE (keyword scanners) */

/**
 * Scan for PII patterns (SSN, email, phone, credit card).
 *
 * These are structural/regex-like patterns that the DFA does not cover,
 * so this scanner always runs regardless of DFA availability.
 */
static void scan_pii(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    /* Look for SSN pattern: XXX-XX-XXXX */
    for (uint16_t i = 0; i + 10 < content_len; i++) {
        if (isdigit((unsigned char)content[i]) && isdigit((unsigned char)content[i+1]) && isdigit((unsigned char)content[i+2]) &&
            content[i+3] == '-' &&
            isdigit((unsigned char)content[i+4]) && isdigit((unsigned char)content[i+5]) &&
            content[i+6] == '-' &&
            isdigit((unsigned char)content[i+7]) && isdigit((unsigned char)content[i+8]) &&
            isdigit((unsigned char)content[i+9]) && isdigit((unsigned char)content[i+10])) {
            add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_CRITICAL, i);
            if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
        }
    }

    /* Look for email patterns: contains @ with text before and after */
    for (uint16_t i = 1; i + 1 < content_len; i++) {
        if (content[i] == '@' && !is_boundary(content[i-1]) && !is_boundary(content[i+1])) {
            add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_MEDIUM, i - 1);
            if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
        }
    }

    /* Look for phone number patterns:
     * Format 1: XXX-XXX-XXXX  (e.g. 555-123-4567)
     * Format 2: (XXX) XXX-XXXX (e.g. (555) 123-4567)
     * Format 3: XXX.XXX.XXXX  (e.g. 555.123.4567)
     */
    for (uint16_t i = 0; i < content_len; i++) {
        /* Format 1: XXX-XXX-XXXX (12 chars) */
        if (i + 11 < content_len &&
            isdigit((unsigned char)content[i]) && isdigit((unsigned char)content[i+1]) && isdigit((unsigned char)content[i+2]) &&
            content[i+3] == '-' &&
            isdigit((unsigned char)content[i+4]) && isdigit((unsigned char)content[i+5]) && isdigit((unsigned char)content[i+6]) &&
            content[i+7] == '-' &&
            isdigit((unsigned char)content[i+8]) && isdigit((unsigned char)content[i+9]) &&
            isdigit((unsigned char)content[i+10]) && isdigit((unsigned char)content[i+11])) {
            /* Disambiguate from SSN (XXX-XX-XXXX): SSN has 2 digits in middle group */
            /* Phone has 3 digits in middle group, so this is different from SSN */
            add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_MEDIUM, i);
            if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
        }

        /* Format 2: (XXX) XXX-XXXX (14 chars) */
        if (i + 13 < content_len &&
            content[i] == '(' &&
            isdigit((unsigned char)content[i+1]) && isdigit((unsigned char)content[i+2]) && isdigit((unsigned char)content[i+3]) &&
            content[i+4] == ')' && content[i+5] == ' ' &&
            isdigit((unsigned char)content[i+6]) && isdigit((unsigned char)content[i+7]) && isdigit((unsigned char)content[i+8]) &&
            content[i+9] == '-' &&
            isdigit((unsigned char)content[i+10]) && isdigit((unsigned char)content[i+11]) &&
            isdigit((unsigned char)content[i+12]) && isdigit((unsigned char)content[i+13])) {
            add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_MEDIUM, i);
            if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
        }

        /* Format 3: XXX.XXX.XXXX (12 chars) */
        if (i + 11 < content_len &&
            isdigit((unsigned char)content[i]) && isdigit((unsigned char)content[i+1]) && isdigit((unsigned char)content[i+2]) &&
            content[i+3] == '.' &&
            isdigit((unsigned char)content[i+4]) && isdigit((unsigned char)content[i+5]) && isdigit((unsigned char)content[i+6]) &&
            content[i+7] == '.' &&
            isdigit((unsigned char)content[i+8]) && isdigit((unsigned char)content[i+9]) &&
            isdigit((unsigned char)content[i+10]) && isdigit((unsigned char)content[i+11])) {
            add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_MEDIUM, i);
            if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
        }
    }

    /* Credit card detection: matches both continuous 16-digit strings
     * (4111111111111111) and grouped formats (4111-1111-1111-1111).
     * Grouped format requires at least 2 separators to reduce false
     * positives on phone numbers. */
    {
        uint8_t digit_run = 0;
        uint8_t groups = 0;
        uint8_t separators = 0;
        uint16_t cc_start = 0;
        uint8_t continuous_digits = 0;
        uint16_t cont_start = 0;
        for (uint16_t i = 0; i < content_len; i++) {
            if (isdigit((unsigned char)content[i])) {
                /* Track continuous digit run for 16-digit detection */
                if (continuous_digits == 0) cont_start = i;
                continuous_digits++;
                if (continuous_digits == 16) {
                    add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_HIGH, cont_start);
                    if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
                    continuous_digits = 0;
                }
                /* Track grouped format */
                if (digit_run == 0 && groups == 0) cc_start = i;
                digit_run++;
                if (digit_run == 4) {
                    groups++;
                    digit_run = 0;
                    if (groups == 4 && separators >= 2) {
                        add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_HIGH, cc_start);
                        if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
                        groups = 0;
                        separators = 0;
                    }
                }
            } else if ((content[i] == '-' || content[i] == ' ') && digit_run == 0 && groups > 0) {
                separators++;
                continuous_digits = 0;
            } else {
                digit_run = 0;
                groups = 0;
                separators = 0;
                continuous_digits = 0;
            }
        }
    }
}

/**
 * Scan for CREDENTIAL patterns (username/password pairs, auth headers).
 * Reduced false-positives: "username" and "login" now require = or : suffix.
 */
#ifndef DCLAW_AC_DFA_AVAILABLE
static void scan_credentials(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    /* Exact-match patterns (substring, no word boundaries) */
    const char *exact_patterns[] = {
        "Authorization:", "Basic ",
        "Bearer ", "Token ",
    };
    const uint8_t num_exact = sizeof(exact_patterns) / sizeof(exact_patterns[0]);

    /* Suffix-required patterns: match "username=" "username:" "login=" "login:" */
    const char *suffix_patterns[] = {
        "username=", "username:",
        "login=", "login:",
    };
    const uint8_t num_suffix = sizeof(suffix_patterns) / sizeof(suffix_patterns[0]);

    for (uint16_t i = 0; i < content_len; i++) {
        /* Check exact-match patterns */
        for (uint8_t p = 0; p < num_exact; p++) {
            const char *pattern = exact_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            if (i + pattern_len <= content_len) {
                bool match = true;
                for (uint16_t j = 0; j < pattern_len; j++) {
                    if (tolower((unsigned char)content[i + j]) != tolower((unsigned char)pattern[j])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    add_finding(ctx, DCLAW_CONTENT_CATEGORY_CREDENTIAL, DCLAW_SEV_HIGH, i);
                    i += pattern_len - 1;
                    goto next_pos;
                }
            }
        }

        /* Check suffix-required patterns (e.g., "username=" or "login:") */
        for (uint8_t p = 0; p < num_suffix; p++) {
            const char *pattern = suffix_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            if (i + pattern_len <= content_len) {
                bool match = true;
                for (uint16_t j = 0; j < pattern_len; j++) {
                    if (tolower((unsigned char)content[i + j]) != tolower((unsigned char)pattern[j])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    /* Also require word boundary before */
                    if (i > 0 && !is_boundary(content[i - 1])) {
                        continue;
                    }
                    add_finding(ctx, DCLAW_CONTENT_CATEGORY_CREDENTIAL, DCLAW_SEV_HIGH, i);
                    i += pattern_len - 1;
                    goto next_pos;
                }
            }
        }

        next_pos: ;
        if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) break;
    }
}

#endif /* !DCLAW_AC_DFA_AVAILABLE (credential scanner) */

/**
 * Scan for EXFIL patterns (base64 blobs, large encoded data).
 */
static void scan_exfil(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    /* Look for long base64-like sequences (alphanumeric + / + = with length > 100) */
    uint16_t b64_start = 0;
    uint16_t b64_len = 0;

    for (uint16_t i = 0; i < content_len; i++) {
        char c = content[i];
        if (isalnum((unsigned char)c) || c == '+' || c == '/' || c == '=') {
            if (b64_len == 0) b64_start = i;
            b64_len++;
        } else {
            if (b64_len > 100) {
                add_finding(ctx, DCLAW_CONTENT_CATEGORY_EXFIL, DCLAW_SEV_MEDIUM, b64_start);
                if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
            }
            b64_len = 0;
        }
    }

    /* Check final sequence */
    if (b64_len > 100) {
        add_finding(ctx, DCLAW_CONTENT_CATEGORY_EXFIL, DCLAW_SEV_MEDIUM, b64_start);
    }
}

#ifndef DCLAW_AC_DFA_AVAILABLE
/**
 * Scan for INJECTION patterns (SQL, XSS, command injection).
 * Reduced false-positives: SQL keywords require a word boundary before them.
 */
static void scan_injection(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    /* SQL keywords — require word boundary before (matches_pattern_at handles both sides) */
    const char *sql_patterns[] = {
        "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "UNION ",
    };
    const uint8_t num_sql = sizeof(sql_patterns) / sizeof(sql_patterns[0]);

    /* Substring patterns — no boundary requirement */
    const char *substr_patterns[] = {
        "<script", "javascript:", "onerror=",
        "../", "../../", "..<", "..\\",
        "${", "eval(", "exec("
    };
    const uint8_t num_substr = sizeof(substr_patterns) / sizeof(substr_patterns[0]);

    for (uint16_t i = 0; i < content_len; i++) {
        /* SQL patterns with word boundary */
        for (uint8_t p = 0; p < num_sql; p++) {
            const char *pattern = sql_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            /* Require boundary before */
            if (i > 0 && !is_boundary(content[i - 1])) {
                continue;
            }
            if (i + pattern_len <= content_len) {
                bool match = true;
                for (uint16_t j = 0; j < pattern_len; j++) {
                    if (tolower((unsigned char)content[i + j]) != tolower((unsigned char)pattern[j])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    add_finding(ctx, DCLAW_CONTENT_CATEGORY_INJECTION, DCLAW_SEV_HIGH, i);
                    i += pattern_len - 1;
                    goto next_inj;
                }
            }
        }

        /* Substring patterns */
        for (uint8_t p = 0; p < num_substr; p++) {
            const char *pattern = substr_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            if (i + pattern_len <= content_len) {
                bool match = true;
                for (uint16_t j = 0; j < pattern_len; j++) {
                    if (tolower((unsigned char)content[i + j]) != tolower((unsigned char)pattern[j])) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    add_finding(ctx, DCLAW_CONTENT_CATEGORY_INJECTION, DCLAW_SEV_HIGH, i);
                    i += pattern_len - 1;
                    goto next_inj;
                }
            }
        }

        next_inj: ;
        if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) break;
    }
}

/**
 * Scan for COMMAND patterns (shell commands, system calls).
 */
static void scan_commands(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    const char *command_patterns[] = {
        "rm ", "chmod ", "chown ", "kill ",
        "sudo ", "su ", "exec ", "system(",
        "/bin/", "/usr/bin/", "cmd.exe", "powershell"
    };
    const uint8_t num_patterns = sizeof(command_patterns) / sizeof(command_patterns[0]);

    for (uint16_t i = 0; i < content_len; i++) {
        for (uint8_t p = 0; p < num_patterns; p++) {
            const char *pattern = command_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            if (matches_pattern_at(content, i, content_len, pattern, pattern_len)) {
                add_finding(ctx, DCLAW_CONTENT_CATEGORY_COMMAND, DCLAW_SEV_HIGH, i);
                i += pattern_len - 1;
                break;
            }
        }
        if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) break;
    }
}

#endif /* !DCLAW_AC_DFA_AVAILABLE */

/* ================================================================== */
/*  Scope-aware dispatcher                                             */
/*                                                                     */
/*  When the Aho-Corasick DFA is compiled in, it replaces the keyword  */
/*  scanners (secrets, credentials, injection, commands) but we still  */
/*  need the structural scanners (PII formats, exfil heuristic).       */
/*  When the DFA is NOT available, we fall back to the manual set.     */
/* ================================================================== */

#ifdef DCLAW_AC_DFA_AVAILABLE

static void scan_content_for_scope(const char *content, uint16_t content_len,
                                   dclaw_content_scope_t scope,
                                   dclaw_scan_context_t *ctx) {
    /* Single O(n) DFA pass for keyword patterns */
    scan_dfa(content, content_len, ctx);

    /* Structural patterns the DFA cannot express */
    if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_pii(content, content_len, ctx);
    }

    /* EXFIL only for USER_INPUT scope */
    if (scope != DCLAW_CONTENT_SCOPE_TOOL_OUTPUT &&
        ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_exfil(content, content_len, ctx);
    }
}

#else /* !DCLAW_AC_DFA_AVAILABLE — manual fallback */

static void scan_content_for_scope(const char *content, uint16_t content_len,
                                   dclaw_content_scope_t scope,
                                   dclaw_scan_context_t *ctx) {
    if (scope == DCLAW_CONTENT_SCOPE_TOOL_OUTPUT) {
        scan_secrets(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_pii(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_credentials(content, content_len, ctx);
    } else {
        scan_secrets(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_pii(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_credentials(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_exfil(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_injection(content, content_len, ctx);
        if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS)
            scan_commands(content, content_len, ctx);
    }
}

#endif /* DCLAW_AC_DFA_AVAILABLE */

#endif /* DCLAW_CONTENT_SCAN */

/* === Main Scanning Function === */

int dclaw_content_scan(const char *content, uint16_t content_len,
                       dclaw_content_scope_t scope,
                       dclaw_scan_context_t *ctx) {
    if (!ctx) {
        return 0;
    }

    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));

    /* Return 0 findings for NULL or empty content */
    if (!content || content_len == 0) {
        return 0;
    }

    /* SYSTEM scope: trusted content, skip scanning entirely */
    if (scope == DCLAW_CONTENT_SCOPE_SYSTEM) {
        return 0;
    }

#if DCLAW_CONTENT_SCAN
    scan_content_for_scope(content, content_len, scope, ctx);
#endif

    return ctx->finding_count;
}

dclaw_action_t dclaw_content_scan_worst_action(const dclaw_scan_context_t *ctx,
                                               dclaw_content_scope_t scope) {
    if (!ctx || ctx->finding_count == 0) {
        return DCLAW_ACTION_ALLOW;
    }

    if (scope == DCLAW_CONTENT_SCOPE_USER_INPUT) {
        /* USER_INPUT: lower thresholds -- block on MEDIUM+ findings */
        for (uint8_t i = 0; i < ctx->finding_count; i++) {
            if (ctx->findings[i].severity >= DCLAW_SEV_MEDIUM) {
                return DCLAW_ACTION_BLOCK;
            }
        }
    } else {
        /* TOOL_OUTPUT / default: normal thresholds */
        for (uint8_t i = 0; i < ctx->finding_count; i++) {
            if (ctx->findings[i].severity >= DCLAW_SEV_HIGH) {
                return DCLAW_ACTION_BLOCK;
            }
        }
        for (uint8_t i = 0; i < ctx->finding_count; i++) {
            if (ctx->findings[i].severity >= DCLAW_SEV_MEDIUM) {
                return DCLAW_ACTION_WARN;
            }
        }
    }

    return DCLAW_ACTION_ALLOW;
}

dclaw_content_scope_t dclaw_infer_content_scope(dclaw_direction_t direction) {
    if (direction == DCLAW_DIRECTION_RESPONSE) {
        return DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    }
    return DCLAW_CONTENT_SCOPE_USER_INPUT;
}
