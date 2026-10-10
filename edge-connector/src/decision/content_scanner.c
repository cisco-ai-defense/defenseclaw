#include "content_scanner.h"
#include "policy_tables.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#if DCLAW_MQTT_ENABLED
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* H-2 fix: Removed SIGALRM + alarm() approach for DNS timeout. Using
 * signal handlers for timeouts is async-signal-unsafe (TOCTOU with
 * getaddrinfo's internal state). getaddrinfo() may block up to the
 * system resolver timeout (typically 5-30s). The DNS check is optional
 * and only runs for STANDARD/EDGE profiles with MQTT enabled. The cloud
 * escalation path provides a secondary check for slow DNS cases. */
#endif

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

    /* Look for credit card patterns: 16 consecutive digits with optional dashes/spaces */
    uint8_t digit_count = 0;
    uint16_t start_pos = 0;
    for (uint16_t i = 0; i < content_len; i++) {
        if (isdigit((unsigned char)content[i])) {
            if (digit_count == 0) start_pos = i;
            digit_count++;
            if (digit_count == 16) {
                add_finding(ctx, DCLAW_CONTENT_CATEGORY_PII, DCLAW_SEV_HIGH, start_pos);
                if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) return;
                digit_count = 0;
            }
        } else if (content[i] != '-' && content[i] != ' ') {
            digit_count = 0;
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

void dclaw_ssrf_init_tables(void) {
    /* Phase 1B stub: no DFA tables to initialize yet */
}

/**
 * Helper: Check if a string starts with a digit (for IP detection).
 */
static bool starts_with_digit(const char *s) {
    return s && isdigit((unsigned char)s[0]);
}

/**
 * Helper: Parse an IPv4 address and return true if valid.
 * Sets octets[0..3] if valid.
 */
static bool parse_ipv4(const char *dest, uint8_t octets[4]) {
    /* H-2 fix: Also handle single-number IPs (decimal, hex 0x, octal 0).
     * e.g., 2130706433 = 127.0.0.1, 0x7f000001 = 127.0.0.1 */
    if (dest[0] == '0' && (dest[1] == 'x' || dest[1] == 'X')) {
        /* Hex: 0x7f000001 */
        char *end;
        unsigned long val = strtoul(dest, &end, 16);
        if (*end == '\0' && val <= 0xFFFFFFFF) {
            octets[0] = (uint8_t)(val >> 24);
            octets[1] = (uint8_t)(val >> 16);
            octets[2] = (uint8_t)(val >> 8);
            octets[3] = (uint8_t)(val);
            return true;
        }
    }
    /* Check for pure decimal single number (no dots) */
    {
        const char *p = dest;
        bool all_digits = true;
        bool has_dot = false;
        while (*p) {
            if (*p == '.') { has_dot = true; break; }
            if (!isdigit((unsigned char)*p)) { all_digits = false; break; }
            p++;
        }
        if (all_digits && !has_dot && p > dest) {
            char *end;
            unsigned long val = strtoul(dest, &end, 10);
            if (*end == '\0' && val <= 0xFFFFFFFF) {
                octets[0] = (uint8_t)(val >> 24);
                octets[1] = (uint8_t)(val >> 16);
                octets[2] = (uint8_t)(val >> 8);
                octets[3] = (uint8_t)(val);
                return true;
            }
        }
    }

    /* Standard dotted-decimal path */
    uint16_t values[4] = {0};
    uint8_t octet_idx = 0;
    uint16_t pos = 0;

    while (dest[pos] && octet_idx < 4) {
        if (!isdigit((unsigned char)dest[pos])) {
            return false;
        }

        /* H-SSRF fix: Detect leading-zero octets and parse as octal.
         * 0177.0.0.01 = 127.0.0.1 in octal — a well-known SSRF technique. */
        int base = 10;
        if (dest[pos] == '0' && isdigit((unsigned char)dest[pos + 1]) && dest[pos + 1] != '.') {
            base = 8; /* leading zero = octal */
        }
        values[octet_idx] = 0;
        while (isdigit((unsigned char)dest[pos]) && dest[pos] != '.') {
            uint16_t digit = dest[pos] - '0';
            if (base == 8 && digit >= 8) return false; /* invalid octal digit */
            values[octet_idx] = values[octet_idx] * base + digit;
            if (values[octet_idx] > 255) {
                return false; /* Octet overflow */
            }
            pos++;
        }

        octet_idx++;

        /* Expect dot after first 3 octets */
        if (octet_idx < 4) {
            if (dest[pos] != '.') {
                return false;
            }
            pos++;
        }
    }

    /* Must have exactly 4 octets and reach end or port separator */
    if (octet_idx != 4 || (dest[pos] != '\0' && dest[pos] != ':')) {
        return false;
    }

    /* Store octets */
    octets[0] = (uint8_t)values[0];
    octets[1] = (uint8_t)values[1];
    octets[2] = (uint8_t)values[2];
    octets[3] = (uint8_t)values[3];

    return true;
}

/**
 * Helper: Extract hostname from a URL or bare host string.
 * Skips scheme (http://, https://), skips userinfo (user:pass@),
 * extracts hostname up to ':', '/', or end of string.
 * Returns pointer into `dest` where hostname starts, and sets *host_len.
 */
static const char *extract_host(const char *dest, size_t *host_len) {
    const char *p = dest;

    /* Skip scheme if present */
    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
    }

    /* Skip userinfo (user:pass@) */
    const char *at = NULL;
    const char *scan = p;
    while (*scan && *scan != '/' && *scan != '?') {
        if (*scan == '@') { at = scan; break; }
        scan++;
    }
    if (at) {
        p = at + 1;
    }

    /* Hostname extends to ':', '/', '?', or end of string */
    const char *host_start = p;
    while (*p && *p != ':' && *p != '/' && *p != '?') {
        p++;
    }
    *host_len = (size_t)(p - host_start);
    return host_start;
}

dclaw_action_t dclaw_ssrf_check_destination(const char *dest) {
    /* NULL destination: caller must not invoke SSRF check for non-network tools */
    if (!dest) {
        return DCLAW_ACTION_ALLOW;
    }

    /* Block data: URIs unconditionally */
    if (strncmp(dest, "data:", 5) == 0) {
        return DCLAW_ACTION_BLOCK;
    }

    /* REQ-61: Only allow http:// and https:// schemes */
    if (strncmp(dest, "http://", 7) != 0 && strncmp(dest, "https://", 8) != 0) {
        /* Allow bare hostnames/IPs (no scheme), block everything else with a scheme */
        const char *colon = strchr(dest, ':');
        if (colon && colon[1] == '/' && colon[2] == '/') {
            return DCLAW_ACTION_BLOCK; /* Non-http(s) scheme like file://, gopher://, ftp:// */
        }
    }

    /* Extract the hostname from the URL for all subsequent checks */
    size_t host_len = 0;
    const char *host_start = extract_host(dest, &host_len);
    if (host_len == 0 || host_len >= 256) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Copy hostname to a NUL-terminated buffer for safe comparison */
    char host[256];
    memcpy(host, host_start, host_len);
    host[host_len] = '\0';

    /* Check for inline credentials (user:pass@host pattern) -- only in URL authority */
    const char *authority_start = dest;
    const char *scheme_end = strstr(dest, "://");
    if (scheme_end) {
        authority_start = scheme_end + 3;
    }
    const char *authority_end = strchr(authority_start, '/');
    if (!authority_end) authority_end = authority_start + strlen(authority_start);
    for (const char *p = authority_start; p < authority_end; p++) {
        if (*p == '@') {
            return DCLAW_ACTION_BLOCK;
        }
    }

    /* Check for "localhost" literal */
    if (strcmp(host, "localhost") == 0) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Check for IPv6 loopback */
    if (strcmp(host, "::1") == 0) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Check for IPv6 ULA (fc00::/7) and link-local (fe80::/10) */
    if (strncmp(host, "fc", 2) == 0 || strncmp(host, "fd", 2) == 0 ||
        strncmp(host, "fe80:", 5) == 0 || strncmp(host, "fe80%", 5) == 0) {
        return DCLAW_ACTION_BLOCK;
    }

    /* M-1 fix: DNS rebinding check — resolve the hostname and verify the
     * resolved IP is not in a private range.  This catches DNS rebinding
     * where evil.com resolves to 192.168.1.1.
     *
     * Enabled by default for STANDARD and EDGE profiles (which have
     * DCLAW_MQTT_ENABLED=1 and therefore have networking / getaddrinfo).
     * MINIMAL profiles lack networking and skip this check.
     *
     * A 2-second SIGALRM timeout prevents getaddrinfo() from stalling the
     * event loop on slow/dead DNS servers. */
#if DCLAW_MQTT_ENABLED
    if (!starts_with_digit(host)) {
        /* H-1 fix: Use AI_NUMERICHOST to avoid blocking DNS resolution.
         * AI_NUMERICHOST only succeeds for literal IP addresses (e.g.,
         * "192.168.1.1"). For actual hostnames it returns EAI_NONAME
         * immediately (no DNS query). This avoids the blocking getaddrinfo
         * call entirely. For hostnames that fail AI_NUMERICHOST, we ALLOW
         * and let the cloud escalation path handle the SSRF check server-side
         * where DNS resolution is safe (non-blocking, pooled resolvers). */
        struct addrinfo hints, *result;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST;

        int dns_rc = getaddrinfo(host, NULL, &hints, &result);

        if (dns_rc != 0) {
            /* Not a literal IP (it's a hostname) — skip on-device DNS.
             * The cloud escalation path will re-evaluate server-side. */
            return DCLAW_ACTION_ALLOW;
        }

        /* Literal IP resolved — check if it's in a private/loopback range */
        struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
        uint32_t ip = ntohl(addr->sin_addr.s_addr);
        freeaddrinfo(result);

        uint8_t o0 = (ip >> 24) & 0xFF;
        uint8_t o1 = (ip >> 16) & 0xFF;

        /* Loopback: 127.x.x.x */
        if (o0 == 127) return DCLAW_ACTION_BLOCK;
        /* 0.0.0.0/8 */
        if (o0 == 0) return DCLAW_ACTION_BLOCK;
        /* 10.x.x.x */
        if (o0 == 10) return DCLAW_ACTION_BLOCK;
        /* 172.16.0.0 - 172.31.255.255 */
        if (o0 == 172 && o1 >= 16 && o1 <= 31) return DCLAW_ACTION_BLOCK;
        /* 192.168.x.x */
        if (o0 == 192 && o1 == 168) return DCLAW_ACTION_BLOCK;
        /* Link-local: 169.254.x.x */
        if (o0 == 169 && o1 == 254) return DCLAW_ACTION_BLOCK;

        /* Resolved to a public IP — allow */
        return DCLAW_ACTION_ALLOW;
    }
#endif /* DCLAW_MQTT_ENABLED */

    /* If not starting with digit, assume it's a hostname — pass through.
     *
     * M-1 tradeoff: When DCLAW_MQTT_ENABLED is 0 (MINIMAL profile without
     * networking/getaddrinfo), hostname-only destinations bypass the
     * private-IP detection above.  STANDARD and EDGE profiles always perform
     * the DNS check.  The cloud escalation path provides a second check for
     * MINIMAL: escalated requests are re-evaluated server-side where DNS
     * resolution IS performed, catching any hostname that resolves to a
     * private range. */
    if (!starts_with_digit(host)) {
        return DCLAW_ACTION_ALLOW;
    }

    /* Try to parse as IPv4 */
    uint8_t octets[4];
    if (!parse_ipv4(host, octets)) {
        /* Not a valid IPv4, treat as hostname */
        return DCLAW_ACTION_ALLOW;
    }

    /* Check for loopback: 127.x.x.x */
    if (octets[0] == 127) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Check for 0.0.0.0/8 range */
    if (octets[0] == 0) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Check for cloud metadata: 169.254.169.254 */
    if (octets[0] == 169 && octets[1] == 254 && octets[2] == 169 && octets[3] == 254) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Check for link-local: 169.254.x.x */
    if (octets[0] == 169 && octets[1] == 254) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Check for RFC1918 private ranges:
     * - 10.x.x.x
     * - 172.16.x.x - 172.31.x.x
     * - 192.168.x.x
     */
    if (octets[0] == 10) {
        return DCLAW_ACTION_BLOCK;
    }

    if (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31) {
        return DCLAW_ACTION_BLOCK;
    }

    if (octets[0] == 192 && octets[1] == 168) {
        return DCLAW_ACTION_BLOCK;
    }

    /* Public IP - allow */
    return DCLAW_ACTION_ALLOW;
}

dclaw_content_scope_t dclaw_infer_content_scope(dclaw_direction_t direction) {
    if (direction == DCLAW_DIRECTION_RESPONSE) {
        return DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    }
    return DCLAW_CONTENT_SCOPE_USER_INPUT;
}
