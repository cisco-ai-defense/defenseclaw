#include "content_scanner.h"
#include <string.h>
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

/**
 * Scan for PII patterns (SSN, email, phone, credit card).
 */
static void scan_pii(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    /* Look for SSN pattern: XXX-XX-XXXX */
    for (uint16_t i = 0; i + 10 < content_len; i++) {
        if (isdigit(content[i]) && isdigit(content[i+1]) && isdigit(content[i+2]) &&
            content[i+3] == '-' &&
            isdigit(content[i+4]) && isdigit(content[i+5]) &&
            content[i+6] == '-' &&
            isdigit(content[i+7]) && isdigit(content[i+8]) &&
            isdigit(content[i+9]) && isdigit(content[i+10])) {
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

    /* Look for credit card patterns: 16 consecutive digits with optional dashes/spaces */
    uint8_t digit_count = 0;
    uint16_t start_pos = 0;
    for (uint16_t i = 0; i < content_len; i++) {
        if (isdigit(content[i])) {
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
 */
static void scan_credentials(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    const char *cred_patterns[] = {
        "Authorization:", "Basic ",
        "Bearer ", "Token ",
        "username", "login"
    };
    const uint8_t num_patterns = sizeof(cred_patterns) / sizeof(cred_patterns[0]);

    for (uint16_t i = 0; i < content_len; i++) {
        for (uint8_t p = 0; p < num_patterns; p++) {
            const char *pattern = cred_patterns[p];
            uint16_t pattern_len = (uint16_t)strlen(pattern);

            /* For "Authorization:", "Basic ", "Bearer ", "Token " - exact match without word boundaries */
            if (p < 4) {
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
                        break;
                    }
                }
            } else {
                /* For "username", "login" - use word boundaries */
                if (matches_pattern_at(content, i, content_len, pattern, pattern_len)) {
                    add_finding(ctx, DCLAW_CONTENT_CATEGORY_CREDENTIAL, DCLAW_SEV_HIGH, i);
                    i += pattern_len - 1;
                    break;
                }
            }
        }
        if (ctx->finding_count >= DCLAW_MAX_SCAN_FINDINGS) break;
    }
}

/**
 * Scan for EXFIL patterns (base64 blobs, large encoded data).
 */
static void scan_exfil(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    /* Look for long base64-like sequences (alphanumeric + / + = with length > 100) */
    uint16_t b64_start = 0;
    uint16_t b64_len = 0;

    for (uint16_t i = 0; i < content_len; i++) {
        char c = content[i];
        if (isalnum(c) || c == '+' || c == '/' || c == '=') {
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

/**
 * Scan for INJECTION patterns (SQL, XSS, command injection).
 */
static void scan_injection(const char *content, uint16_t content_len, dclaw_scan_context_t *ctx) {
    const char *injection_patterns[] = {
        "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ",
        "UNION ", "<script", "javascript:", "onerror=",
        "../", "../../", "..<", "..\\",
        "${", "eval(", "exec("
    };
    const uint8_t num_patterns = sizeof(injection_patterns) / sizeof(injection_patterns[0]);

    for (uint16_t i = 0; i < content_len; i++) {
        for (uint8_t p = 0; p < num_patterns; p++) {
            const char *pattern = injection_patterns[p];
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
                    break;
                }
            }
        }
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

#endif /* DCLAW_CONTENT_SCAN */

/* === Main Scanning Function === */

int dclaw_content_scan(const char *content, uint16_t content_len,
                       dclaw_content_scope_t scope,
                       dclaw_scan_context_t *ctx) {
    (void)scope; /* Scope-specific tuning can be added later */

    if (!ctx) {
        return 0;
    }

    /* Initialize context */
    memset(ctx, 0, sizeof(*ctx));

    /* Return 0 findings for NULL or empty content */
    if (!content || content_len == 0) {
        return 0;
    }

#if DCLAW_CONTENT_SCAN
    /* Run all category scanners */
    scan_secrets(content, content_len, ctx);
    if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_pii(content, content_len, ctx);
    }
    if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_credentials(content, content_len, ctx);
    }
    if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_exfil(content, content_len, ctx);
    }
    if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_injection(content, content_len, ctx);
    }
    if (ctx->finding_count < DCLAW_MAX_SCAN_FINDINGS) {
        scan_commands(content, content_len, ctx);
    }
#endif

    return ctx->finding_count;
}

dclaw_action_t dclaw_content_scan_worst_action(const dclaw_scan_context_t *ctx) {
    if (!ctx || ctx->finding_count == 0) {
        return DCLAW_ACTION_ALLOW;
    }

    /* Check for HIGH or CRITICAL severity findings */
    for (uint8_t i = 0; i < ctx->finding_count; i++) {
        if (ctx->findings[i].severity >= DCLAW_SEV_HIGH) {
            return DCLAW_ACTION_BLOCK;
        }
    }

    /* Check for MEDIUM severity findings */
    for (uint8_t i = 0; i < ctx->finding_count; i++) {
        if (ctx->findings[i].severity >= DCLAW_SEV_MEDIUM) {
            return DCLAW_ACTION_WARN;
        }
    }

    return DCLAW_ACTION_ALLOW;
}

void dclaw_ssrf_init_tables(void) {
    /* Phase 1B stub: no DFA tables to initialize yet */
}

dclaw_action_t dclaw_ssrf_check_destination(const char *dest) {
    (void)dest; /* Unused in stub */
    /* Phase 1B stub: always allow */
    return DCLAW_ACTION_ALLOW;
}

dclaw_content_scope_t dclaw_infer_content_scope(dclaw_direction_t direction) {
    if (direction == DCLAW_DIRECTION_RESPONSE) {
        return DCLAW_CONTENT_SCOPE_TOOL_OUTPUT;
    }
    return DCLAW_CONTENT_SCOPE_USER_INPUT;
}
