#ifndef DCLAW_CONTENT_SCANNER_H
#define DCLAW_CONTENT_SCANNER_H

#include "defenseclaw.h"

/* === Content Scanning Structures === */

typedef struct {
    dclaw_content_category_t category;
    dclaw_severity_t         severity;
    uint16_t                 offset;
} dclaw_content_finding_t;

typedef struct {
    uint8_t                  transitions[256];
    dclaw_content_category_t accept_category;
    dclaw_severity_t         accept_severity;
} dclaw_dfa_state_t;

typedef struct {
    const dclaw_dfa_state_t *states;
    uint8_t                  state_count;
    dclaw_content_category_t category;
} dclaw_dfa_table_t;

typedef struct {
    uint8_t                current_state[DCLAW_MAX_DFA_CATEGORIES];
    dclaw_content_finding_t findings[DCLAW_MAX_SCAN_FINDINGS];
    uint8_t                finding_count;
} dclaw_scan_context_t;

/* === Content Scanning Functions === */

/**
 * Scan content for sensitive patterns using DFA-based matching.
 * Returns the number of findings detected (0 if none).
 */
int dclaw_content_scan(const char *content, uint16_t content_len,
                       dclaw_content_scope_t scope,
                       dclaw_scan_context_t *ctx);

/**
 * Determine the worst action based on scan findings.
 * Returns ALLOW if no findings, BLOCK if any HIGH+, WARN if any MEDIUM+.
 */
dclaw_action_t dclaw_content_scan_worst_action(const dclaw_scan_context_t *ctx);

/**
 * Initialize SSRF detection DFA tables (called once at agent init).
 */
void dclaw_ssrf_init_tables(void);

/**
 * Check if a destination matches SSRF patterns.
 * Returns BLOCK if suspicious, ALLOW otherwise.
 */
dclaw_action_t dclaw_ssrf_check_destination(const char *dest);

/**
 * Infer content scope from direction if not explicitly provided.
 * Returns TOOL_OUTPUT if direction==RESPONSE, else USER_INPUT.
 */
dclaw_content_scope_t dclaw_infer_content_scope(dclaw_direction_t direction);

#endif /* DCLAW_CONTENT_SCANNER_H */
