#ifndef DEFENSECLAW_H
#define DEFENSECLAW_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "config.h"

/* === Enumerations === */

typedef enum {
    DCLAW_ACTION_ALLOW    = 0,
    DCLAW_ACTION_BLOCK    = 1,
    DCLAW_ACTION_WARN     = 2,
    DCLAW_ACTION_ESCALATE = 3,
} dclaw_action_t;

typedef enum {
    DCLAW_CAP_UNKNOWN     = 0x00,
    DCLAW_CAP_READ_FS     = 0x01,
    DCLAW_CAP_WRITE_FS    = 0x02,
    DCLAW_CAP_EXEC_SHELL  = 0x04,
    DCLAW_CAP_NET_FETCH   = 0x08,
    DCLAW_CAP_SEND_MSG    = 0x10,
    DCLAW_CAP_ACTUATE     = 0x20,
    DCLAW_CAP_SENSOR_READ = 0x40,
} dclaw_capability_t;

typedef enum {
    DCLAW_SEV_INFO     = 0,
    DCLAW_SEV_LOW      = 1,
    DCLAW_SEV_MEDIUM   = 2,
    DCLAW_SEV_HIGH     = 3,
    DCLAW_SEV_CRITICAL = 4,
} dclaw_severity_t;

typedef enum {
    DCLAW_REASON_POLICY_TABLE   = 0x01,
    DCLAW_REASON_CAP_SEQUENCE   = 0x02,
    DCLAW_REASON_DEST_DENY      = 0x03,
    DCLAW_REASON_HASH_DENY      = 0x04,
    DCLAW_REASON_RATE_LIMIT     = 0x05,
    DCLAW_REASON_CLOUD_BLOCK    = 0x06,
    DCLAW_REASON_CLOUD_TIMEOUT  = 0x07,
    DCLAW_REASON_PII_DETECTED   = 0x08,
    DCLAW_REASON_BLOOM_HIT      = 0x09,
    DCLAW_REASON_INVALID_INPUT  = 0x0A,
    DCLAW_REASON_RETROACTIVE    = 0x0B,
} dclaw_reason_t;

typedef enum {
    DCLAW_VERDICT_SYNC,
    DCLAW_VERDICT_PENDING,
    DCLAW_VERDICT_RETROACTIVE_BLOCK,
} dclaw_verdict_mode_t;

typedef enum {
    DCLAW_EXEC_STAGE_QUEUED,
    DCLAW_EXEC_STAGE_STARTED,
    DCLAW_EXEC_STAGE_COMMITTED,
    DCLAW_EXEC_STAGE_COMPLETE,
} dclaw_exec_stage_t;

typedef enum {
    DCLAW_SE_MODE_STRICT,
    DCLAW_SE_MODE_DEGRADED,
    DCLAW_SE_MODE_DISABLED,
} dclaw_se_failure_mode_t;

/* === Core Structures === */

typedef struct {
    uint16_t tenant_id;
    uint16_t fleet_id;
    uint32_t device_id;
    uint16_t policy_version;
    uint16_t fw_version;
    uint8_t  hw_profile;
    uint8_t  capabilities;
} dclaw_device_info_t;

#define DCLAW_FULL_ID(t, f, d) \
    (((uint64_t)(t) << 48) | ((uint64_t)(f) << 32) | (uint64_t)(d))

typedef struct {
    uint32_t cloud_epoch;
    uint32_t local_ticks;
    uint32_t ticks_at_sync;
    bool     time_trusted;
} dclaw_clock_t;

typedef struct {
    char     tool_name[DCLAW_TOOL_NAME_MAX];
    uint8_t  tool_hash[32];
    uint8_t  cap_flags;
    char     destination[DCLAW_DESTINATION_MAX];
    uint16_t session_id;
} dclaw_tool_request_t;

typedef struct {
    dclaw_action_t       action;
    dclaw_reason_t       reason;
    dclaw_severity_t     severity;
    dclaw_verdict_mode_t mode;
    uint16_t             ttl_minutes;
    bool                 from_cache;
} dclaw_verdict_t;

/* === Audit === */

typedef struct {
    uint32_t timestamp;     /* 4 */
    uint16_t target_hash;   /* 2 */
    uint16_t session_id;    /* 2 */
    uint8_t  hmac[4];       /* 4 (truncated for 16B fit) */
    uint8_t  action;        /* 1 */
    uint8_t  reason;        /* 1 */
    uint8_t  _pad[2];       /* 2 */
} dclaw_audit_entry_t;      /* 16 bytes, naturally aligned */

_Static_assert(sizeof(dclaw_audit_entry_t) == 16, "audit entry must be 16 bytes");

typedef struct {
    dclaw_audit_entry_t buffer[DCLAW_AUDIT_RAM_BUFFER_SIZE];
    uint8_t  count;
    uint32_t last_flush_tick;
    uint32_t total_flash_writes;
} dclaw_audit_writer_t;

/* === Session Correlator === */

typedef struct {
    uint16_t session_id;
    uint8_t  cap_history[DCLAW_SESSION_HISTORY_DEPTH];
    uint8_t  cap_head;
    uint8_t  cap_count;
    uint32_t started_at;
    uint32_t last_activity;
    uint8_t  risk_score;
} dclaw_session_t;

/* === Verdict Cache === */

typedef struct {
    uint8_t  tool_hash[32];
    uint8_t  action;
    uint8_t  severity;
    uint16_t ttl_minutes;
    uint32_t cached_at_tick;
    bool     occupied;
} dclaw_cache_entry_t;

/* === Pending Verdict Dedup === */

typedef struct {
    uint16_t request_id;
    bool     resolved;
    uint32_t resolved_at;
} dclaw_pending_verdict_t;

/* === Speculative Execution === */

typedef struct {
    uint16_t         session_id;
    uint16_t         request_id;
    uint8_t          cap_flags;
    dclaw_exec_stage_t stage;
    bool             verdict_received;
    dclaw_action_t   cloud_verdict;
} dclaw_speculative_slot_t;

typedef struct {
    uint8_t cap_flag;
    uint8_t mode; /* 0=sync_block, 1=speculative */
} dclaw_escalation_entry_t;

/* === Rate Limiter === */

typedef struct {
    uint16_t tokens;
    uint16_t bucket_size;
    uint16_t refill_rate;
    uint32_t last_refill_tick;
} dclaw_rate_limiter_t;

/* === IPC Peer Verification === */

typedef struct {
    uint32_t expected_uid;
    uint32_t expected_gid;
    uint8_t  reg_token[16];
    int32_t  registered_pid;
    uint64_t start_time;
    bool     verified;
} dclaw_ipc_peer_t;

/* === Policy OTA Canary === */

typedef struct {
    uint16_t baseline_blocks_per_min;
    uint16_t canary_blocks[10];
    uint8_t  canary_minute;
    uint8_t  spike_streak;
    bool     canary_active;
    uint32_t canary_started_at;
} dclaw_canary_state_t;

/* === Emergency Broadcast === */

typedef struct {
    uint32_t last_seen_seq;
    uint32_t gap_start;
    bool     replay_requested;
} dclaw_emergency_state_t;

/* === Global Agent State === */

typedef struct {
    dclaw_device_info_t     device;
    dclaw_clock_t           clock;
    dclaw_session_t         sessions[DCLAW_MAX_SESSIONS];
    dclaw_cache_entry_t     cache[DCLAW_VERDICT_CACHE_SIZE];
    dclaw_pending_verdict_t pending[DCLAW_PENDING_SLOTS];
    dclaw_speculative_slot_t speculative[DCLAW_SPECULATIVE_SLOTS];
    dclaw_rate_limiter_t    rate_limiters[DCLAW_RATE_LIMITERS];
    dclaw_audit_writer_t    audit_writer;
    dclaw_canary_state_t    canary;
    dclaw_emergency_state_t emergency;
    dclaw_ipc_peer_t        ipc_peer;
    uint16_t                next_request_id;
    bool                    online;
    bool                    initialized;
} dclaw_state_t;

/* === Public API === */

int dclaw_init(const dclaw_device_info_t *info);
dclaw_verdict_t dclaw_evaluate(const dclaw_tool_request_t *req);
dclaw_action_t dclaw_check_destination(const char *host, uint16_t port);
void dclaw_report_result(uint16_t session_id, const char *tool_name,
                         bool success, const char *output_summary);
int dclaw_flush_audit(void);
int dclaw_apply_policy(const uint8_t *blob, uint32_t blob_len,
                       const uint8_t *signature);
int dclaw_apply_emergency(const uint8_t *msg, uint32_t msg_len);
int dclaw_ipc_verify_peer(int client_fd, dclaw_ipc_peer_t *peer);
void dclaw_get_health(uint8_t *out_heartbeat, uint8_t *out_len);
void dclaw_shutdown(void);

typedef void (*dclaw_retroactive_block_fn)(uint16_t session_id,
                                           const char *tool_name);
void dclaw_register_retroactive_callback(dclaw_retroactive_block_fn cb);

#endif /* DEFENSECLAW_H */
