#include "defenseclaw.h"
#include "platform.h"
#include <string.h>

static char broker_urls[DCLAW_BROKER_FALLBACK_LIST_SIZE][DCLAW_BROKER_URL_MAX];
static uint8_t active_policy_partition = 0; /* 0 = A, 1 = B */

int dclaw_config_load_brokers(void) {
    /* In Phase 1, broker URLs are loaded from /etc/defenseclaw-lite/brokers.conf
     * Each line is one URL, up to DCLAW_BROKER_FALLBACK_LIST_SIZE */
    memset(broker_urls, 0, sizeof(broker_urls));
    strncpy(broker_urls[0], "mqtts://localhost:8883", DCLAW_BROKER_URL_MAX - 1);
    return 0;
}

const char *dclaw_config_get_broker(uint8_t index) {
    if (index >= DCLAW_BROKER_FALLBACK_LIST_SIZE) return NULL;
    if (broker_urls[index][0] == '\0') return NULL;
    return broker_urls[index];
}

uint8_t dclaw_config_active_policy_partition(void) {
    return active_policy_partition;
}

void dclaw_config_switch_policy_partition(void) {
    active_policy_partition = (active_policy_partition == 0) ? 1 : 0;
}
