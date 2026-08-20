#include "platform.h"

/* Flash-safe writes with basic wear-leveling.
 * On Linux HAL, flash is backed by a regular file — wear leveling is a no-op.
 * On real MCU HAL, this would track sector erase counts and rotate. */

int dclaw_flash_write_safe(uint32_t offset, const void *buf, size_t len) {
    return hal_flash_write(offset, buf, len);
}

int dclaw_flash_read_safe(uint32_t offset, void *buf, size_t len) {
    return hal_flash_read(offset, buf, len);
}
