#ifndef DCLAW_PLATFORM_H
#define DCLAW_PLATFORM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Hardware Abstraction Layer — platform-specific operations. */

/* Monotonic tick counter (millisecond resolution). Never wraps within device uptime. */
uint32_t hal_tick_ms(void);

/* Flash operations */
int hal_flash_read(uint32_t offset, void *buf, size_t len);
int hal_flash_write(uint32_t offset, const void *buf, size_t len);
int hal_flash_erase_sector(uint32_t sector);

/* Flash partition offsets (configured per platform) */
#define HAL_FLASH_POLICY_A_OFFSET   0x00000
#define HAL_FLASH_POLICY_A_SIZE     4096
#define HAL_FLASH_POLICY_B_OFFSET   0x01000
#define HAL_FLASH_POLICY_B_SIZE     4096
#define HAL_FLASH_AUDIT_OFFSET      0x02000
#define HAL_FLASH_AUDIT_SIZE        4096
#define HAL_FLASH_CONFIG_OFFSET     0x03000
#define HAL_FLASH_CONFIG_SIZE       1024

/* Unix socket for IPC */
int hal_ipc_socket_create(const char *path);
int hal_ipc_socket_accept(int server_fd);
void hal_ipc_socket_close(int fd);

/* Peer credential retrieval */
int hal_get_peer_cred(int fd, uint32_t *uid, uint32_t *gid, int32_t *pid);
uint64_t hal_get_pid_start_time(int32_t pid);

/* Secure random */
int hal_random_bytes(void *buf, size_t len);

/* Device certificate loading */
int hal_load_device_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len);
int hal_load_device_key(uint8_t *key_buf, size_t *key_len, size_t max_len);
int hal_load_ca_cert(uint8_t *cert_buf, size_t *cert_len, size_t max_len);

/* Watchdog */
void hal_watchdog_feed(void);

/* Platform init/shutdown */
int hal_init(void);
void hal_shutdown(void);

#endif /* DCLAW_PLATFORM_H */
