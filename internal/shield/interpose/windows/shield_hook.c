/*
 * DefenseClaw Shield — Windows SSL Hook Library (DLL)
 *
 * Uses Microsoft Detours to hook SSL functions in the target process.
 * Intercepted plaintext is sent to the defenseclaw-shield daemon over
 * a named pipe for inspection. Supports both SChannel (Windows native TLS)
 * and OpenSSL (used by Python, Node.js, curl).
 *
 * Build (requires Detours SDK):
 *   cl /LD shield_hook.c /I<detours_include> /link detours.lib ws2_32.lib
 *
 * Usage:
 *   withdll /d:shield_hook.dll claude.exe "do something"
 *   OR: inject via CreateRemoteThread + LoadLibrary
 */

#ifdef _WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

/* --- Detours stubs ---
 * In a real build these come from Microsoft Detours.
 * For POC we declare the API shape; the actual linking
 * happens at build time with the Detours NuGet package.
 */
#ifdef USE_DETOURS
#include <detours.h>
#else
/* Stub declarations so the file compiles as reference code */
#define DetourTransactionBegin()        (0)
#define DetourUpdateThread(h)           (0)
#define DetourAttach(ppOrig, pHook)     (0)
#define DetourDetach(ppOrig, pHook)     (0)
#define DetourTransactionCommit()       (0)
#endif

/* --- Wire protocol (matches Go ipc.go) --- */
#define MSG_TYPE_REQUEST  0x01
#define MSG_TYPE_RESPONSE 0x02
#define VERDICT_ALLOW     0x00
#define VERDICT_BLOCK     0x01

/* Named pipe path */
static const char *PIPE_NAME = "\\\\.\\pipe\\defenseclaw-shield";

/* --- OpenSSL function types --- */
typedef int (*ssl_write_func)(void *ssl, const void *buf, int num);
typedef int (*ssl_read_func)(void *ssl, void *buf, int num);
typedef int (*ssl_get_fd_func)(const void *ssl);

static ssl_write_func  Real_SSL_write  = NULL;
static ssl_read_func   Real_SSL_read   = NULL;
static ssl_get_fd_func Real_SSL_get_fd = NULL;

/* --- Per-thread pipe handle --- */
static __declspec(thread) HANDLE pipe_handle = INVALID_HANDLE_VALUE;

static HANDLE get_pipe(void) {
    if (pipe_handle != INVALID_HANDLE_VALUE)
        return pipe_handle;

    pipe_handle = CreateFileA(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        0, NULL);

    return pipe_handle;
}

/* Get peer address from SSL fd */
static void get_peer_address(const void *ssl, char *buf, size_t buflen) {
    if (!Real_SSL_get_fd) {
        _snprintf_s(buf, buflen, _TRUNCATE, "unknown:443");
        return;
    }

    int fd = Real_SSL_get_fd(ssl);
    if (fd < 0) {
        _snprintf_s(buf, buflen, _TRUNCATE, "unknown:443");
        return;
    }

    struct sockaddr_storage ss;
    int sslen = sizeof(ss);
    if (getpeername((SOCKET)fd, (struct sockaddr *)&ss, &sslen) != 0) {
        _snprintf_s(buf, buflen, _TRUNCATE, "unknown:443");
        return;
    }

    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        char ip[64];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        _snprintf_s(buf, buflen, _TRUNCATE, "%s:%d", ip, ntohs(sin->sin_port));
    } else if (ss.ss_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        char ip[128];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        _snprintf_s(buf, buflen, _TRUNCATE, "[%s]:%d", ip, ntohs(sin6->sin6_port));
    } else {
        _snprintf_s(buf, buflen, _TRUNCATE, "unknown:443");
    }
}

/* Send to shield daemon, get verdict */
static uint8_t send_to_shield(uint8_t msg_type, const void *ssl,
                               const void *data, int datalen) {
    HANDLE h = get_pipe();
    if (h == INVALID_HANDLE_VALUE)
        return VERDICT_ALLOW;

    char host[256];
    get_peer_address(ssl, host, sizeof(host));
    uint16_t host_len = (uint16_t)strlen(host);
    uint32_t pid = GetCurrentProcessId();
    uint32_t payload_len = (datalen > 0) ? (uint32_t)datalen : 0;

    uint32_t body_len = 1 + 4 + 2 + host_len + 4 + payload_len;
    uint32_t total = 4 + body_len;

    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) return VERDICT_ALLOW;

    /* Encode (little-endian) */
    *(uint32_t *)(buf + 0) = body_len;
    buf[4] = msg_type;
    *(uint32_t *)(buf + 5) = pid;
    *(uint16_t *)(buf + 9) = host_len;
    memcpy(buf + 11, host, host_len);
    uint32_t off = 11 + host_len;
    *(uint32_t *)(buf + off) = payload_len;
    if (payload_len > 0) {
        memcpy(buf + off + 4, data, payload_len);
    }

    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, total, &written, NULL);
    free(buf);

    if (!ok || written != total) {
        CloseHandle(pipe_handle);
        pipe_handle = INVALID_HANDLE_VALUE;
        return VERDICT_ALLOW;
    }

    /* Read verdict */
    uint8_t verdict = VERDICT_ALLOW;
    DWORD nread = 0;
    ok = ReadFile(h, &verdict, 1, &nread, NULL);
    if (!ok || nread != 1) {
        CloseHandle(pipe_handle);
        pipe_handle = INVALID_HANDLE_VALUE;
        return VERDICT_ALLOW;
    }

    return verdict;
}

/* --- Hooked functions --- */

static int Hook_SSL_write(void *ssl, const void *buf, int num) {
    uint8_t verdict = send_to_shield(MSG_TYPE_REQUEST, ssl, buf, num);

    if (verdict == VERDICT_BLOCK) {
        SetLastError(ERROR_ACCESS_DENIED);
        return -1;
    }

    return Real_SSL_write(ssl, buf, num);
}

static int Hook_SSL_read(void *ssl, void *buf, int num) {
    int ret = Real_SSL_read(ssl, buf, num);

    if (ret > 0) {
        send_to_shield(MSG_TYPE_RESPONSE, ssl, buf, ret);
    }

    return ret;
}

/* --- DLL attach/detach --- */

static void resolve_ssl_functions(void) {
    /* Try OpenSSL/BoringSSL (libssl, ssleay32, libcrypto) */
    HMODULE hssl = GetModuleHandleA("libssl-3.dll");
    if (!hssl) hssl = GetModuleHandleA("libssl-1_1.dll");
    if (!hssl) hssl = GetModuleHandleA("libssl-1_1-x64.dll");
    if (!hssl) hssl = GetModuleHandleA("ssleay32.dll");

    /* Node.js statically links BoringSSL — symbols are in the main exe */
    if (!hssl) hssl = GetModuleHandleA(NULL);

    if (hssl) {
        Real_SSL_write  = (ssl_write_func)GetProcAddress(hssl, "SSL_write");
        Real_SSL_read   = (ssl_read_func)GetProcAddress(hssl, "SSL_read");
        Real_SSL_get_fd = (ssl_get_fd_func)GetProcAddress(hssl, "SSL_get_fd");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        resolve_ssl_functions();

        if (Real_SSL_write && Real_SSL_read) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach((PVOID *)&Real_SSL_write, Hook_SSL_write);
            DetourAttach((PVOID *)&Real_SSL_read, Hook_SSL_read);
            DetourTransactionCommit();
        }
        break;

    case DLL_PROCESS_DETACH:
        if (Real_SSL_write && Real_SSL_read) {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourDetach((PVOID *)&Real_SSL_write, Hook_SSL_write);
            DetourDetach((PVOID *)&Real_SSL_read, Hook_SSL_read);
            DetourTransactionCommit();
        }
        if (pipe_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(pipe_handle);
        }
        break;
    }
    return TRUE;
}

#endif /* _WIN32 */
