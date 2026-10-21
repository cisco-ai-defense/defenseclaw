cmake_minimum_required(VERSION 3.22)
project(edge-connector C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Profile selection (maps to Kconfig)
set(DCLAW_PROFILE "STANDARD" CACHE STRING "Agent profile: MINIMAL, STANDARD, EDGE")
set_property(CACHE DCLAW_PROFILE PROPERTY STRINGS MINIMAL STANDARD EDGE)

# Profile-dependent defaults
if(DCLAW_PROFILE STREQUAL "MINIMAL")
    set(DCLAW_AUDIT_RING_SIZE 64)
    set(DCLAW_VERDICT_CACHE_SIZE 0)
    set(DCLAW_HEARTBEAT_INTERVAL_SEC 0)
    set(DCLAW_MQTT_ENABLED OFF)
    set(DCLAW_PII_REDACTION OFF)
    set(DCLAW_BLOOM_FILTER OFF)
    set(DCLAW_SPECULATIVE_EXECUTION OFF)
    set(DCLAW_CONTENT_SCAN OFF)
    set(DCLAW_AUDIT_RAM_BUFFER_SIZE 4)
    set(DCLAW_CANARY_WINDOW_SEC 0)
    set(DCLAW_MAX_SESSIONS 4)
    set(DCLAW_ESCALATION_PAYLOAD_MAX 256)
    set(DCLAW_PENDING_RING_SIZE 4)
elseif(DCLAW_PROFILE STREQUAL "STANDARD")
    set(DCLAW_AUDIT_RING_SIZE 127)
    set(DCLAW_VERDICT_CACHE_SIZE 64)
    set(DCLAW_HEARTBEAT_INTERVAL_SEC 30)
    set(DCLAW_MQTT_ENABLED ON)
    set(DCLAW_PII_REDACTION ON)
    set(DCLAW_BLOOM_FILTER OFF)
    set(DCLAW_SPECULATIVE_EXECUTION ON)
    set(DCLAW_CONTENT_SCAN ON)
    set(DCLAW_AUDIT_RAM_BUFFER_SIZE 16)
    set(DCLAW_CANARY_WINDOW_SEC 600)
    set(DCLAW_MAX_SESSIONS 16)
    set(DCLAW_ESCALATION_PAYLOAD_MAX 1024)
    set(DCLAW_PENDING_RING_SIZE 16)
    if(NOT DEFINED CACHE{DCLAW_DEV_MODE})
        set(DCLAW_DEV_MODE OFF)
    endif()
elseif(DCLAW_PROFILE STREQUAL "EDGE")
    set(DCLAW_AUDIT_RING_SIZE 127)
    set(DCLAW_VERDICT_CACHE_SIZE 256)
    set(DCLAW_HEARTBEAT_INTERVAL_SEC 10)
    set(DCLAW_MQTT_ENABLED ON)
    set(DCLAW_PII_REDACTION ON)
    set(DCLAW_BLOOM_FILTER ON)
    set(DCLAW_SPECULATIVE_EXECUTION ON)
    set(DCLAW_CONTENT_SCAN ON)
    set(DCLAW_AUDIT_RAM_BUFFER_SIZE 32)
    set(DCLAW_CANARY_WINDOW_SEC 600)
    set(DCLAW_MAX_SESSIONS 64)
    set(DCLAW_ESCALATION_PAYLOAD_MAX 2048)
    set(DCLAW_PENDING_RING_SIZE 64)
    if(NOT DEFINED CACHE{DCLAW_DEV_MODE})
        set(DCLAW_DEV_MODE OFF)
    endif()
endif()

# Dev mode flag — controls audit key enforcement behavior.
# ON (default for dev/test): missing DCLAW_AUDIT_KEY uses dev fallback key with warning.
# OFF (required for production): audit ring refuses to start without a real key.
# Installers pass -DDCLAW_DEV_MODE=OFF. CI tests run with ON.
option(DCLAW_DEV_MODE "Enable development mode (relaxed key requirements)" OFF)

# BLOCKER: Warn when building non-MINIMAL profiles with DEV_MODE=ON
if(DCLAW_DEV_MODE AND NOT DCLAW_PROFILE STREQUAL "MINIMAL")
    message(WARNING "⚠ DCLAW_DEV_MODE=ON for ${DCLAW_PROFILE} profile. "
        "Production deployments MUST pass -DDCLAW_DEV_MODE=OFF. "
        "Development mode relaxes audit-key and zero-key checks and permits plaintext MQTT.")
endif()

# Sanitizer support (ASan + UBSan)
option(DCLAW_SANITIZE "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(DCLAW_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# Generate config.h from profile settings
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/config.h
    @ONLY
)

# Compiler flags
add_compile_options(
    -Wall -Wextra -Werror
    -fstack-protector-strong
    -fno-strict-aliasing
    -Os
)

# Hardening.
# Every build type is optimized (-Os above comes after the per-config
# flags), so _FORTIFY_SOURCE applies to all of them, Debug and MinSizeRel
# included. It is incompatible with the sanitizers (ASan intercepts memcpy
# etc.). -U first avoids a redefinition warning (-Werror) on toolchains that
# predefine it.
if(NOT DCLAW_SANITIZE)
    add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
endif()

# Stack-clash probes (ELF toolchains; Apple clang accepts but ignores the
# flag, which -Werror turns into an error).
include(CheckCCompilerFlag)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CMAKE_REQUIRED_FLAGS "-Werror")
    check_c_compiler_flag(-fstack-clash-protection DCLAW_CC_STACK_CLASH_PROTECTION)
    unset(CMAKE_REQUIRED_FLAGS)
    if(DCLAW_CC_STACK_CLASH_PROTECTION)
        add_compile_options(-fstack-clash-protection)
    endif()
endif()

# Position-independent executables (ASLR for the daemon itself), not only
# the shared library. Apple's linker produces PIE by default.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(CheckPIESupported)
check_pie_supported(OUTPUT_VARIABLE _dclaw_pie_msg LANGUAGES C)

# ELF: read-only relocations after start-up, eager binding (no writable
# GOT), and a non-executable stack. These flags do not exist on Mach-O.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    include(CheckLinkerFlag)
    foreach(_flag -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
        string(MAKE_C_IDENTIFIER "DCLAW_LD${_flag}" _var)
        check_linker_flag(C "${_flag}" ${_var})
        if(${_var})
            add_link_options(${_flag})
        endif()
    endforeach()
endif()

# Sources common to all profiles
set(CORE_SOURCES
    src/dclaw_core.c
    src/crypto/sha256.c
    src/crypto/hmac_sha256.c
    src/decision/policy_table.c
    src/decision/ssrf_guard.c
    src/decision/correlator.c
    src/decision/verdict_cache.c
    src/enforce/deferred_reply.c
    src/enforce/ipc_hook.c
    src/enforce/ipc_json.c
    src/enforce/rate_limiter.c
    src/persist/audit_ring.c
    src/persist/config_store.c
    src/platform/hal_linux.c
)

# Sources only for profiles with MQTT
if(DCLAW_MQTT_ENABLED)
    list(APPEND CORE_SOURCES
        src/comms/mqtt_client.c
        src/comms/tls_engine.c
        src/comms/cbor_codec.c
        src/comms/verdict_protocol.c
        src/comms/ota_receiver.c
    )

    # Paho Embedded C MQTT client (vendored) — replaces hand-rolled protocol code.
    # Only the MQTTPacket serializer and MQTTClient-C state machine are needed;
    # we provide our own platform layer (MQTTDclaw.h) for Timer/Network types.
    set(PAHO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/paho-embedded)
    list(APPEND CORE_SOURCES
        ${PAHO_DIR}/MQTTPacket/MQTTPacket.c
        ${PAHO_DIR}/MQTTPacket/MQTTConnectClient.c
        ${PAHO_DIR}/MQTTPacket/MQTTSerializePublish.c
        ${PAHO_DIR}/MQTTPacket/MQTTDeserializePublish.c
        ${PAHO_DIR}/MQTTPacket/MQTTSubscribeClient.c
        ${PAHO_DIR}/MQTTPacket/MQTTUnsubscribeClient.c
        ${PAHO_DIR}/MQTTPacket/MQTTFormat.c
        ${PAHO_DIR}/MQTTClient-C/MQTTClient.c
    )
endif()

# Sources only for profiles with content scanning
if(DCLAW_CONTENT_SCAN)
    list(APPEND CORE_SOURCES
        src/decision/content_scanner.c
    )
endif()

# Main library (static)
add_library(dclaw_core STATIC ${CORE_SOURCES})
target_include_directories(dclaw_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/generated
)

# Shared library (for Python ctypes integration, e.g. PicoClaw hook)
add_library(dclaw_shared SHARED ${CORE_SOURCES})
target_include_directories(dclaw_shared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/generated
)

# Paho Embedded C include paths and platform header selection
if(DCLAW_MQTT_ENABLED)
    set(PAHO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/paho-embedded)
    foreach(_tgt dclaw_core dclaw_shared)
        target_include_directories(${_tgt} PRIVATE
            ${PAHO_DIR}/MQTTPacket
            ${PAHO_DIR}/MQTTClient-C
            ${PAHO_DIR}
        )
        target_compile_definitions(${_tgt} PRIVATE
            MQTTCLIENT_PLATFORM_HEADER=MQTTDclaw.h
            MAX_MESSAGE_HANDLERS=5
        )
    endforeach()
    # Suppress -Werror for vendored Paho sources (we don't control that code)
    set(_PAHO_SOURCES
        ${PAHO_DIR}/MQTTPacket/MQTTPacket.c
        ${PAHO_DIR}/MQTTPacket/MQTTConnectClient.c
        ${PAHO_DIR}/MQTTPacket/MQTTSerializePublish.c
        ${PAHO_DIR}/MQTTPacket/MQTTDeserializePublish.c
        ${PAHO_DIR}/MQTTPacket/MQTTSubscribeClient.c
        ${PAHO_DIR}/MQTTPacket/MQTTUnsubscribeClient.c
        ${PAHO_DIR}/MQTTPacket/MQTTFormat.c
        ${PAHO_DIR}/MQTTClient-C/MQTTClient.c
    )
    set_source_files_properties(${_PAHO_SOURCES} PROPERTIES
        COMPILE_FLAGS "-Wno-error -Wno-unused-parameter -Wno-sign-compare"
    )
endif()
set_target_properties(dclaw_shared PROPERTIES
    OUTPUT_NAME "dclaw_core"
    POSITION_INDEPENDENT_CODE ON
)

# Link mbedTLS for STANDARD/EDGE profiles
if(DCLAW_MQTT_ENABLED)
    # The connector TLS engine uses the mbedTLS 3.x API. Production cannot
    # run with TLS/MQTT stubs; 2.x and 4.x are unsupported.
    set(DCLAW_HAS_USABLE_MBEDTLS OFF)
    find_package(MbedTLS 3 QUIET)
    if(MbedTLS_FOUND AND TARGET MbedTLS::mbedcrypto AND
       MbedTLS_VERSION VERSION_GREATER_EQUAL 3 AND MbedTLS_VERSION VERSION_LESS 4)
        target_link_libraries(dclaw_core PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto)
        target_link_libraries(dclaw_shared PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto)
        target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=1)
        target_compile_definitions(dclaw_shared PRIVATE DCLAW_HAS_MBEDTLS=1)
        set(DCLAW_HAS_USABLE_MBEDTLS ON)
    else()
        find_library(MBEDTLS_LIB mbedtls)
        if(MBEDTLS_LIB)
            get_filename_component(_MBEDTLS_LIBDIR ${MBEDTLS_LIB} DIRECTORY)
            get_filename_component(_MBEDTLS_PREFIX ${_MBEDTLS_LIBDIR} DIRECTORY)
            # 2.x also has entropy.h. Read the actual major-version macro
            # from build_info.h (3.x) or version.h (older packages).
            set(_MBEDTLS_HEADER_DIR "${_MBEDTLS_PREFIX}/include/mbedtls")
            set(_MBEDTLS_MAJOR_HEADER "")
            if(EXISTS "${_MBEDTLS_HEADER_DIR}/build_info.h")
                set(_MBEDTLS_MAJOR_HEADER "${_MBEDTLS_HEADER_DIR}/build_info.h")
            elseif(EXISTS "${_MBEDTLS_HEADER_DIR}/version.h")
                set(_MBEDTLS_MAJOR_HEADER "${_MBEDTLS_HEADER_DIR}/version.h")
            endif()
            if(_MBEDTLS_MAJOR_HEADER)
                file(STRINGS "${_MBEDTLS_MAJOR_HEADER}" _MBEDTLS_MAJOR_LINE
                     REGEX "^#[ \t]*define[ \t]+MBEDTLS_VERSION_MAJOR[ \t]+[0-9]+")
            endif()
            if(_MBEDTLS_MAJOR_LINE MATCHES "MBEDTLS_VERSION_MAJOR[ \t]+3([ \t]|$)" AND
               EXISTS "${_MBEDTLS_HEADER_DIR}/entropy.h")
                target_link_libraries(dclaw_core PRIVATE mbedtls mbedcrypto mbedx509)
                target_link_libraries(dclaw_shared PRIVATE mbedtls mbedcrypto mbedx509)
                target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=1)
                target_compile_definitions(dclaw_shared PRIVATE DCLAW_HAS_MBEDTLS=1)
                set(DCLAW_HAS_USABLE_MBEDTLS ON)
                if(EXISTS "${_MBEDTLS_HEADER_DIR}/ssl.h")
                    target_include_directories(dclaw_core PRIVATE ${_MBEDTLS_PREFIX}/include)
                    target_include_directories(dclaw_shared PRIVATE ${_MBEDTLS_PREFIX}/include)
                endif()
            else()
                if(DCLAW_DEV_MODE)
                    message(WARNING "Unsupported mbedTLS version detected — TLS/MQTT stubs are for development only")
                endif()
                target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=0)
                target_compile_definitions(dclaw_shared PRIVATE DCLAW_HAS_MBEDTLS=0)
            endif()
        else()
            if(DCLAW_DEV_MODE)
                message(WARNING "mbedTLS not found — TLS/MQTT stubs will be used (dev mode)")
            endif()
            target_compile_definitions(dclaw_core PRIVATE DCLAW_HAS_MBEDTLS=0)
            target_compile_definitions(dclaw_shared PRIVATE DCLAW_HAS_MBEDTLS=0)
        endif()
    endif()
    if(NOT DCLAW_DEV_MODE AND NOT DCLAW_HAS_USABLE_MBEDTLS)
        message(FATAL_ERROR "Production ${DCLAW_PROFILE} requires mbedTLS 3.x; TLS/MQTT stubs are only permitted in development mode")
    endif()
endif()

option(DCLAW_ALLOW_HMAC_OTA "Allow HMAC-SHA256 for OTA verification in production" OFF)
if(DCLAW_ALLOW_HMAC_OTA AND DCLAW_MQTT_ENABLED)
    message(STATUS "OTA HMAC explicitly enabled; provision DCLAW_OTA_HMAC_KEY on the device")
    target_compile_definitions(dclaw_core PRIVATE DCLAW_ALLOW_HMAC_OTA=1)
    target_compile_definitions(dclaw_shared PRIVATE DCLAW_ALLOW_HMAC_OTA=1)
elseif(NOT DCLAW_DEV_MODE AND DCLAW_MQTT_ENABLED)
    message(STATUS "OTA updates disabled: Ed25519 verifier unavailable and HMAC not enabled")
endif()

# Main executable
add_executable(edge-connector src/main.c)
target_link_libraries(edge-connector PRIVATE dclaw_core)

# Tests
option(DCLAW_BUILD_TESTS "Build unit tests" ON)
if(DCLAW_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Print build summary
message(STATUS "Edge Connector Configuration:")
message(STATUS "  Profile:          ${DCLAW_PROFILE}")
message(STATUS "  Audit ring:       ${DCLAW_AUDIT_RING_SIZE} entries")
message(STATUS "  Verdict cache:    ${DCLAW_VERDICT_CACHE_SIZE} entries")
message(STATUS "  Sessions:         ${DCLAW_MAX_SESSIONS}")
message(STATUS "  MQTT:             ${DCLAW_MQTT_ENABLED}")
message(STATUS "  Speculative exec: ${DCLAW_SPECULATIVE_EXECUTION}")
message(STATUS "  Canary window:    ${DCLAW_CANARY_WINDOW_SEC}s")

# --- Install targets ---
include(GNUInstallDirs)

# The static library
install(TARGETS dclaw_core
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# The shared library
install(TARGETS dclaw_shared
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# The standalone binary
install(TARGETS edge-connector
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Public headers
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/defenseclaw.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/platform.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/content_scanner.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/sha256.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/hmac_sha256.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/defenseclaw
)

# The PicoClaw hook
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/picoclaw_hook.py
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/defenseclaw
)

# The policy compiler
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/policy_compiler.py
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/defenseclaw
)

# Python adapter hooks
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/generic_hook.py
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/defenseclaw
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/mcp_proxy.py
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/defenseclaw
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/langchain_hook.py
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/defenseclaw
)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/tools/http_middleware.py
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/defenseclaw
)

# Default policy
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/policies/strict.yaml
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/defenseclaw
    RENAME policy.yaml
)
