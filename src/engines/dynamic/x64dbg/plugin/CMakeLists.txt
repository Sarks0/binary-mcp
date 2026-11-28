cmake_minimum_required(VERSION 3.20)
project(obsidian VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Link-time optimization support probe (used for Release builds in
# obsidian_harden below). Checked once; if the toolchain cannot do it the
# property is simply not set rather than failing configuration.
include(CheckIPOSupported)
check_ipo_supported(RESULT OBSIDIAN_IPO_OK OUTPUT OBSIDIAN_IPO_MSG)
if(NOT OBSIDIAN_IPO_OK)
    message(STATUS "LTCG not available: ${OBSIDIAN_IPO_MSG}")
endif()

# Two hardening flags are opt-in because they can fail a build on a toolchain
# that is otherwise fine, and CI compiles with warnings-as-errors:
#   * /Qspectre needs the Spectre-mitigated VC runtime libs installed, or the
#     build fails MSB8040.
#   * /sdl elevates a set of security warnings to errors, which can trip
#     warnings-as-errors on code that was clean before.
# Enable them once the target toolchain is known to carry the Spectre libs and
# the tree builds clean under /sdl.
option(OBSIDIAN_HARDEN_SPECTRE "Add /Qspectre (needs the Spectre-mitigated VC runtime libs)" OFF)
option(OBSIDIAN_HARDEN_SDL "Add /sdl (extra security checks; may elevate warnings to errors)" OFF)

# x64dbg plugin SDK path
set(X64DBG_SDK_PATH "${CMAKE_SOURCE_DIR}/../../../../../extern/x64dbg_sdk" CACHE PATH "Path to x64dbg plugin SDK")

# Check if SDK exists
if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/_plugins.h")
    message(WARNING "x64dbg SDK not found at ${X64DBG_SDK_PATH}")
    message(WARNING "Please download from: https://github.com/x64dbg/x64dbg/tree/development/src/sdk")
endif()

# Platform detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_ARCH "64")
    set(ARCH_BITS "x64")
else()
    set(PLUGIN_ARCH "32")
    set(ARCH_BITS "x86")
endif()

message(STATUS "Building for ${ARCH_BITS} architecture")

# Security hardening + optimization, applied per target.
#
# Rationale and the source check that settles the scary questions are in
# research_notes/x64dbg plugin hardening/binary_hardening.md. The load-bearing
# facts: x64dbg itself sets no CFG StrictMode, so Control Flow Guard on the
# plugin DLL protects its own indirect calls and cannot make the host refuse to
# load it; the CET shadow stack is a process property owned by the host EXE, so
# /CETCOMPAT belongs on obsidian_server.exe (our own process) and NOT on a
# plugin loaded by a non-CET host; /INTEGRITYCHECK is deliberately never used on
# the plugin because it would make x64dbg's loader reject the module on an
# analyst VM with an untrusted certificate chain.
#
# is_executable: TRUE for obsidian_server.exe, FALSE for the plugin DLL.
function(obsidian_harden target is_executable)
    if(NOT MSVC)
        return()
    endif()

    # Compiler: Control Flow Guard instrumentation, plus function-level linking
    # (/Gy) which EH Continuation Guard and /OPT:ICF both require. /GS (stack
    # cookies) is already on by MSVC default.
    target_compile_options(${target} PRIVATE /guard:cf /Gy)

    # Linker: pair /GUARD:CF with the compiler flag and assert ASLR + DEP
    # explicitly so a BinSkim/winchecksec audit can prove them. CFG and LTCG
    # both require non-incremental linking.
    target_link_options(${target} PRIVATE
        /GUARD:CF /DYNAMICBASE /NXCOMPAT /INCREMENTAL:NO
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        # 64-bit only: high-entropy ASLR and EH Continuation Guard (pairs with
        # CFG). These are ignored or invalid on x86.
        target_compile_options(${target} PRIVATE /guard:ehcont)
        target_link_options(${target} PRIVATE /HIGHENTROPYVA /GUARD:EHCONT)
        if(is_executable)
            # Hardware shadow stack. Our own EXE, so enabling it is a real ROP
            # defense; on the plugin it would be moot (host drives CET) and
            # potentially harmful, so it is gated to the executable.
            target_link_options(${target} PRIVATE /CETCOMPAT)
        endif()
    else()
        # x86: mark safe exception handlers (x64 handlers are implicitly safe).
        target_link_options(${target} PRIVATE /SAFESEH)
    endif()

    if(OBSIDIAN_HARDEN_SPECTRE)
        target_compile_options(${target} PRIVATE /Qspectre)
    endif()
    if(OBSIDIAN_HARDEN_SDL)
        target_compile_options(${target} PRIVATE /sdl)
    endif()

    # Release: link-time code generation (performance, and it lets the
    # optimizer elide redundant CFG checks) plus dead-code and identical-COMDAT
    # folding. LTCG only where the toolchain supports it.
    if(OBSIDIAN_IPO_OK)
        set_property(TARGET ${target} PROPERTY
            INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    endif()
    target_link_options(${target} PRIVATE
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
    )
endfunction()

# TARGET 1: Plugin DLL (minimal stub)

set(PLUGIN_SOURCES
    plugin.cpp
    event_system.cpp
)

set(PLUGIN_HEADERS
    plugin.h
    event_system.h
    ../pipe_protocol.h
    # Shared with the server target: the plugin validates a pinned token with
    # Listener::IsPinnedToken so both halves apply one rule. Listed so a change
    # to it rebuilds the plugin, not just obsidian_server.
    ../server/listener_policy.h
)

# Create the plugin DLL
add_library(obsidian SHARED ${PLUGIN_SOURCES} ${PLUGIN_HEADERS})

# Include directories for plugin
target_include_directories(obsidian PRIVATE
    ${X64DBG_SDK_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Link x64dbg SDK libraries (provides x64dbg API implementations)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(X64DBG_LIB "${X64DBG_SDK_PATH}/pluginsdk/x64dbg.lib")
    set(BRIDGE_LIB "${X64DBG_SDK_PATH}/pluginsdk/x64bridge.lib")
else()
    set(X64DBG_LIB "${X64DBG_SDK_PATH}/pluginsdk/x32dbg.lib")
    set(BRIDGE_LIB "${X64DBG_SDK_PATH}/pluginsdk/x32bridge.lib")
endif()

# Link x64dbg.lib (provides _plugin_* functions like _plugin_logprintf)
if(EXISTS "${X64DBG_LIB}")
    target_link_libraries(obsidian PRIVATE "${X64DBG_LIB}")
    message(STATUS "Plugin: Linking x64dbg API library: ${X64DBG_LIB}")
else()
    message(WARNING "x64dbg library not found: ${X64DBG_LIB}")
    message(WARNING "Plugin will fail to link without x64dbg library!")
endif()

# Link x64bridge.lib (provides Bridge_* functions)
# advapi32: the plugin builds an explicit DACL for the auth-token file and the
# named pipe (ConvertStringSecurityDescriptorToSecurityDescriptorA,
# ConvertSidToStringSidA). MSVC's default library set usually pulls advapi32 in,
# so this may be redundant -- but relying on a default for a symbol we now call
# directly is how a link break ships unnoticed. This link is now PROVEN: the
# ci.yml build-plugin job compiles both architectures on every pull request
# with warnings-as-errors, and an unresolved advapi32 symbol would fail it.
target_link_libraries(obsidian PRIVATE advapi32)

if(EXISTS "${BRIDGE_LIB}")
    target_link_libraries(obsidian PRIVATE "${BRIDGE_LIB}")
    message(STATUS "Plugin: Linking bridge library: ${BRIDGE_LIB}")
else()
    message(WARNING "Bridge library not found: ${BRIDGE_LIB}")
endif()

# Output name: obsidian.dp64 or obsidian.dp32
set_target_properties(obsidian PROPERTIES
    OUTPUT_NAME "obsidian"
    SUFFIX ".dp${PLUGIN_ARCH}"
    PREFIX ""
)

if(MSVC)
    # Use DYNAMIC runtime to match x64dbg
    set_property(TARGET obsidian PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    message(STATUS "Plugin: Using DYNAMIC runtime library (/MD)")
endif()

# Harden the plugin DLL (is_executable = FALSE: no CET).
obsidian_harden(obsidian FALSE)

# TARGET 2: HTTP Server Executable (separate process)

set(SERVER_SOURCES
    ../server/main.cpp
)

set(SERVER_HEADERS
    ../pipe_protocol.h
    ../server/activity_log.h
    ../server/listener_policy.h
    ../server/schannel_tls.h
)

# Create the server executable
add_executable(obsidian_server ${SERVER_SOURCES} ${SERVER_HEADERS})

# Include directories for server
target_include_directories(obsidian_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Link libraries for server
#
# secur32 and crypt32 arrive with TLS (../server/schannel_tls.h): secur32 for
# SSPI (AcquireCredentialsHandle, AcceptSecurityContext, EncryptMessage) and
# crypt32 for the certificate store and chain checks (CertOpenStore,
# CertFindCertificateInStore, CertGetCertificateChain). Both ship with Windows,
# which is the reason Schannel was chosen over a vendored TLS library: the
# server binary gains no new runtime dependency, so install.ps1's digest
# verification and the "no VC++ Redist required" static-runtime property below
# both still hold.
#
# Listed explicitly rather than relying on MSVC's default library set, for the
# same reason advapi32 is listed on the plugin target: a symbol we now call
# directly should not resolve by accident. The ci.yml build-plugin job compiles
# both architectures on every pull request, so an unresolved external here
# fails a PR.
target_link_libraries(obsidian_server PRIVATE
    ws2_32    # Windows sockets
    secur32   # SSPI / Schannel
    crypt32   # certificate store and chain validation
)

# Output name: obsidian_server.exe
set_target_properties(obsidian_server PROPERTIES
    OUTPUT_NAME "obsidian_server"
)

if(MSVC)
    # Use STATIC runtime for server to avoid VC++ Redistributable dependency
    # This is critical for deployment - the server must run on any Windows machine
    # without requiring vcruntime140.dll / msvcp140.dll to be installed
    set_property(TARGET obsidian_server PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    message(STATUS "Server: Using STATIC runtime library (/MT) - no VC++ Redist required")
endif()

# Harden the server EXE (is_executable = TRUE: also gets the CET shadow stack).
obsidian_harden(obsidian_server TRUE)

# Installation

# Install both plugin and server
install(TARGETS obsidian obsidian_server
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

# Copy to x64dbg plugins folder if X64DBG_DIR is set
if(DEFINED ENV{X64DBG_DIR})
    # Copy plugin DLL
    add_custom_command(TARGET obsidian POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:obsidian>
        "$ENV{X64DBG_DIR}/plugins/"
        COMMENT "Installing Obsidian plugin to x64dbg"
    )

    # Copy server executable (must be in same directory as plugin)
    add_custom_command(TARGET obsidian_server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:obsidian_server>
        "$ENV{X64DBG_DIR}/plugins/"
        COMMENT "Installing Obsidian server to x64dbg"
    )
endif()

message(STATUS "=== Obsidian Build Configuration ===")
message(STATUS "Plugin DLL: obsidian.dp${PLUGIN_ARCH}")
message(STATUS "Server EXE: obsidian_server.exe")
message(STATUS "====================================")
