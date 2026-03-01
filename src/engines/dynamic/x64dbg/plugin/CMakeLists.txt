cmake_minimum_required(VERSION 3.20)
project(obsidian VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# =============================================================================
# TARGET 1: Plugin DLL (minimal stub)
# =============================================================================

set(PLUGIN_SOURCES
    plugin.cpp
    event_system.cpp
)

set(PLUGIN_HEADERS
    plugin.h
    event_system.h
    ../pipe_protocol.h
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
    set_property(TARGET obsidian PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
    message(STATUS "Plugin: Using DYNAMIC runtime library (/MD)")
endif()

# =============================================================================
# TARGET 2: HTTP Server Executable (separate process)
# =============================================================================

set(SERVER_SOURCES
    ../server/main.cpp
)

set(SERVER_HEADERS
    ../pipe_protocol.h
)

# Create the server executable
add_executable(obsidian_server ${SERVER_SOURCES} ${SERVER_HEADERS})

# Include directories for server
target_include_directories(obsidian_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Link libraries for server
target_link_libraries(obsidian_server PRIVATE
    ws2_32  # Windows sockets
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

# =============================================================================
# Installation
# =============================================================================

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
