cmake_minimum_required(VERSION 3.20)
project(x64dbg_mcp VERSION 0.2.0 LANGUAGES CXX)

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
)

set(PLUGIN_HEADERS
    plugin.h
    ../pipe_protocol.h
)

# Create the plugin DLL
add_library(x64dbg_mcp SHARED ${PLUGIN_SOURCES} ${PLUGIN_HEADERS})

# Include directories for plugin
target_include_directories(x64dbg_mcp PRIVATE
    ${X64DBG_SDK_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Find and link x64dbg bridge library (provides x64dbg API implementations)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BRIDGE_LIB "${X64DBG_SDK_PATH}/pluginsdk/x64bridge.lib")
else()
    set(BRIDGE_LIB "${X64DBG_SDK_PATH}/pluginsdk/x32bridge.lib")
endif()

if(EXISTS "${BRIDGE_LIB}")
    target_link_libraries(x64dbg_mcp PRIVATE "${BRIDGE_LIB}")
    message(STATUS "Plugin: Linking bridge library: ${BRIDGE_LIB}")
else()
    message(WARNING "Bridge library not found: ${BRIDGE_LIB}")
    message(WARNING "Plugin may fail to load without bridge library!")
endif()

# Output name: x64dbg_mcp.dp64 or x64dbg_mcp.dp32
set_target_properties(x64dbg_mcp PROPERTIES
    OUTPUT_NAME "x64dbg_mcp"
    SUFFIX ".dp${PLUGIN_ARCH}"
    PREFIX ""
)

if(MSVC)
    # Use DYNAMIC runtime to match x64dbg
    set_property(TARGET x64dbg_mcp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
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
add_executable(x64dbg_mcp_server ${SERVER_SOURCES} ${SERVER_HEADERS})

# Include directories for server
target_include_directories(x64dbg_mcp_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

# Link libraries for server
target_link_libraries(x64dbg_mcp_server PRIVATE
    ws2_32  # Windows sockets
)

# Output name: x64dbg_mcp_server.exe
set_target_properties(x64dbg_mcp_server PROPERTIES
    OUTPUT_NAME "x64dbg_mcp_server"
)

if(MSVC)
    # Use DYNAMIC runtime for server too
    set_property(TARGET x64dbg_mcp_server PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreadedDLL$<$<CONFIG:Debug>:Debug>")
    message(STATUS "Server: Using DYNAMIC runtime library (/MD)")
endif()

# =============================================================================
# Installation
# =============================================================================

# Install both plugin and server
install(TARGETS x64dbg_mcp x64dbg_mcp_server
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

# Copy to x64dbg plugins folder if X64DBG_DIR is set
if(DEFINED ENV{X64DBG_DIR})
    # Copy plugin DLL
    add_custom_command(TARGET x64dbg_mcp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:x64dbg_mcp>
        "$ENV{X64DBG_DIR}/plugins/"
        COMMENT "Installing plugin to x64dbg"
    )

    # Copy server executable (must be in same directory as plugin)
    add_custom_command(TARGET x64dbg_mcp_server POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:x64dbg_mcp_server>
        "$ENV{X64DBG_DIR}/plugins/"
        COMMENT "Installing server executable to x64dbg"
    )
endif()

message(STATUS "=== Build Configuration ===")
message(STATUS "Plugin DLL: x64dbg_mcp.dp${PLUGIN_ARCH}")
message(STATUS "Server EXE: x64dbg_mcp_server.exe")
message(STATUS "==========================")
