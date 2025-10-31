cmake_minimum_required(VERSION 3.20)
project(x64dbg_mcp_plugin VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# x64dbg plugin SDK path (user should set this)
set(X64DBG_SDK_PATH "${CMAKE_SOURCE_DIR}/../../../../../extern/x64dbg_sdk" CACHE PATH "Path to x64dbg plugin SDK")

# Check if SDK exists
if(NOT EXISTS "${X64DBG_SDK_PATH}/pluginsdk/_plugins.h")
    message(WARNING "x64dbg SDK not found at ${X64DBG_SDK_PATH}")
    message(WARNING "Please download from: https://github.com/x64dbg/x64dbg/tree/development/src/sdk")
endif()

# Plugin sources
set(PLUGIN_SOURCES
    plugin.cpp
    http_server.cpp
    commands.cpp
    debugger_state.cpp
    x64dbg_stubs.cpp
)

set(PLUGIN_HEADERS
    plugin.h
    http_server.h
    commands.h
    debugger_state.h
)

# Create the plugin DLL
add_library(x64dbg_mcp SHARED ${PLUGIN_SOURCES} ${PLUGIN_HEADERS})

# Include directories
target_include_directories(x64dbg_mcp PRIVATE
    ${X64DBG_SDK_PATH}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against x64dbg SDK
target_link_libraries(x64dbg_mcp PRIVATE
    ws2_32  # Windows sockets
    # Add x64dbg SDK libs if needed
)

# Platform-specific settings
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_ARCH "x64")
else()
    set(PLUGIN_ARCH "x32")
endif()

# Output name: x64dbg_mcp.dp64 or x64dbg_mcp.dp32
set_target_properties(x64dbg_mcp PROPERTIES
    OUTPUT_NAME "x64dbg_mcp"
    SUFFIX ".dp${PLUGIN_ARCH}"
    PREFIX ""
)

# Install target
install(TARGETS x64dbg_mcp
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

# Copy to x64dbg plugins folder if X64DBG_DIR is set
if(DEFINED ENV{X64DBG_DIR})
    add_custom_command(TARGET x64dbg_mcp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        $<TARGET_FILE:x64dbg_mcp>
        "$ENV{X64DBG_DIR}/plugins/"
        COMMENT "Installing plugin to x64dbg"
    )
endif()
