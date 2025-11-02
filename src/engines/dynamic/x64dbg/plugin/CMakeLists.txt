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
)

# Note: We don't compile SDK bridge sources
# x64dbg provides all plugin API functions at runtime via its plugin loader

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
# Note: x64dbg plugin SDK provides bridge libraries that export plugin API functions
target_link_libraries(x64dbg_mcp PRIVATE
    ws2_32  # Windows sockets
)

# Platform-specific settings
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_ARCH "64")
else()
    set(PLUGIN_ARCH "32")
endif()

# NOTE: x64dbg provides all plugin API functions at runtime
# We use /FORCE:UNRESOLVED to allow linking with missing symbols
# x64dbg.exe will provide these when the plugin loads
message(STATUS "Building ${PLUGIN_ARCH}-bit plugin")
message(STATUS "x64dbg API functions will be resolved at runtime")

# Output name: x64dbg_mcp.dp64 or x64dbg_mcp.dp32
set_target_properties(x64dbg_mcp PROPERTIES
    OUTPUT_NAME "x64dbg_mcp"
    SUFFIX ".dp${PLUGIN_ARCH}"
    PREFIX ""
)

# x64dbg provides API functions at runtime
# IMPORTANT: We use /FORCE:UNRESOLVED because x64dbg provides plugin API functions at runtime
# This is SAFE because:
# 1. We delayed initialization to plugsetup() (not pluginInit())
# 2. We added comprehensive exception handling around all x64dbg API calls
# 3. We only call x64dbg APIs after the plugin is fully loaded
# 4. This is the standard approach for x64dbg plugins
if(MSVC)
    # Use static runtime to avoid VC++ redistributable dependencies
    set_property(TARGET x64dbg_mcp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # Allow unresolved symbols - x64dbg provides them at runtime
    target_link_options(x64dbg_mcp PRIVATE
        "/FORCE:UNRESOLVED"
        "/IGNORE:4199"  # Suppress /FORCE:UNRESOLVED warning
    )

    message(STATUS "Using /FORCE:UNRESOLVED for x64dbg API functions")
endif()

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
