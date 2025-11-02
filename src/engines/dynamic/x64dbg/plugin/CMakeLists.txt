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

# Add x64dbg SDK bridge source if it exists
# The bridge provides implementations for DbgIsDebugging, DbgIsRunning, etc.
if(EXISTS "${X64DBG_SDK_PATH}/pluginsdk/_plugin_types.h")
    # Modern SDK structure
    if(EXISTS "${X64DBG_SDK_PATH}/pluginsdk/bridgemain.cpp")
        list(APPEND PLUGIN_SOURCES "${X64DBG_SDK_PATH}/pluginsdk/bridgemain.cpp")
        message(STATUS "Using SDK bridgemain.cpp")
    elseif(EXISTS "${X64DBG_SDK_PATH}/pluginsdk/_plugins.cpp")
        list(APPEND PLUGIN_SOURCES "${X64DBG_SDK_PATH}/pluginsdk/_plugins.cpp")
        message(STATUS "Using SDK _plugins.cpp")
    else()
        message(WARNING "SDK bridge source file not found")
    endif()
endif()

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

# Platform-specific settings MUST come before we try to link libraries
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(PLUGIN_ARCH "64")
    set(BRIDGE_ARCH "x64")
else()
    set(PLUGIN_ARCH "32")
    set(BRIDGE_ARCH "x32")
endif()

# Link x64dbg SDK bridge library - provides DbgIsDebugging, DbgIsRunning, etc.
# Try multiple possible locations and names
set(BRIDGE_LIB_FOUND FALSE)
set(POSSIBLE_LIBS
    "${X64DBG_SDK_PATH}/pluginsdk/${BRIDGE_ARCH}bridge.lib"
    "${X64DBG_SDK_PATH}/pluginsdk/lib/${BRIDGE_ARCH}bridge.lib"
    "${X64DBG_SDK_PATH}/pluginsdk/bridgemain.lib"
    "${X64DBG_SDK_PATH}/${BRIDGE_ARCH}bridge.lib"
)

foreach(LIB_PATH ${POSSIBLE_LIBS})
    if(EXISTS "${LIB_PATH}" AND NOT BRIDGE_LIB_FOUND)
        message(STATUS "Found x64dbg bridge library: ${LIB_PATH}")
        target_link_libraries(x64dbg_mcp PRIVATE "${LIB_PATH}")
        set(BRIDGE_LIB_FOUND TRUE)
    endif()
endforeach()

if(NOT BRIDGE_LIB_FOUND)
    message(WARNING "x64dbg bridge library not found - plugin may fail to link")
    message(WARNING "Searched locations: ${POSSIBLE_LIBS}")
    # List SDK contents for debugging
    if(EXISTS "${X64DBG_SDK_PATH}/pluginsdk")
        file(GLOB SDK_CONTENTS "${X64DBG_SDK_PATH}/pluginsdk/*")
        message(STATUS "SDK contents: ${SDK_CONTENTS}")
    endif()
endif()

# Output name: x64dbg_mcp.dp64 or x64dbg_mcp.dp32
# (PLUGIN_ARCH already set above for bridge library detection)
set_target_properties(x64dbg_mcp PROPERTIES
    OUTPUT_NAME "x64dbg_mcp"
    SUFFIX ".dp${PLUGIN_ARCH}"
    PREFIX ""
)

# x64dbg provides API functions at runtime via the SDK
# The plugin SDK provides stub implementations that resolve at runtime
if(MSVC)
    # Use static runtime to avoid VC++ redistributable dependencies
    set_property(TARGET x64dbg_mcp PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
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
