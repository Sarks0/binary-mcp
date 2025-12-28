#pragma once

// Prevent old winsock from being included by windows.h
#define _WINSOCKAPI_
// Include winsock2 before Windows headers
#include <winsock2.h>
#include <ws2tcpip.h>

#include "pluginsdk/_plugins.h"
#include "pluginsdk/bridgemain.h"  // Required for PLUG_SDKVERSION

#define PLUGIN_NAME "Obsidian"
#define PLUGIN_VERSION 1
#define PLUGIN_VERSION_STR "1.0.0"
#define PLUGIN_DESCRIPTION "AI-Powered Debugging Bridge for x64dbg"
#define PLUGIN_AUTHOR "Binary MCP Project"
#define PLUGIN_WEBSITE "https://github.com/Sarks0/binary-mcp"

// Plugin handles
extern int g_pluginHandle;
extern HWND g_hwndDlg;
extern int g_hMenu;
extern int g_hMenuDisasm;
extern int g_hMenuDump;
extern int g_hMenuStack;

// Plugin initialization
bool pluginInit(PLUG_INITSTRUCT* initStruct);
void pluginStop();
void pluginSetup();

// Logging helpers
void LogInfo(const char* format, ...);
void LogError(const char* format, ...);
void LogDebug(const char* format, ...);
