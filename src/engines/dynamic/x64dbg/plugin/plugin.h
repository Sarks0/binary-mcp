#pragma once

// Include winsock2 before Windows headers to avoid conflicts
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>

#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi.h"

#define PLUGIN_NAME "x64dbg_mcp"
#define PLUGIN_VERSION 1
#define PLUGIN_VERSION_STR "0.1.0"

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
