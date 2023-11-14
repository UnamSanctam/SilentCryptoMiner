#pragma once

#include <windows.h>

HANDLE process_hollowing(wchar_t* programPath, wchar_t* cmdLine, wchar_t* runtimeData, BYTE* payloadBuf, wchar_t* startDir);