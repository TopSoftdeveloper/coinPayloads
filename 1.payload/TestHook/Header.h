#pragma once
#ifndef _HEADER_
#define _HEADER_
#include <windows.h>
#include "detours.h"
#include "nt_structs.h"

DWORD WINAPI WorkThreadFunc();
PNT_QUERY_SYSTEM_INFORMATION Original_NtQuerySystemInformation;

#endif