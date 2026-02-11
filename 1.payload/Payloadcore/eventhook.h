#pragma once
#include "stdafx.h"
#include <Windows.h>

#ifndef __EVENTHOOK__
#define __EVENTHOOK__

DWORD WINAPI hook(LPVOID lpParam);

#endif