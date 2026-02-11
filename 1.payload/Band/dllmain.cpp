#include "pch.h"

#include "MetaString.h"
#include "ObfuscatedCall.h"
#include "ObfuscatedCallWithPredicate.h"
using namespace andrivet::ADVobfuscator;

enum ZBID
{
	ZBID_DEFAULT = 0,
	ZBID_DESKTOP = 1,
	ZBID_UIACCESS = 2,
	ZBID_IMMERSIVE_IHM = 3,
	ZBID_IMMERSIVE_NOTIFICATION = 4,
	ZBID_IMMERSIVE_APPCHROME = 5,
	ZBID_IMMERSIVE_MOGO = 6,
	ZBID_IMMERSIVE_EDGY = 7,
	ZBID_IMMERSIVE_INACTIVEMOBODY = 8,
	ZBID_IMMERSIVE_INACTIVEDOCK = 9,
	ZBID_IMMERSIVE_ACTIVEMOBODY = 10,
	ZBID_IMMERSIVE_ACTIVEDOCK = 11,
	ZBID_IMMERSIVE_BACKGROUND = 12,
	ZBID_IMMERSIVE_SEARCH = 13,
	ZBID_GENUINE_WINDOWS = 14,
	ZBID_IMMERSIVE_RESTRICTED = 15,
	ZBID_SYSTEM_TOOLS = 16,

	//Windows 10+
	ZBID_LOCK = 17,
	ZBID_ABOVELOCK_UX = 18
};

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mutex>
#include <vector>

//INSTALL DETOURS FROM NUGET! (or build from source yourself)
#include "detours.h"

//Definitions
typedef BOOL(WINAPI* SetWindowBand)(IN HWND hWnd, IN HWND hwndInsertAfter, IN DWORD dwBand);
typedef BOOL(WINAPI* NtUserEnableIAMAccess)(IN ULONG64 key, IN BOOL enable);

//Fields
NtUserEnableIAMAccess lNtUserEnableIAMAccess;
SetWindowBand lSetWindowBand;

ULONG64 g_iam_key = 0x0;
bool g_is_detached = false; //To prevent detaching twice.
std::mutex g_mutex;

//Forward functions
BOOL WINAPI NtUserEnableIAMAccessHook(ULONG64 key, BOOL enable);
BOOL SetWindowBandInternal(HWND hWnd, HWND hwndInsertAfter, DWORD dwBand);

//Function for detouring NtUserEnableIAMAccess
VOID AttachHook()
{
	OBFUSCATED_CALL(DetourTransactionBegin);
	OBFUSCATED_CALL(DetourUpdateThread, GetCurrentThread());
	OBFUSCATED_CALL(DetourAttach, &(PVOID&)lNtUserEnableIAMAccess, (PVOID)NtUserEnableIAMAccessHook);
	OBFUSCATED_CALL(DetourTransactionCommit);
}

//Function for restoring NtUserEnableIAMAccess
VOID DetachHook()
{
	g_mutex.lock();
	if (!g_is_detached)
	{
		OBFUSCATED_CALL(DetourTransactionBegin);
		OBFUSCATED_CALL(DetourUpdateThread, GetCurrentThread());
		OBFUSCATED_CALL(DetourDetach, &(PVOID&)lNtUserEnableIAMAccess, NtUserEnableIAMAccessHook);
		OBFUSCATED_CALL(DetourTransactionCommit);
		g_is_detached = true;
	}
	g_mutex.unlock();
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	std::vector<HWND>* pVec = reinterpret_cast<std::vector<HWND>*>(lParam);
	CHAR className[256];
	GetClassNameA(hwnd, className, 256);
	if (strcmp(className, OBFUSCATED("Neutralinojs_webview")) == 0)
	{
		SetWindowBandInternal(hwnd, NULL, ZBID_UIACCESS);
	} else if (strcmp(className, OBFUSCATED("Neutralinojs_blankscreen")) == 0)
	{
		SetWindowBandInternal(hwnd, NULL, ZBID_IMMERSIVE_IHM);
	}

	return TRUE;
}

//Our detoured function
BOOL WINAPI NtUserEnableIAMAccessHook(ULONG64 key, BOOL enable)
{
	const auto res = lNtUserEnableIAMAccess(key, enable);

	if (res == TRUE && !g_iam_key)
	{
		g_iam_key = key;
		DetachHook();

		//Example, for testing only. Don't call it here, make an IPC for that.
		//HWND hwnd = FindWindow(L"Neutralinojs_webview", NULL);
		//SetWindowBandInternal(hwnd, NULL, 18);

		std::vector<HWND> hwnds;
		EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&hwnds));
	}

	return res;
}

//This functions is needed to induce explorer.exe (actually twinui.pcshell.dll) to call NtUserEnableIAMAccess
VOID TryForceIAMAccessCallThread(LPVOID lpParam)
{
	//These 7 calls will force a call into EnableIAMAccess.
	auto hwndFore = GetForegroundWindow();
	auto hwndToFocus = FindWindowA(OBFUSCATED("Shell_TrayWnd"), NULL);
	SetForegroundWindow(GetDesktopWindow()); //This in case Shell_TrayWnd is already focused
	Sleep(100);
	SetForegroundWindow(hwndToFocus); //Focus on the taskbar, should trigger EnableIAMAccess
	Sleep(100);
	SetForegroundWindow(hwndFore); //Restore focus.
}

//Function helper to call SetWindowBand in the proper way.
BOOL SetWindowBandInternal(HWND hWnd, HWND hwndInsertAfter, DWORD dwBand)
{
	if (g_iam_key)
	{
		lNtUserEnableIAMAccess(g_iam_key, TRUE);
		const auto callResult = lSetWindowBand(hWnd, hwndInsertAfter, dwBand);
		lNtUserEnableIAMAccess(g_iam_key, FALSE);

		return callResult;
	}

	return FALSE;
}

//DllMain
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		OBFUSCATED_CALL(DisableThreadLibraryCalls, hModule);

		const auto path = LoadLibraryA(OBFUSCATED("user32.dll"));
		lSetWindowBand = SetWindowBand(GetProcAddress(path, OBFUSCATED("SetWindowBand")));
		lNtUserEnableIAMAccess = NtUserEnableIAMAccess(GetProcAddress(path, MAKEINTRESOURCEA(2510)));

		OBFUSCATED_CALL(AttachHook);

		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)& TryForceIAMAccessCallThread, NULL, NULL, NULL);
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		DetachHook();
	}
	break;
	}
	return TRUE;
}