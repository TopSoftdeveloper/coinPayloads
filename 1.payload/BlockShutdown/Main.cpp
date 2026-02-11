#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <winuser.h>
#include <Shlwapi.h>
#include <string>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include "detours.h"
#include <fstream>
#include "DebugInfo.h"
#include "MetaString.h"
#include "ObfuscatedCall.h"
#include "ObfuscatedCallWithPredicate.h"

#pragma comment(lib,"shlwapi.lib")

using namespace std;
using namespace andrivet::ADVobfuscator;

typedef RPC_STATUS(NTAPI* RPCSERVERTESTCANCEL)(
	RPC_BINDING_HANDLE BindingHandle
	);
static RPCSERVERTESTCANCEL OriginalRpcServerTestCancel = NULL;
static RPC_STATUS NTAPI HookedRpcServerTestCancel(
	RPC_BINDING_HANDLE BindingHandle
)
{
	//disable temp error
	HANDLE hMutex = OpenMutex(SYNCHRONIZE, FALSE, OBFUSCATED("Global\\BLOCK_SHUTDOWN_UPDATE"));

	if (hMutex != nullptr) {
		HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, false, OBFUSCATED("Global\\BLOCK_SHUTDOWN_UPDATE_SHOW"));

		if (hEvent) {
			SetEvent(hEvent);
			CloseHandle(hEvent);
		}

		CloseHandle(hMutex);
		return RPC_S_OK;
	}

	//disable temp error
	HANDLE hMutex1 = OpenMutex(SYNCHRONIZE, FALSE, OBFUSCATED("Global\\BLOCK_SHUTDOWN_TURNOFF"));

	if (hMutex1 != nullptr) {
		HANDLE hEvent = OpenEvent(EVENT_MODIFY_STATE, false, OBFUSCATED("Global\\BLOCK_SHUTDOWN_TURNOFF_SHOW"));

		if (hEvent) {
			SetEvent(hEvent);
			CloseHandle(hEvent);
		}

		CloseHandle(hMutex1);
		return RPC_S_OK;
	}


	return OriginalRpcServerTestCancel(BindingHandle);
}

static void InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);
	typedef int (*DetourAttatchType)(PVOID*, PVOID);
	DetourAttatchType tempfunc = reinterpret_cast<DetourAttatchType>(&DetourAttach);

	if (*originalFunction)
		OBFUSCATED_CALL(tempfunc, originalFunction, hookedFunction);
}


static DWORD WINAPI WorkThreadFunc()
{
	OBFUSCATED_CALL(DetourTransactionBegin);
	OBFUSCATED_CALL(DetourUpdateThread, GetCurrentThread());
#ifdef _WIN64
	InstallHook(OBFUSCATED("Rpcrt4.dll"), OBFUSCATED("RpcServerTestCancel"), (LPVOID*)& OriginalRpcServerTestCancel, HookedRpcServerTestCancel);
#else
	//InstallHook("User32.dll", "SetWindowDisplayAffinity", (LPVOID*)&OriginalSetWindowDisplayAffinity, HookedInitiateSystemShutdownExA);
#endif
	OBFUSCATED_CALL(DetourTransactionCommit);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		OBFUSCATED_CALL(DisableThreadLibraryCalls, hMoudle);
		OBFUSCATED_CALL(WorkThreadFunc);
	}

	break;
	case DLL_PROCESS_DETACH:
	{

	}
	break;
	}
	return TRUE;
}