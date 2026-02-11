#pragma once

#ifndef _UTIL_HEADER_
#define _UTIL_HEADER_

#include "stdafx.h"
#include "resource.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <string>
#include <fstream>
#include <time.h>
#include <shlobj.h>
#include <tchar.h>
#include <strsafe.h>
#include <aclapi.h>
#include <stdio.h>
#include <Windows.h>
#include <UserEnv.h>
#include <shlwapi.h>
#include <regex>
#include <WtsApi32.h>
#include <locale>
#include <codecvt>
#include <filesystem>
#include <filesystem>
#include <json/json.h>
#include <sddl.h>

using namespace std;

bool IsTargetProcess(CHAR* pszName, std::string processname);

void WINAPI InjectLib(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr);

std::wstring to_wide_string(const std::string& input);

std::string to_byte_string(const std::wstring& input);

std::string getExePath();

const std::string currentDate();

const std::string currentDateTime();

Json::Value parseJson(const string& json);

string stringifyJson(const Json::Value& val);

void run_in_service(string Path, int nShow = SW_HIDE);

int exist_directory(std::string& pathname);

bool exist_file(const std::string& name);

void killProcessByName(string filename);

BOOL InstallHookDll(const char* pDllPath, std::string attach, bool bUnloadneeded);

BOOL IsProcessRunning(string filename, BOOL critical);

BOOL IsProcessRunning(DWORD proessid);

std::string randomName(int length, string extension);

std::string GetComputerUid();

BOOL EnableDebugPrivilege();

BOOL MakeSchedule(std::string time);

std::string convertWideToChar(const std::wstring& wstr);

bool IsProcessActiveWindow(DWORD processId);

void DoClearFolder();

void DoClearFolderNotExit();

std::string GetMacAddress();

std::string MacAddressToLicenseKey(const std::string& macAddress);

bool CreateDirectoryRecursively(const std::string& path);

void notifytoserver(std::string notifyurl);

bool DownloadFile(const std::string& url, const std::string& outputPath);

bool GetJsonResponse(const std::string& url, std::string& jsonResponse);

bool PostJsonToServer(const std::string& url, std::string& body, std::string& response);

std::string removeNonASCII(const std::string& input);

bool isNonAscii(char c);

std::string string_replace(std::string src, std::string const& target, std::string const& repl);

std::string ToLower(const std::string& str);

int getStringSID(LPWSTR szSID);

std::string getHMACSHA256(unsigned char* key, const char* pszBuffer);

bool dirExists(LPCTSTR strPath);

int DeleteDirectory(const std::wstring& refcstrRootDirectory, bool bDeleteSubdirectories);

void CreateProcessCommand(char* commandStr);

BOOL is64BitSystem();

void runExitProcess(BOOL rpctestunload);

DWORD GetProcessIdFromName(string filename);

void WINAPI UnloadLib(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr);

bool isChromeExtensionActive();

void manageHostFile(const std::string& active, const std::string& dns, const std::string& ip);
#endif