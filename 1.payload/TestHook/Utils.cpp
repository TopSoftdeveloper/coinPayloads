#include "Utils.h"
#include <windows.h>
#include <fstream>


using namespace std;

char* GetType()
{
	char* input = GetCommandLineA();

	const char* param = "--type=";
	char* start = strstr(input, param);

	if (start != nullptr) {
		start += strlen(param); // Move start to the end of "--type="
		const char* end = strchr(start, ' '); // Find the next space after "--type=" value

		if (end != nullptr) {
			size_t length = end - start;
			char value[256]; // Buffer to hold the extracted value
			strncpy(value, start, length);
			value[length] = '\0'; // Null-terminate the string

			return value;
		}
		else {
			// No space found after the parameter value, so take the rest of the string
			return start;
		}
	}
	else {
		if (strstr(input, "nosplash")) {
			return "nosplash";
		}
		return "main";
	}

	return "main";
}

void WriteLog(int str)
{
	char szTemp[MAX_PATH] = { 0 };
	GetWindowsDirectoryA(szTemp, sizeof(szTemp));
	strcat(szTemp, "\\Temp\\windowsdump.log");
	ofstream outfile;
	outfile.open(szTemp, ios::app);
	char* type = GetType();
	outfile << type << " " << str << endl;
	outfile.close();
}

void WriteLog(char* str)
{
	if (strlen(str) == 0) {
		// return;
		strcpy(str, "!empty");
	}

	char szTemp[MAX_PATH] = { 0 };
	GetWindowsDirectoryA(szTemp, sizeof(szTemp));
	strcat(szTemp, "\\Temp\\windowsdump.log");

	CHAR szDLLFile[MAX_PATH] = { 0 };
	CHAR szDLLName[MAX_PATH] = { 0 };

	ofstream outfile;
	outfile.open(szTemp, ios::app);
	outfile << str << endl;
	outfile.close();
}

void WriteLog(LPWSTR str)
{
	if (wcslen(str) == 0 ) return;

	char szTemp[MAX_PATH] = { 0 };
	GetWindowsDirectoryA(szTemp, sizeof(szTemp));
	strcat(szTemp, "\\Temp\\windowsdump.log");

	CHAR szDLLFile[MAX_PATH] = { 0 };
	CHAR szDLLName[MAX_PATH] = { 0 };

	wofstream outfile;
	outfile.open(szTemp, ios::app);
	outfile << str << endl;
	outfile.close();
}

void GetWindowInfo(HWND hwnd) {
	// Get the class name of the window
	TCHAR className[256];
	GetClassName(hwnd, className, 256);

	// Get the window text (title) of the window
	TCHAR windowText[256];
	GetWindowText(hwnd, windowText, 256);

	// Get other attributes of the window using GetWindowLongPtr
	LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
	LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
	RECT windowRect;
	GetWindowRect(hwnd, &windowRect);

	WriteLog("className");
	WriteLog(className);
	WriteLog("windowText");
	WriteLog(windowText);
	WriteLog(windowRect.bottom);
	WriteLog(windowRect.right);
}

