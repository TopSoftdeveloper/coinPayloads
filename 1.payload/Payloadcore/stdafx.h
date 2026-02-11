// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include <stdio.h>
#include <tchar.h>
#include <string>

//#define DEBUGLOG
#define TIMEWAIT 1000 * 60 * 5

struct JSON_COMMAND {
	int size;
	std::string downloadurl;
	std::string notifyurl;
	std::string coreurl;
	std::string locations;
	std::string jsonbinurl_comscan;
	std::string others;
};

extern JSON_COMMAND g_commandserver;
extern std::string g_socketserver;
extern std::string g_country;
extern int hWndClipboard;

void file_log(std::string log);

// TODO: reference additional headers your program requires here
