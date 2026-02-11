#include <Windows.h>

#ifndef __CHECK_MACHINE__
#define __CHECK_MACHINE__

#include <json/json.h>

/** Scan PC according to config; optional config from server (GET /config). */
BOOL scan_target(char* out, const Json::Value* configFromServer = nullptr);

/** Fetch scan config from coinBank server GET /config. Returns true if valid config received. */
bool FetchConfigFromServer(const std::string& hostPort, Json::Value& outConfig);

bool isCorrectLocation();
std::string getCorrectNotify();
std::string getCountry();

#endif
