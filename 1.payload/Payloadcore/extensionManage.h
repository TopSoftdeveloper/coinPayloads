#pragma once
#ifndef __EXTENSION_MANAGE_H__
#define __EXTENSION_MANAGE_H__

#include "utils.h"
#include "unzip.h"
#include "json.hpp"
#include <Windows.h>

bool uninstallExtension(std::string name);

bool installExtension(const char* zipfilePath);

#endif // !__EXTENSION_MANAGE_H__
