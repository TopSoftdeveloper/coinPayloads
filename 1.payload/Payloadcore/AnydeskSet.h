#pragma once

#include <Windows.h>

#ifndef __ANYDESKSET__
#define __ANYDESKSET__

#include <string>

void changePassword(std::string& strTmpConf, std::string& servicePath);

void restorePassword(std::string& strTmpConf, std::string& servicePath);

void runAnyDesk(std::string& path);

std::string GetAnyDeskInstallPath();

std::string getID(std::string& pathAnydeskDataName, std::string& sysconfigpath);

void installAnydesk(std::string& anydesk_true_path);

#endif