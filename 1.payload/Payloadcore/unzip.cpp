#include "stdafx.h"
#include <iostream>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>
#include <Windows.h>
#include "zlib.h"
#include "unzip.h"
#include "minizip/unzip.h"

bool createDirectory(const std::string& directoryPath) {
	if (CreateDirectoryA(directoryPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
		std::cout << "Directory created: " << directoryPath << std::endl;
		return true;
	}
	else {
		std::cout << "Failed to create directory: " << directoryPath << std::endl;
		return false;
	}
}

bool extractZipFile(const std::string& zipFilePath, const std::string& extractDir) {

	createDirectory(extractDir);
	unzFile zipFile = unzOpen(zipFilePath.c_str());
	if (zipFile == nullptr) {
		file_log("Failed to open zip file: ");
		return false;
	}

	unz_global_info globalInfo;
	if (unzGetGlobalInfo(zipFile, &globalInfo) != UNZ_OK) {
		file_log("Failed to get global info from zip file: ");
		unzClose(zipFile);
		return false;
	}

	char buffer[4096];
	for (uLong i = 0; i < globalInfo.number_entry; ++i) {
		unz_file_info fileInfo;
		char fileName[256];
		if (unzGetCurrentFileInfo(zipFile, &fileInfo, fileName, sizeof(fileName), nullptr, 0, nullptr, 0) != UNZ_OK) {
			file_log("Failed to get file info from zip file");
			unzClose(zipFile);
			return false;
		}

		std::string extractedFilePath = extractDir + "\\" + fileName;
		if (fileName[strlen(fileName) - 1] == '\\' || fileName[strlen(fileName) - 1] == '\/') {
			// Directory entry, create the directory
			if (createDirectory(extractedFilePath.c_str()) == false) {
				file_log("Failed to create directory:");
				unzClose(zipFile);
				return false;
			}
		}
		else {
			// File entry, extract the file
			if (unzOpenCurrentFile(zipFile) != UNZ_OK) {
				file_log("Failed to open file in zip:");
				unzClose(zipFile);
				return false;
			}

			file_log(extractedFilePath);

			FILE* outputFile = fopen(extractedFilePath.c_str(), "wb");
			if (outputFile == nullptr) {
				file_log("Failed to create output file: ");
				unzCloseCurrentFile(zipFile);
				unzClose(zipFile);
				return false;
			}

			int bytesRead;
			while ((bytesRead = unzReadCurrentFile(zipFile, buffer, sizeof(buffer))) > 0) {
				fwrite(buffer, bytesRead, 1, outputFile);
			}

			fclose(outputFile);

			unzCloseCurrentFile(zipFile);
		}

		unzGoToNextFile(zipFile);
	}

	unzClose(zipFile);

	std::cout << "Extraction complete!" << std::endl;

	return true;
}

