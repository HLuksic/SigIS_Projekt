#include <Windows.h>

// Check against typical sandbox hardware restrictions

bool CpuHas2Cores()
{
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	
	if (systemInfo.dwNumberOfProcessors < 2) return false;
	
	return true;
}

bool RamIs2Gb()
{
	MEMORYSTATUSEX memoryStatus{};
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullAvailPhys / 1024 / 1024;
	
	if (RAMMB < 2000) return false;
	
	return true;
}

bool HddIs100Gb()
{
	ULARGE_INTEGER freeBytesAvailable;
	ULARGE_INTEGER totalNumberOfBytes;
	ULARGE_INTEGER totalNumberOfFreeBytes;
	GetDiskFreeSpaceEx(NULL, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes);
	DWORD HDDGB = totalNumberOfBytes.QuadPart / 1024 / 1024 / 1024;
	
	if (HDDGB < 100) return false;

	return true;
}

bool SystemHasSufficientHardware()
{
	return CpuHas2Cores() && RamIs2Gb() && HddIs100Gb();
}
