#include <Windows.h>
#include <intrin.h>

void IsVmHypervisor()
{
	int cpuInfo[4] = {};

	// Check bit 31 of the ECX register
	__cpuid(cpuInfo, 1);

	// Bit is clear, no hypervisor
	if (!(cpuInfo[2] & (1 << 31)))
		return;

	// Leaf used by Intel and AMD where vendor strings are stored
	const auto queryVendorIdMagic = 0x40000000;
	
	__cpuid(cpuInfo, queryVendorIdMagic);

	char hyperVendorId[13] = {};

	memcpy(hyperVendorId + 0, &cpuInfo[1], 4);
	memcpy(hyperVendorId + 4, &cpuInfo[2], 4);
	memcpy(hyperVendorId + 8, &cpuInfo[3], 4);
	
	hyperVendorId[12] = '\0';

	const char* vendors[]{
		"Oketquqhv\"Jx",    // Microsoft Hyper-V
		"XOyctgXOyctg",    // VMWare 
		"ZgpXOOZgpXOO",    // Xen 
		"rtn\"j{rgtx\"\"",    // Parallels
		"XDqzXDqzXDqz"     // VirtualBox 
	};

	for (int i = 0; i < 5; i++) 
	{
		char vendor[13] = {};
		memcpy(vendor, vendors[i], 13);
		
		for (int i = 0; i < 13; i++) {
			vendor[i] = vendor[i] - 2;
		}
		
		if (!memcmp(vendor, hyperVendorId, 13)) exit(0);
	}
}

// Check against typical sandbox hardware restrictions
void CpuHas2Cores()
{
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	
	if (systemInfo.dwNumberOfProcessors < 2) exit(0);
}

void RamIs2Gb()
{
	MEMORYSTATUSEX memoryStatus{};
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullAvailPhys / 1024 / 1024;
	
	if (RAMMB < 2000) exit(0);
}

void HddIs100Gb()
{
	ULARGE_INTEGER freeBytesAvailable;
	ULARGE_INTEGER totalNumberOfBytes;
	ULARGE_INTEGER totalNumberOfFreeBytes;
	GetDiskFreeSpaceEx(NULL, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes);
	DWORD HDDGB = totalNumberOfBytes.QuadPart / 1024 / 1024 / 1024;
	
	if (HDDGB < 100) exit(0);
}

void SystemHasCorrectHardware()
{
	CpuHas2Cores();
	RamIs2Gb();
	HddIs100Gb();
	IsVmHypervisor();
}
