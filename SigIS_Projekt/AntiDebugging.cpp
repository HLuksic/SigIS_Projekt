#include <Windows.h>
#include<windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <intrin.h>
#include <stdio.h>
#include <sys/types.h>
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
#define ProcessDebugObjectHandle 0x1E
#define ProcessDebugFlags 0x1F
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x4

bool checkIfRemoteDebuggerPresent()
{
	BOOL isDebuggerPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
	return isDebuggerPresent;
}

bool checkSpecifigDebuggerFlagsSet()
{
	PDWORD pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);
	return (*pNtGlobalFlag) & NT_GLOBAL_FLAG_DEBUGGED;
}

bool checkHeapDebuggerFlagSet()
{
	PDWORD pHeapFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x70);
	PDWORD pHeapForceFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x74);
	return *pHeapFlags ^ HEAP_GROWABLE || *pHeapForceFlags != 0;
}

bool checkProcessDebugObjectHandle()
{
	typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(IN HANDLE, IN PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG);
	PNtQueryInformationProcess pNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	HANDLE hProcessDebugObject = NULL;
	DWORD processDebugFlags = 0;
	pNtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &hProcessDebugObject, sizeof HANDLE, NULL);
	pNtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugFlags, &processDebugFlags, sizeof DWORD, NULL);
	return hProcessDebugObject != NULL || processDebugFlags == 0;
}

#pragma comment(linker, "/INCREMENTAL:YES")

DWORD CalculateFunctionChecksum(PUCHAR functionStart, PUCHAR functionEnd)
{
	DWORD checksum = 0;
	while (functionStart < functionEnd)
	{
		checksum += *functionStart;
		functionStart++;
	}
	return checksum;
}
#pragma auto_inline(off)

VOID CrucialFunction()
{
	int x = 0;
	x += 2;
}

VOID AfterCrucialFunction()
{
};
#pragma auto_inline(on)

bool detectSoftwareBreakpoints() 
{
	DWORD originalChecksum = 3429;
	DWORD checksum = CalculateFunctionChecksum((PUCHAR)CrucialFunction, (PUCHAR)AfterCrucialFunction);
	return checksum != originalChecksum;
}

bool detectHardwareBreakpoints()
{
	CONTEXT context = {};
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	GetThreadContext(GetCurrentThread(), &context);
	return context.Dr0 || context.Dr1 || context.Dr2  || context.Dr3;
}

bool detectBreakpointsByMemoryPages()
{
	BOOL debugged = false;

	PSAPI_WORKING_SET_INFORMATION workingSetInfo;
	QueryWorkingSet(GetCurrentProcess(), &workingSetInfo, sizeof workingSetInfo);
	DWORD requiredSize = sizeof PSAPI_WORKING_SET_INFORMATION * (workingSetInfo.NumberOfEntries + 20);
	PPSAPI_WORKING_SET_INFORMATION pWorkingSetInfo = (PPSAPI_WORKING_SET_INFORMATION)VirtualAlloc(0, requiredSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	BOOL s = QueryWorkingSet(GetCurrentProcess(), pWorkingSetInfo, requiredSize);

	for (int i = 0; i < pWorkingSetInfo->NumberOfEntries; i++)
	{
		PVOID physicalAddress = (PVOID)(pWorkingSetInfo->WorkingSetInfo[i].VirtualPage * 4096);
		MEMORY_BASIC_INFORMATION memoryInfo;
		VirtualQuery((PVOID)physicalAddress, &memoryInfo, sizeof memoryInfo);
		if (memoryInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
		{
			if ((pWorkingSetInfo->WorkingSetInfo[i].Shared == 0) || (pWorkingSetInfo->WorkingSetInfo[i].ShareCount == 0))
			{
				debugged = true;
				break;
			}
		}
	}

	return debugged;
}

BOOL isDebugged = TRUE;

LONG WINAPI CustomUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPointers)
{
	isDebugged = FALSE;
	return EXCEPTION_CONTINUE_EXECUTION;
}

bool detectDebuggingByUnhandledExceptionFilter()
{
	PTOP_LEVEL_EXCEPTION_FILTER previousUnhandledExceptionFilter = SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
	SetUnhandledExceptionFilter(previousUnhandledExceptionFilter);
	return isDebugged;
}


bool createBreakpointInterrupt()
{
	BOOL isDebugged = TRUE;
	__try
	{
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		isDebugged = FALSE;
	}
	return isDebugged;
}

bool createBreakpointInterruptForx64dbg()
{
	BOOL isDebugged = TRUE;
	__try
	{
		RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		isDebugged = FALSE;
	}
	return isDebugged;
}

BOOL isDebugged2 = TRUE;

LONG WINAPI CustomVectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionPointers)
{
	if (pExceptionPointers->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		pExceptionPointers->ContextRecord->Rip++;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH; // pass on other exceptions
}

bool vectoredExceptionHandler() 
{
	AddVectoredExceptionHandler(1, CustomVectoredExceptionHandler);
	DebugBreak();
	RemoveVectoredExceptionHandler(CustomVectoredExceptionHandler);
	return isDebugged2;
}

LONG WINAPI CustomVectoredExceptionHandler2(PEXCEPTION_POINTERS pExceptionPointers)
{
	return EXCEPTION_CONTINUE_EXECUTION;
}

bool processAllExceptions()
{
	AddVectoredExceptionHandler(1, CustomVectoredExceptionHandler2);
	RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
	return RemoveVectoredExceptionHandler(CustomVectoredExceptionHandler2);
}

bool NoSelfDebugging()
{
	DWORD pid = GetCurrentProcessId();
	
	if (!DebugActiveProcess(pid))
	{
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		TerminateProcess(hProcess, 0);
		return true;
	}

	return false;
}

/*bool hideThreadAndEvents()
{
	typedef NTSTATUS(WINAPI* NtCreateThreadEx)(OUT PHANDLE, IN ACCESS_MASK, IN PVOID, IN HANDLE, IN PTHREAD_START_ROUTINE, IN PVOID, IN ULONG, IN SIZE_T, IN SIZE_T, IN SIZE_T, OUT PVOID);
	NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
	HANDLE hThread;
	pNtCreateThreadEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(), (PTHREAD_START_ROUTINE)shellcode_exec, NULL, THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, NULL, NULL, NULL, NULL);
	WaitForSingleObject(hThread, INFINITE);
}*/

/*VOID CALLBACK MyCallback(DWORD errorCode, DWORD bytesTransferred, POVERLAPPED pOverlapped)
{
	MessageBoxW(NULL, L"Catch me if you can", L"xD", 0);
}

void tanglingExecutionPath()
{
	HANDLE hFile = CreateFileW(L"C:\\Windows\\win.ini", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
	PVOID fileBuffer = VirtualAlloc(0, 64, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	OVERLAPPED overlapped = { 0 };
	ReadFileEx(hFile, fileBuffer, 32, &overlapped, MyCallback);

	WaitForSingleObjectEx(hFile, INFINITE, true);
}*/

/*void NTAPI TlsCallback(PVOID DllHandle, DWORD dwReason, PVOID)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (CheckIfDebugged()) exit(0);
	}
}

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_function")

#pragma const_seg(".CRT$XLA")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_function = TlsCallback;
#pragma const_seg()*/

//BlockInput(true);

bool DebuggerNotPresent() 
{
	return IsDebuggerPresent() && checkIfRemoteDebuggerPresent();
}

bool DebuggerFlagsNotSet()
{
	return checkSpecifigDebuggerFlagsSet && checkHeapDebuggerFlagSet() && checkProcessDebugObjectHandle();
}

bool NoBreakpoints()
{
	return detectSoftwareBreakpoints() 
		&& detectHardwareBreakpoints()
		&& detectBreakpointsByMemoryPages()
		&& createBreakpointInterrupt() 
		&& createBreakpointInterruptForx64dbg();
}

bool NoExceptionDebugging() 
{
	return detectDebuggingByUnhandledExceptionFilter() 
		&& vectoredExceptionHandler() 
		&& processAllExceptions();
}

bool IsBeingDebugged()
{
	return DebuggerNotPresent() 
		&& DebuggerFlagsNotSet() 
		&& NoBreakpoints() 
		&& NoExceptionDebugging() 
		&& NoSelfDebugging();
}