#include <Windows.h>
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

void CheckDebuggerFlagPeb()
{
	PPEB pPEB = (PPEB)__readgsqword(0x60);
	if (pPEB->BeingDebugged) exit(0);
}

void IsRemoteDebuggerPresent()
{
	BOOL isDebuggerPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
	
	if (isDebuggerPresent) exit(0);
}

void IsDebuggerFlagSet()
{
	PDWORD pNtGlobalFlag = (PDWORD)(__readgsqword(0x60) + 0xBC);
	
	if ((*pNtGlobalFlag) & NT_GLOBAL_FLAG_DEBUGGED) exit(0);
}

void IsHeapDebuggerFlagSet()
{
	PDWORD pHeapFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x70);
	PDWORD pHeapForceFlags = (PDWORD)((PBYTE)GetProcessHeap() + 0x74);
	
	if (*pHeapFlags ^ HEAP_GROWABLE || *pHeapForceFlags != 0) exit(0);
}

void IsDebugHandleOrFlagSet()
{
	typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(IN HANDLE, IN PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG);
	PNtQueryInformationProcess pNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	
	HANDLE hProcessDebugObject = NULL;
	DWORD processDebugFlags = 0;
	
	pNtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugObjectHandle, &hProcessDebugObject, sizeof HANDLE, NULL);
	pNtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)ProcessDebugFlags, &processDebugFlags, sizeof DWORD, NULL);
	
	if ((hProcessDebugObject != NULL) || (processDebugFlags == 0)) exit(0);
}

void ContainsHardwareBreakpoints()
{
	CONTEXT context = {};
	context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	
	GetThreadContext(GetCurrentThread(), &context);
	if (context.Dr0 || context.Dr1 || context.Dr2  || context.Dr3) exit(0);
}

// Normally all executable pages are shared by all processes, but when a debugger
// sets a breakpoint, the page is copied and no longer shared
void HasBreakpointsInMemoryPages()
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
				exit(0);
		}
	}
}

BOOL isDebugged = TRUE;

// Called only if program is not being debugged (structured exception handling)
LONG WINAPI CustomUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionPointers)
{
	isDebugged = FALSE;
	
	return EXCEPTION_CONTINUE_EXECUTION;
}

void DetectExceptionDebugging()
{
	PTOP_LEVEL_EXCEPTION_FILTER previousUnhandledExceptionFilter = SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, NULL);
	SetUnhandledExceptionFilter(previousUnhandledExceptionFilter);
	
	if (isDebugged) exit(0);
}

// Detects VS and WinDbg, but not x64dbg by creating a breakpoint interrupt
bool DetectInterruptDebugging()
{
	BOOL isDebugged = TRUE;
	
	__try
	{
		// Causes undefined behaviour in debugger (EXCEPTION_ILLEGAL_INSTRUCTION loop)
		RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		isDebugged = FALSE;
	}
	if (isDebugged) exit(0);
}

LONG WINAPI CustomVectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionPointers)
{
	return EXCEPTION_CONTINUE_EXECUTION;
}

// Similar to previous function but abuses vectored exception handling
void BreakAnalysisWithVectoredExceptions()
{
	AddVectoredExceptionHandler(1, CustomVectoredExceptionHandler);
	RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
	RemoveVectoredExceptionHandler(CustomVectoredExceptionHandler);
}

// Try to attach a process to the existing one
// If it fails, the process already has a debugger attached
//void NoSelfDebugging()
//{
//	DWORD pid = GetCurrentProcessId();
//	
//	if (!DebugActiveProcess(pid))
//	{
//		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
//		TerminateProcess(hProcess, 0);
//	}
//}

void IsBeingDebugged()
{
	CheckDebuggerFlagPeb();
	IsRemoteDebuggerPresent();
	IsDebuggerFlagSet();
	IsHeapDebuggerFlagSet();
	IsDebugHandleOrFlagSet();
	ContainsHardwareBreakpoints();
	HasBreakpointsInMemoryPages();
	DetectExceptionDebugging();
	DetectInterruptDebugging();
	BreakAnalysisWithVectoredExceptions();
	//NoSelfDebugging();
}