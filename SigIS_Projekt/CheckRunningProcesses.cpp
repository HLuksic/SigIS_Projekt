#include <Windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

bool SnapshotIsValid(HANDLE& hSnapshot, PROCESSENTRY32W processEntry)
{
	return Process32FirstW(hSnapshot, &processEntry);
}

bool IsBadProcess(WCHAR* processName)
{
	return
		wcsstr(processName, L"WIRESHARK.EXE") ||
		wcsstr(processName, L"IDA64.EXE")     ||
		wcsstr(processName, L"PROCMON.EXE")   ||
		wcsstr(processName, L"X64DBG.EXE");
}

bool AnalysisProcessesRunning()
{
	PROCESSENTRY32W processEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	WCHAR processName[MAX_PATH + 1];
	
	// If snapshot is valid
	if (SnapshotIsValid(hSnapshot, processEntry))
	{
		do
		{
			StringCchCopyW(processName, MAX_PATH, processEntry.szExeFile);
			CharUpperW(processName);
			
			if (IsBadProcess(processName)) return true;
			
		} while (Process32NextW(hSnapshot, &processEntry));
	}

	return false;
}

bool AnalysisToolsRunning()
{
	return AnalysisProcessesRunning();
}