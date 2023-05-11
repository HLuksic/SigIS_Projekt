#include <Windows.h>
#include <Winternl.h>
#include <devguid.h>
#include <SetupAPI.h>

#pragma comment (lib, "Setupapi.lib")
#pragma comment (lib, "ntdll.lib")

bool SystemHasVirtualDevice()
{
	OBJECT_ATTRIBUTES objectAttributes{};
	UNICODE_STRING uDeviceName{};
	HANDLE hDevice = NULL;
	IO_STATUS_BLOCK ioStatusBlock;
	
	RtlSecureZeroMemory(&uDeviceName, sizeof(uDeviceName));
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\VBoxGuest");
	InitializeObjectAttributes(&objectAttributes, &uDeviceName, OBJ_CASE_INSENSITIVE, 0, NULL);
	NTSTATUS status = NtCreateFile(&hDevice, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
	
	if (NT_SUCCESS(status)) return true;

	return false;
}

bool ContainsBadString(PWSTR HDDName)
{
	return 
		wcsstr(HDDName, L"VBOX")   ||
		wcsstr(HDDName, L"VMWARE") ||
		wcsstr(HDDName, L"VM");
}

bool HardDriveContainsVMString()
{
	SP_DEVINFO_DATA deviceInfoData{};
	
	// Get HDD information set handle
	HDEVINFO hDeviceInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, 0, 0, DIGCF_PRESENT);
	deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	SetupDiEnumDeviceInfo(hDeviceInfo, 0, &deviceInfoData);
	
	DWORD propertyBufferSize;
	SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, NULL, 0, &propertyBufferSize);
	
	PWSTR HDDName = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertyBufferSize);
	SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)HDDName, propertyBufferSize, NULL);
	
	CharUpperW(HDDName);
	
	if (ContainsBadString(HDDName)) return true;

	return false;
}

bool SystemHasVmDeviceNames()
{
	return SystemHasVirtualDevice() || HardDriveContainsVMString();
}


