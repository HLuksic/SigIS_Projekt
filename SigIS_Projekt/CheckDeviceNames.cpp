#include <Windows.h>
#include <Winternl.h>
#include <devguid.h>
#include <SetupAPI.h>

#pragma comment (lib, "Setupapi.lib")
#pragma comment (lib, "ntdll.lib")

bool SystemHasVirtualDevices()
{
	OBJECT_ATTRIBUTES objectAttributes{};
	UNICODE_STRING uDeviceName{};
	HANDLE hDevice = NULL;
	IO_STATUS_BLOCK ioStatusBlock;
	
	RtlSecureZeroMemory(&uDeviceName, sizeof(uDeviceName));
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\VBoxGuest"); // or pipe: L"\\??\\pipe\\VBoxTrayIPC-<username>"
	InitializeObjectAttributes(&objectAttributes, &uDeviceName, OBJ_CASE_INSENSITIVE, 0, NULL);
	NTSTATUS status = NtCreateFile(&hDevice, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
	
	if (NT_SUCCESS(status)) return false;
}

bool HardDriveContainsVMString()
{
	HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, 0, 0, DIGCF_PRESENT);
	SP_DEVINFO_DATA deviceInfoData;
	deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	SetupDiEnumDeviceInfo(hDevInfo, 0, &deviceInfoData);
	
	DWORD propertyBufferSize;
	SetupDiGetDeviceRegistryPropertyW(hDevInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, NULL, 0, &propertyBufferSize);
	
	PWSTR HDDName = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertyBufferSize);
	SetupDiGetDeviceRegistryPropertyW(hDevInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)HDDName, propertyBufferSize, NULL);
	
	CharUpperW(HDDName);
	
	// Look for VM-like HDD device names
	if (wcsstr(HDDName, L"VBOX") || wcsstr(HDDName, L"VMWARE") || wcsstr(HDDName, L"VM")) return true;

	return false;
}

bool SystemHasVmDeviceNames()
{
	return !HardDriveContainsVMString();
}


