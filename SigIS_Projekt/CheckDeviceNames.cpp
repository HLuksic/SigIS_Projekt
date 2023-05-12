#include <WinSock2.h>
#include <Winternl.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <Windows.h>
#include <iphlpapi.h>

#pragma comment (lib, "Setupapi.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment (lib, "iphlpapi.lib")

const char* const vendorBytes[] = {
	// VMWare
	"\x00\x50\x56",
	"\x00\x0c\x29",
	"\x00\x05\x69",
	"\x00\x1c\x14",
	// Parallel
	"\x00\x1c\x42",
	// Docker
	"\x02\x42",
	// Hyper-V
	"\x00\x15\x5d",
	// Oracle
	"\x08\x00\x27",
	"\x52\x54\x00",
	"\x00\x21\xf6",
	"\x00\x14\x4f",
	"\x00\x0f\x4b"
};

bool ContainsBadBytes(char* mac)
{
	for (auto& vendorByte : vendorBytes)
	{
		if (!memcmp(vendorByte, mac, 3)) return true;
	}

	return false;
}

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

bool MacAddressContainsVmVendorBytes()
{
	DWORD adaptersListSize = 0;
	GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &adaptersListSize);
	IP_ADAPTER_ADDRESSES* pAdaptersAddresses = (IP_ADAPTER_ADDRESSES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, adaptersListSize);
	
	if (pAdaptersAddresses)
	{
		GetAdaptersAddresses(AF_UNSPEC, 0, 0, pAdaptersAddresses, &adaptersListSize);
		char mac[6] = { 0 };
		
		while (pAdaptersAddresses)
		{
			if (pAdaptersAddresses->PhysicalAddressLength == 6)
			{
				memcpy(mac, pAdaptersAddresses->PhysicalAddress, 6);
				
				if (ContainsBadBytes(mac)) return true;
			}
			pAdaptersAddresses = pAdaptersAddresses->Next;
		}
	}
	return false;
}

bool SystemHasVmDeviceNames()
{
	return SystemHasVirtualDevice() 
		|| HardDriveContainsVMString() 
		|| MacAddressContainsVmVendorBytes();
}


