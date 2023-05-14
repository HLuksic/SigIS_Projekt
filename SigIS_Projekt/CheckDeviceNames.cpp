#include <WinSock2.h>
#include <Winternl.h>
#include <SetupAPI.h>
#include <devguid.h>
#include <Windows.h>
#include <iphlpapi.h>

#pragma comment (lib, "Setupapi.lib")
#pragma comment (lib, "ntdll.lib")
#pragma comment (lib, "iphlpapi.lib")

// First three bytes of MAC address are hardware vendor bytes
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
	for (const char* const& vendorByte : vendorBytes)
		if (!memcmp(vendorByte, mac, 3)) return true;

	return false;
}

// Try to open virtual devices specific to VMs
void SystemHasVirtualDevice()
{
	OBJECT_ATTRIBUTES objectAttributes{};
	UNICODE_STRING uDeviceName{};
	HANDLE hDevice = NULL;
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS status = 0;
	
	RtlSecureZeroMemory(&uDeviceName, sizeof(uDeviceName));
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\VBoxGuest");
	InitializeObjectAttributes(&objectAttributes, &uDeviceName, OBJ_CASE_INSENSITIVE, 0, NULL);
	
	RtlInitUnicodeString(&uDeviceName, L"\\Device\\VBoxGuest");

	status = NtCreateFile(&hDevice, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
	
	if (NT_SUCCESS(status)) exit(0);
}

bool ContainsBadString(PWSTR HDDName)
{
	return wcsstr(HDDName, L"VBOX")
		|| wcsstr(HDDName, L"VMWARE")
		|| wcsstr(HDDName, L"VM")
		|| wcsstr(HDDName, L"VIRTUAL")
		|| wcsstr(HDDName, L"PARALLEL")
		|| wcsstr(HDDName, L"HYPER");
}

void HardDriveContainsVMString()
{
	SP_DEVINFO_DATA deviceInfoData{};
	DWORD propertyBufferSize;
	
	HDEVINFO hDeviceInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_DISKDRIVE, 0, 0, DIGCF_PRESENT);
	deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	
	SetupDiEnumDeviceInfo(hDeviceInfo, 0, &deviceInfoData);
	SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, NULL, 0, &propertyBufferSize);
	
	PWSTR HDDName = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, propertyBufferSize);
	SetupDiGetDeviceRegistryPropertyW(hDeviceInfo, &deviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)HDDName, propertyBufferSize, NULL);
	CharUpperW(HDDName);
	
	if (ContainsBadString(HDDName)) exit(0);
}

void MacAddressContainsVmVendorBytes()
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
				
				if (ContainsBadBytes(mac)) exit(0);
			}
			pAdaptersAddresses = pAdaptersAddresses->Next;
		}
	}
}

void SystemHasVmDeviceNames()
{
	SystemHasVirtualDevice();
	HardDriveContainsVMString();
	MacAddressContainsVmVendorBytes();
}


