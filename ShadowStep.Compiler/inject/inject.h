#pragma once
#include <windows.h>

BOOL InjectShellcode(
	HANDLE hProcess, 
	IN const PBYTE shellcode, 
	IN SIZE_T shellcodeSize, 
	OUT LPVOID* shellcodeAddress
);