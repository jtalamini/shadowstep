#pragma once
#include <windows.h>
#include "../crypt/crypt.h"

BOOL GenerateShadowStepMain(
	LPCWSTR OutputFile, 
	PBYTE shellcode, 
	SIZE_T shellcodeSize, 
	PBYTE keys = NULL, 
	SIZE_T keySize = 0, 
	EncryptionType encryption = ENCRYPTION_XOR
);