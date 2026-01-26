#pragma once
#include <windows.h>
#include <cstdint>

typedef enum {
    ENCRYPTION_XOR,
    ENCRYPTION_RC4
} EncryptionType;

void ApplyCryptInstruction(
    PBYTE* shellcode, 
    SIZE_T offset, 
    SIZE_T size, 
    PBYTE keys, 
    SIZE_T keySize, 
    EncryptionType encryption
);
