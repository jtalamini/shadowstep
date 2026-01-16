#pragma once
#include <windows.h>
#include "../crypt/crypt.h"

#define MAX_INSTRUCTION_SIZE 60

struct ShellcodeContext {
    HANDLE processHandle;
    DWORD currentInstrOffset;
    SIZE_T currentInstrSize;
    INT currentInstrIndex;
    SIZE_T shellcodeSize;
    PBYTE shellcode;
    PBYTE keys;
    SIZE_T keySize;
    PDWORD instrOffsets;
    PDWORD instrSizes;
    PDWORD regMasks;
    SIZE_T numInstructions;
    EncryptionType encryption;
};


BOOL Setup(
    HANDLE hProcess,
    PVOID address,
    SIZE_T shellcodeSize,
    PBYTE keys,
    SIZE_T keySize,
    PDWORD instrOffsets,
    PDWORD instrSizes,
    PDWORD regMasks,
    SIZE_T numInstructions,
    EncryptionType encryption,
    OUT ShellcodeContext* outContext
);

BOOL ShellcodeRunner(LPVOID param);

extern const char* tracked_regs[];
extern const int NUM_TRACKED_REGS;