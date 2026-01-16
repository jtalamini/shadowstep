#include <Windows.h>
#include "gen/gen.h"
#include "crypt/crypt.h"
#include <stdio.h>
#include "utils/utils.h"


int wmain(int argc, wchar_t* argv[]) {

    // OPTIONAL: XOR encryption keys of your choice
    // used mainly for debugging purpose. it will be removed
    BYTE keys[] = { 0x12, 0x34, 0x56, 0x78 };
    SIZE_T keySize = sizeof(keys);

    // required arguments:
    // - the .bin shellcode to process
    // - the path to the ShadowStep.Runtime.vcxproj file
    if (argc < 3) {
        wprintf(L"Usage: %s <path>\n", argv[0]);
        wprintf(L"Example: %s C:\\Users\\user\\source\\payloads\\calc.bin C:\\Users\\user\\source\\repos\\shadowstep\\ShadowStep.Runtime\\ShadowStep.Runtime.vcxproj", argv[0]);
        return 1;
    }

    const WCHAR* inputFile = argv[1];

    // check if input .bin file exists
    if (!FileExists(inputFile)) {
        wprintf(L"[-] File %s not found\n", inputFile);
        return -1;
    }

    const WCHAR* projectFile = argv[2];

    // check if input .vcxproj file exists
    if (!FileExists(projectFile)) {
        wprintf(L"[-] File %s not found\n", projectFile);
        return -1;
    }

    wprintf(L"[!] Loading binary data from: %s\n", inputFile);

    // arbitrary output file name
    // the ShadowStep.Runtime project is already configured to include this as source file
    
    //const WCHAR* outputFile = L"ShadowStep.cpp";
    WCHAR outputFile[MAX_PATH*2];

    if (!BuildGeneratedSourcePath(
        projectFile,
        L"Generated",
        L"ShadowStep.cpp",
        outputFile,
        _countof(outputFile)
    )) {
        wprintf(L"[-] Failed to build output file path %s\n", outputFile);
        return -1;
    }

    BYTE* shellcode = NULL;
    SIZE_T shellcodeSize = 0;

    // read the shellcode from the specified .bin file
    if (!ReadFileToByteArray(inputFile, &shellcode, &shellcodeSize)) {
        wprintf(L"[-] Error while reading data from file: %s\n", inputFile);
        return 1;
    }
    printf("[+] Loaded %lu bytes\n", (unsigned long)shellcodeSize);

    // the ShadowStep.cpp source code generation algorithm 
    GenerateShadowStepMain(outputFile, shellcode, shellcodeSize, keys, keySize, ENCRYPTION_XOR);
    wprintf(L"[+] Data written to %s\n", outputFile);

    // automatically build the ShadowStep.Runtime.vcxproj project
    if (BuildProject(inputFile, projectFile) == 0) {
        wprintf(L"[+] Failed to build project %s\n", projectFile);
        return -1;
    }


    return 1;
}
