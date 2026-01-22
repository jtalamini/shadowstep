#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <cstdint>
#include <capstone/capstone.h>
#include <shlwapi.h>
#include <pathcch.h>
#include <strsafe.h>
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Pathcch.lib")


/*
 * builds a path for a generated source file:
 *   <project directory>\<subDirName>\<fileName>
 *
 * creates the subdirectory if it does not exist.
 */
BOOL BuildGeneratedSourcePath(
	const wchar_t* projectFile,
	const wchar_t* subDirName,
	const wchar_t* fileName,
	wchar_t* outputFile,
	DWORD outputFileSize
)
{
	wchar_t projectDir[MAX_PATH];
	wchar_t targetDir[32768];
	HRESULT hr;
	DWORD err;

	if (!projectFile || !subDirName || !fileName || !outputFile || outputFileSize == 0)
		return FALSE;

	// copy project path so we can strip the filename
	hr = StringCchCopyW(projectDir, _countof(projectDir), projectFile);
	if (FAILED(hr))
		return FALSE;

	// remove the filename, leaving only the directory
	if (!PathRemoveFileSpecW(projectDir))
		return FALSE;

	// combine: projectDir\subDirName
	hr = PathCchCombineEx(
		targetDir,
		_countof(targetDir),
		projectDir,
		subDirName,
		PATHCCH_ALLOW_LONG_PATHS
	);
	if (FAILED(hr))
		return FALSE;

	// ensure that the target directory exists
	if (!CreateDirectoryW(targetDir, NULL)) {
		err = GetLastError();
		if (err != ERROR_ALREADY_EXISTS)
			return FALSE;
	}

	// combine: targetDir\fileName
	hr = PathCchCombineEx(
		outputFile,
		outputFileSize,
		targetDir,
		fileName,
		PATHCCH_ALLOW_LONG_PATHS
	);
	if (FAILED(hr))
		return FALSE;

	return TRUE;
}

/*
 * Reads an entire file into a heap-allocated byte buffer.
 */
BOOL ReadFileToByteArray(LPCWSTR path, BYTE** outData, SIZE_T* outSize)
{
	if (!outData || !outSize) return FALSE;
	*outData = NULL;
	*outSize = 0;

	HANDLE hFile = CreateFileW(
		path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) return FALSE;

	LARGE_INTEGER liSize;
	if (!GetFileSizeEx(hFile, &liSize)) {
		CloseHandle(hFile);
		return FALSE;
	}

	// only support files <= 4GB
	if (liSize.QuadPart < 0 || liSize.QuadPart > 0xFFFFFFFFLL) {
		CloseHandle(hFile);
		SetLastError(ERROR_FILE_TOO_LARGE);
		return FALSE;
	}

	DWORD size = (DWORD)liSize.QuadPart;
	// allocate at least 1 byte to remain safe for zero-length files
	BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size ? size : 1); // 0-byte safe
	if (!buf) {
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD totalRead = 0;
	while (totalRead < size) {
		DWORD chunkRead = 0;
		DWORD toRead = size - totalRead;

		if (!ReadFile(hFile, buf + totalRead, toRead, &chunkRead, NULL)) {
			HeapFree(GetProcessHeap(), 0, buf);
			CloseHandle(hFile);
			return FALSE;
		}
		if (chunkRead == 0) break; // unexpected EOF
		totalRead += chunkRead;
	}

	CloseHandle(hFile);

	if (totalRead != size) {
		HeapFree(GetProcessHeap(), 0, buf);
		SetLastError(ERROR_HANDLE_EOF);
		return FALSE;
	}

	*outData = buf;
	*outSize = size;
	return TRUE;
}

/*
 * extracts the filename without extension from a full path
 */
BOOL GetFileNameWithoutExtension(
	const wchar_t* fullPath,
	wchar_t* outName,
	DWORD outNameSize
)
{
	if (!fullPath || !outName || outNameSize == 0)
		return FALSE;

	const wchar_t* fileName = PathFindFileNameW(fullPath);

	// copy filename portion
	wcscpy_s(outName, outNameSize, fileName);

	// remove extension (if present)
	PathRemoveExtensionW(outName);

	return TRUE;
}

/*
 * checks whether a file exists and is not a directory
 */
BOOL FileExists(CONST WCHAR* path) {
	if (path == NULL || *path == L'\0')
		return FALSE;

	DWORD attr = GetFileAttributesW(path);

	if (attr == INVALID_FILE_ATTRIBUTES)
		return FALSE;

	if (attr & FILE_ATTRIBUTE_DIRECTORY)
		return FALSE;

	return TRUE;
}

/*
 * builds a Visual Studio project using MSBuild
 */
int BuildProject(const WCHAR* inputFile, const WCHAR* vcxprojPath)
{
	wchar_t cmdLine[1024];
	wchar_t targetName[MAX_PATH];
	int ret;

	GetFileNameWithoutExtension(
		inputFile,
		targetName,
		_countof(targetName)
	);

	_snwprintf(
		cmdLine,
		_countof(cmdLine),
		L"msbuild \"%s\" "
		L"/p:Configuration=Release "
		L"/p:Platform=x64 "
		L"/verbosity:minimal "
		L"/p:TargetName=shadow%s",
		vcxprojPath,
		targetName
	);

	wprintf(L"[+] Executing: %s\n", cmdLine);

	ret = _wsystem(cmdLine);

	if (ret != 0) {
		wprintf(L"[-] MSBuild failed (return code=%d)\n", ret);
		return 0;
	}

	wprintf(L"[+] Project built successfully\n");
	return 1;
}

/*
 * returns the full path to a file located in the same directory
 * as the current executable.
 */
WCHAR* GetFullPath(LPCWSTR file) {
	WCHAR exePath[MAX_PATH];
	GetModuleFileNameW(NULL, exePath, MAX_PATH);
	PathRemoveFileSpecW(exePath);
	wcscat_s(exePath, MAX_PATH, L"\\");
	wcscat_s(exePath, MAX_PATH, file);
	return exePath;
}

/*
 * prints a string at the specified address
 */
void PrintStringAtAddress(uint64_t addr) {
	__try {
		if (IsBadReadPtr((void*)addr, 16)) return;

		const char* strA = (const char*)addr;
		const wchar_t* strW = (const wchar_t*)addr;

		// heuristic: check if first few bytes match ASCII or UTF-16LE pattern
		BOOL isLikelyUnicode = FALSE;

		// check if first few wide chars are printable and the second byte of each char is zero
		for (int i = 0; i < 4; i++) {
			if (IsBadReadPtr(&strW[i], sizeof(wchar_t))) break;
			if (!iswprint(strW[i])) break;
			if (((uint8_t*)&strW[i])[1] != 0) break;
			isLikelyUnicode = TRUE;
		}

		if (isLikelyUnicode) {
			// Print as Unicode string
			wchar_t buffer[65] = { 0 };
			for (int i = 0; i < 64; i++) {
				if (IsBadReadPtr(&strW[i], sizeof(wchar_t)) || !iswprint(strW[i]))
					break;
				buffer[i] = strW[i];
			}
			char utf8[256] = { 0 };
			int len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, utf8, sizeof(utf8), NULL, NULL);
			if (len > 0) {
				printf(" -> L\"%s\"", utf8);
			}
		}
		else {
			// print as ASCII string
			if (isprint(strA[0])) {
				printf(" -> \"%.*s\"", 64, strA);
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// silently ignore memory access errors
	}
}


void PrintContext(const CONTEXT* ctx) {
	if (!ctx) {
		printf("[-] CONTEXT pointer is null\n");
		return;
	}

	printf("=== CONTEXT REGISTERS ===\n");


#define PRINT_REG(name) \
	printf(#name " = 0x%016llx", ctx->name); \
	printf("\n");
	//PrintStringAtAddress(ctx->name); \
	printf("\n");

	// general purpose registers + pointed string
	PRINT_REG(Rax);
	PRINT_REG(Rbx);
	PRINT_REG(Rcx);
	PRINT_REG(Rdx);
	PRINT_REG(Rsi);
	PRINT_REG(Rdi);
	PRINT_REG(Rbp);
	PRINT_REG(Rsp);
	PRINT_REG(R8);
	PRINT_REG(R9);
	PRINT_REG(R10);
	PRINT_REG(R11);
	PRINT_REG(R12);
	PRINT_REG(R13);
	PRINT_REG(R14);
	PRINT_REG(R15);
	PRINT_REG(Rip);

#undef PRINT_REG

	// Segments
	printf("CS  = 0x%04x\n", ctx->SegCs);
	printf("DS  = 0x%04x\n", ctx->SegDs);
	printf("ES  = 0x%04x\n", ctx->SegEs);
	printf("FS  = 0x%04x\n", ctx->SegFs);
	printf("GS  = 0x%04x\n", ctx->SegGs);
	printf("SS  = 0x%04x\n", ctx->SegSs);

	// Flags
	printf("EFLAGS = 0x%08x\n", ctx->EFlags);
	printf("Flags: ");
	if (ctx->EFlags & 0x00000001) printf("CF ");
	if (ctx->EFlags & 0x00000004) printf("PF ");
	if (ctx->EFlags & 0x00000010) printf("AF ");
	if (ctx->EFlags & 0x00000040) printf("ZF ");
	if (ctx->EFlags & 0x00000080) printf("SF ");
	if (ctx->EFlags & 0x00000100) printf("TF ");
	if (ctx->EFlags & 0x00000200) printf("IF ");
	if (ctx->EFlags & 0x00000400) printf("DF ");
	if (ctx->EFlags & 0x00000800) printf("OF ");
	printf("\n");

	
		// Stack dump
	printf("\n=== TOP 10 STACK VALUES FROM RSP ===\n");
	uint64_t* stackPtr = (uint64_t*)ctx->Rsp;
	for (int i = 0; i < 10; i++) {
		__try {
			uint64_t val = stackPtr[i];
			printf("[RSP + 0x%02X] = 0x%016llx", i * 8, val);
			//PrintStringAtAddress(val);
			printf("\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			printf("[RSP + 0x%02X] = <unreadable>\n", i * 8);
		}
	}
}

void PrintInstructions(const uint8_t* shellcode, size_t offset, size_t size, uint64_t baseAddress = 0x0) {
	csh handle;
	cs_insn* insn;
	size_t count;

	if (offset + size > SIZE_MAX) {
		printf("[-] Invalid offset/size combination\n");
		return;
	}

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("[-] Failed to initialize Capstone\n");
		return;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF); // Optional, if you don't need operand details

	count = cs_disasm(handle, shellcode + offset, size, baseAddress + offset, 0, &insn);
	if (count == 0) {
		printf("[-] Failed to disassemble any instruction at offset %zu\n", offset);
		cs_close(&handle);
		return;
	}

	for (size_t i = 0; i < count; i++) {
		printf("0x%llx:\t%-10s\t%s\n",
			insn[i].address,
			insn[i].mnemonic,
			insn[i].op_str
		);
	}

	cs_free(insn, count);
	cs_close(&handle);
}


void prettyPrint(const BYTE* buffer, SIZE_T bufferSize, SIZE_T bytesPerLine) {
	SIZE_T counter = 0;
	for (SIZE_T i = 0; i < bufferSize; i++) {
		if (buffer[i] > 0xf) {
			printf("0x%x, ", buffer[i]);
		}
		else {
			printf("0x0%x, ", buffer[i]);
		}
		counter += 1;
		if (counter == bytesPerLine) {
			printf("\n");
			counter = 0;
		}
	}
	printf("\n");
}
