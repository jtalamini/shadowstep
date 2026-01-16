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

// absolute path to vswhere.exe (used to locate MSBuild)
#define VSWHERE_PATH L"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe"

/*
 * uses vswhere.exe to locate the latest installed MSBuild.exe.
 * the function spawns vswhere, captures its stdout via a pipe,
 * and extracts the first returned MSBuild path.
 *
 * outPath      - output buffer receiving the full MSBuild path
 * outPathSize  - size of outPath in wchar_t units
 *
 * returns TRUE on success, FALSE on failure.
 */
BOOL FindMSBuildPath(wchar_t* outPath, DWORD outPathSize)
{
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE hRead = NULL, hWrite = NULL;
	DWORD bytesRead;
	char bufferA[2048]; // raw UTF-8 output from vswhere
	wchar_t bufferW[2048]; // converted UTF-16 string

	if (!outPath || outPathSize == 0)
		return FALSE;

	outPath[0] = L'\0';

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	// allow child process to inherit pipe handles
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	// create an anonymous pipe to capture stdout/stderr
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
		return FALSE;

	// prevent read handle from being inherited
	SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

	// command line invoking vswhere to locate MSBuild.exe
	wchar_t cmdLine[] =
		L"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" "
		L"-latest -products * -requires Microsoft.Component.MSBuild "
		L"-find MSBuild\\**\\Bin\\MSBuild.exe";

	// redirect stdout and stderr to the pipe
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdOutput = hWrite;
	si.hStdError = hWrite;

	if (!CreateProcessW(
		NULL,
		cmdLine,
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi))
	{
		CloseHandle(hRead);
		CloseHandle(hWrite);
		return FALSE;
	}

	// close write end in parent; child owns it now
	CloseHandle(hWrite);

	if (!ReadFile(hRead, bufferA, sizeof(bufferA) - 1, &bytesRead, NULL)) {
		CloseHandle(hRead);
		return FALSE;
	}

	bufferA[bytesRead] = '\0';

	// converte UTF-8 -> UTF-16
	if (!MultiByteToWideChar(
		CP_UTF8,
		0,
		bufferA,
		-1,
		bufferW,
		_countof(bufferW)))
	{
		CloseHandle(hRead);
		return FALSE;
	}

	// strip CR/LF characters
	wchar_t* nl = wcspbrk(bufferW, L"\r\n");
	if (nl) *nl = L'\0';

	if (bufferW[0] == L'\0') {
		CloseHandle(hRead);
		return FALSE;
	}

	// copy the result to output buffer
	wcscpy_s(outPath, outPathSize, bufferW);

	CloseHandle(hRead);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return TRUE;
}

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
	wchar_t msbuildPath[MAX_PATH];
	wchar_t cmdLine[32768];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD exitCode;

	if (!FindMSBuildPath(msbuildPath, _countof(msbuildPath))) {
		wprintf(L"[-] MSBuild not found (vswhere failed)\n");
		return 0;
	}

	wprintf(L"[+] Using MSBuild: %s\n", msbuildPath);

	wchar_t targetName[MAX_PATH];
	GetFileNameWithoutExtension(
		inputFile,
		targetName,
		_countof(targetName)
	);
	
	// construct MSBuild command line
	_snwprintf(
		cmdLine,
		_countof(cmdLine),
		L"\"%s\" \"%s\" /p:Configuration=Release /p:Platform=x64 /verbosity:minimal /p:TargetName=shadow%s",
		msbuildPath,
		vcxprojPath,
		targetName
	);

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	if (!CreateProcessW(
		NULL,
		cmdLine,
		NULL,
		NULL,
		FALSE,
		0,
		NULL,
		NULL,
		&si,
		&pi))
	{
		wprintf(L"[-] Failed to start MSBuild (error=%lu)\n", GetLastError());
		return 0;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exitCode);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	if (exitCode != 0) {
		wprintf(L"[-] MSBuild failed (exit code=%lu)\n", exitCode);
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
