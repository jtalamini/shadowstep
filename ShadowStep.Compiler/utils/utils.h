#pragma once

#include <windows.h>
#include <stdint.h>

BOOL ReadFileToByteArray(
	LPCWSTR path, 
	BYTE** outData, 
	SIZE_T* outSize
);

BOOL FileExists(CONST WCHAR* path);

int BuildProject(const WCHAR* inputFile, const WCHAR* vcxprojPath);

BOOL BuildGeneratedSourcePath(
	const wchar_t* projectFile,   
	const wchar_t* subDirName,    
	const wchar_t* fileName,      
	wchar_t* outputFile,           
	DWORD outputFileSize          
);

WCHAR* GetFullPath(LPCWSTR file);

// void PrintStringAtAddress(uint64_t addr);

// void PrintContext(const CONTEXT* ctx);

/*
void PrintInstructions(
	const uint8_t* shellcode, 
	size_t offset, 
	size_t size, 
	uint64_t baseAddress
);
*/

/*
void PrettyPrint(
	const BYTE* buffer, 
	SIZE_T bufferSize, 
	SIZE_T bytesPerLine
);
*/

/*
void PrintDWORDArray(
	PDWORD array, 
	SIZE_T arraySize, 
	CONST CHAR* arrayName, 
	SIZE_T elementsPerLine
);
*/

