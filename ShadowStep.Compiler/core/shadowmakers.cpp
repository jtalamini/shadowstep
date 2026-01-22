#include <windows.h>
#include <cstdint>
#include <stdio.h>

// global storage used to temporarily save the host RSP
// while executing the emulated instruction.
uint64_t g_savedRsp = 0;
//uint64_t g_savedRax = 0;

/*
 * Implements: mov r64, imm64
 *
 * buffer      -> output code buffer
 * offset      -> current write offset (updated by reference)
 * regCode     -> register index (r64)
 * value       -> immediate 64-bit value (imm64)
 * isExtended  -> true for R8–R15 (REX.B = 1)
 */
void WriteMovRegImm64(BYTE* buffer, SIZE_T& offset, BYTE regCode, uint64_t value, bool isExtended = false) {
	// REX prefix: 0x48 = REX.W, 0x49 = REX.W | REX.B
	buffer[offset++] = isExtended ? 0x49 : 0x48;

	// opcode B8–BF: MOV r64, imm64
	buffer[offset++] = 0xB8 + (regCode & 0x7);
	
	// immediate 64-bit value
	*(uint64_t*)(buffer + offset) = value;
	
	offset += 8;
}

/*
 * builds a code stub (execPtr) that:
 *  - saves the host CPU CONTEXT
 *  - loads a virtual CONTEXT (shellCtx)
 *  - executes one instruction
 *  - writes back modified registers and flags
 *  - restores the host CONTEXT and returns
 */
SIZE_T ShadowStep(
	BYTE* execPtr,
	const BYTE* instruction,
	SIZE_T instrSize,
	CONTEXT* shellCtx // virtual CPU state
) {
	SIZE_T offset = 0;
	CONTEXT& ctx = *shellCtx;

	// optional NOP byte
	//replace it with 0xcc to enable debug mode
	BYTE debug = 0x90;

	/*
	 * save the host CPU state:
	 *  - all general-purpose registers
	 *  - EFLAGS
	 */
	const BYTE saveHost[] = {
		debug,
		0x50,       // push rax
		0x51,       // push rcx
		0x52,       // push rdx
		0x53,       // push rbx
		0x55,       // push rbp
		0x56,       // push rsi
		0x57,       // push rdi
		0x41, 0x50, // push r8
		0x41, 0x51, // push r9
		0x41, 0x52, // push r10
		0x41, 0x53, // push r11
		0x41, 0x54, // push r12
		0x41, 0x55, // push r13
		0x41, 0x56, // push r14
		0x41, 0x57, // push r15
		0x9C        // pushf; save EFLAGS
	};

	memcpy(execPtr + offset, saveHost, sizeof(saveHost));
	offset += sizeof(saveHost);

	// ---------------------------------------------------------------------
	// save host RSP to global memory (needed to restore after emulation)
	// ---------------------------------------------------------------------

	// mov [g_savedRsp], rsp

	// mov rax, rsp
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x89;
	execPtr[offset++] = 0xE0; 
	
	// here: rax = rsp

	// mov rcx, imm64 (address of g_savedRsp)
	WriteMovRegImm64(execPtr, offset, 1, (uint64_t)&g_savedRsp); 
	
	// here: rcx = &g_savedRsp

	// mov [rcx], rax
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x89;
	execPtr[offset++] = 0x01; 

	// here: [rcx] <- rax

	// ---------------------------------------------------------------------
	// load EFLAGS from CONTEXT (ctx.EFlags)
	// ---------------------------------------------------------------------

	// mov rax, imm64 (ctx->EFlags)
	WriteMovRegImm64(execPtr, offset, 0, ctx.EFlags); 

	// rax = ctx->EFlags

	// push rax
	execPtr[offset++] = 0x50;

	// popfq
	execPtr[offset++] = 0x9D;

	// ---------------------------------------------------------------------
	// load general-purpose registers from CONTEXT
	// ---------------------------------------------------------------------

	WriteMovRegImm64(execPtr, offset, 0, ctx.Rax);              // mov rax, ctx.Rax
	WriteMovRegImm64(execPtr, offset, 1, ctx.Rcx);              // mov rcx, ctx.Rcx
	WriteMovRegImm64(execPtr, offset, 2, ctx.Rdx);              // mov rdx, ctx.Rdx
	WriteMovRegImm64(execPtr, offset, 3, ctx.Rbx);              // mov rbx, ctx.Rbx
	WriteMovRegImm64(execPtr, offset, 4, ctx.Rsp);              // mov rsp, ctx.Rsp
	WriteMovRegImm64(execPtr, offset, 5, ctx.Rbp);              // mov rbp, ctx.Rbp
	WriteMovRegImm64(execPtr, offset, 6, ctx.Rsi);              // mov rsi, ctx.Rsi
	WriteMovRegImm64(execPtr, offset, 7, ctx.Rdi);              // mov rdi, ctx.Rdi
	WriteMovRegImm64(execPtr, offset, 0, ctx.R8, true);         // mov r8, ctx.R8
	WriteMovRegImm64(execPtr, offset, 1, ctx.R9, true);         // mov r9, ctx.R9
	WriteMovRegImm64(execPtr, offset, 2, ctx.R10, true);        // mov r10, ctx.R10
	WriteMovRegImm64(execPtr, offset, 3, ctx.R11, true);        // mov r11, ctx.R11
	WriteMovRegImm64(execPtr, offset, 4, ctx.R12, true);        // mov r12, ctx.R12
	WriteMovRegImm64(execPtr, offset, 5, ctx.R13, true);        // mov r13, ctx.R13
	WriteMovRegImm64(execPtr, offset, 6, ctx.R14, true);        // mov r14, ctx.R14
	WriteMovRegImm64(execPtr, offset, 7, ctx.R15, true);        // mov r15, ctx.R15


	// ---------------------------------------------------------------------
	// execute the target instruction
	// ---------------------------------------------------------------------
	
	memcpy(execPtr + offset, instruction, instrSize);
	offset += instrSize;

	// save rax and EFLAGS after execution
	// push rax
	execPtr[offset++] = 0x50; 

	// pushfq
	execPtr[offset++] = 0x9C;

	// mov rax, imm64 (ctx pointer)
	WriteMovRegImm64(execPtr, offset, 0, (uint64_t)shellCtx); 
	
	// here: rax = &ctx

	// helper lambda:
	// writes general-purpose registers back to CONTEXT (using rax as base)
	// mov [rax + disp32], reg
	
	auto storeRegToCtx = [&](BYTE regCode, DWORD ctxOffset, bool extended) {
		execPtr[offset++] = extended ? 0x4C : 0x48; // REX.W + R/M
		execPtr[offset++] = 0x89;                  // MOV [rax + disp32], reg
		execPtr[offset++] = 0x80 | ((regCode & 0x7) << 3); // ModRM: [rax + disp32]
		*(DWORD*)(execPtr + offset) = ctxOffset;
		offset += 4;
		};

	// add rsp, 0x10
	// to avoid overwriting rax or EFLAGS
	// (to compensate for push rax + pushfq)
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x83;
	execPtr[offset++] = 0xC4;
	execPtr[offset++] = 0x10;

	// save general-purpose registers back into CONTEXT
	// (notice that RAX is not saved here)
	storeRegToCtx(1, offsetof(CONTEXT, Rcx), false);  // mov [rax + offsetof(CONTEXT, Rcx)], rcx
	storeRegToCtx(2, offsetof(CONTEXT, Rdx), false);  // mov [rax + offsetof(CONTEXT, Rdx)], rdx
	storeRegToCtx(3, offsetof(CONTEXT, Rbx), false);  // mov [rax + offsetof(CONTEXT, Rbx)], rbx
	storeRegToCtx(4, offsetof(CONTEXT, Rsp), false);  // mov [rax + offsetof(CONTEXT, Rsp)], rsp
	storeRegToCtx(5, offsetof(CONTEXT, Rbp), false);  // mov [rax + offsetof(CONTEXT, Rbp)], rbp
	storeRegToCtx(6, offsetof(CONTEXT, Rsi), false);  // mov [rax + offsetof(CONTEXT, Rsi)], rsi
	storeRegToCtx(7, offsetof(CONTEXT, Rdi), false);  // mov [rax + offsetof(CONTEXT, Rdi)], rdi
	storeRegToCtx(0, offsetof(CONTEXT, R8), true);   // mov [rax + offsetof(CONTEXT, R8)], r8
	storeRegToCtx(1, offsetof(CONTEXT, R9), true);   // mov [rax + offsetof(CONTEXT, R9)], r9
	storeRegToCtx(2, offsetof(CONTEXT, R10), true);   // mov [rax + offsetof(CONTEXT, R10)], r10
	storeRegToCtx(3, offsetof(CONTEXT, R11), true);   // mov [rax + offsetof(CONTEXT, R11)], r11
	storeRegToCtx(4, offsetof(CONTEXT, R12), true);   // mov [rax + offsetof(CONTEXT, R12)], r12
	storeRegToCtx(5, offsetof(CONTEXT, R13), true);   // mov [rax + offsetof(CONTEXT, R13)], r13
	storeRegToCtx(6, offsetof(CONTEXT, R14), true);   // mov [rax + offsetof(CONTEXT, R14)], r14
	storeRegToCtx(7, offsetof(CONTEXT, R15), true);   // mov [rax + offsetof(CONTEXT, R15)], r15

	// sub rsp, 0x10
	// (restore stack state)
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x83;
	execPtr[offset++] = 0xEC;
	execPtr[offset++] = 0x10;

	
	// ---------------------------------------------------------------------
	// store EFLAGS into CONTEXT
	// ---------------------------------------------------------------------

	// pop rax (EFLAGS)
	execPtr[offset++] = 0x58;

	// here: rax = EFLAGS

	// mov rcx, imm64 (&ctx)
	WriteMovRegImm64(execPtr, offset, 1, (uint64_t)shellCtx);

	// here: rcx = &ctx

	// mov [rcx + offsetof(CONTEXT, EFlags)], rax
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x89;
	execPtr[offset++] = 0x81;
	*(DWORD*)(execPtr + offset) = offsetof(CONTEXT, EFlags);
	offset += 4;

	// ---------------------------------------------------------------------
	// store RAX into CONTEXT
	// ---------------------------------------------------------------------

	// pop rax (rsp points at the previously saved rax value)
	execPtr[offset++] = 0x58;
	
	// write back RAX to CONTEXT using RCX as base

	// mov rcx, imm64 (&ctx)
	WriteMovRegImm64(execPtr, offset, 1, (uint64_t)shellCtx); 
	
	// here: rcx = &ctx

	// mov [rcx + offset(Rax)], rax
	execPtr[offset++] = 0x48;                      // REX.W
	execPtr[offset++] = 0x89;                      // MOV r/m64, r64
	execPtr[offset++] = 0x81;        // ModRM: reg=RAX, r/m=RCX (with disp32)
	*(DWORD*)(execPtr + offset) = offsetof(CONTEXT, Rax); // disp32 = offset of Rax
	offset += 4;

	// ---------------------------------------------------------------------
	// restore original host RSP
	// ---------------------------------------------------------------------

	// mov rax, imm64 (&g_savedRsp)
	WriteMovRegImm64(execPtr, offset, 0, (uint64_t)&g_savedRsp); 
	
	// here: rax = &g_savedRsp

	// mov rax, [rax]
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x8B;
	execPtr[offset++] = 0x00; 
	
	// here: rax = [rax]

	// mov rsp, rax
	execPtr[offset++] = 0x48;
	execPtr[offset++] = 0x89;
	execPtr[offset++] = 0xC4; 
	
	// here: rsp = rax

	// ---------------------------------------------------------------------
	// restore host registers and return
	// ---------------------------------------------------------------------

	const BYTE restoreHost[] = {
		0x9D,       // popf            ; restore EFLAGS
		0x41, 0x5F, // pop r15
		0x41, 0x5E, // pop r14
		0x41, 0x5D, // pop r13
		0x41, 0x5C, // pop r12
		0x41, 0x5B, // pop r11
		0x41, 0x5A, // pop r10
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5F,       // pop rdi
		0x5E,       // pop rsi
		0x5D,       // pop rbp
		0x5B,       // pop rbx
		0x5A,       // pop rdx
		0x59,       // pop rcx
		0x58,       // pop rax
		0xC3        // ret             ; return to caller
	};
	memcpy(execPtr + offset, restoreHost, sizeof(restoreHost));

	return offset + sizeof(restoreHost);
}

BYTE* GeneratePushReturnAddressBytes(uint64_t returnOffset, uint64_t baseAddress, SIZE_T& outSize) {
	// mov rax, <returnAddress>   (10 bytes)
	// push rax                   (1 byte)

	// returnAddress = base + offset
	uint64_t returnAddress = baseAddress + returnOffset;

	outSize = 10 + 1;
	BYTE* buffer = (BYTE*)malloc(outSize);
	if (!buffer) return nullptr;

	SIZE_T offset = 0;

	// === mov rax, <returnAddress>
	buffer[offset++] = 0x48;
	buffer[offset++] = 0xB8;
	memcpy(buffer + offset, &returnAddress, 8);
	offset += 8;

	// === push rax
	buffer[offset++] = 0x50;

	return buffer;
}
