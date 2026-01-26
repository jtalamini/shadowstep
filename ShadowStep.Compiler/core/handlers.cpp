#include <windows.h>
#include <stdio.h>
#include <cstdint>
#include "shadowmakers.h"
#include "../crypt/crypt.h"
#include "core.h"

/*
 * high-level classification of x64 instructions handled explicitly
 * by the dispatcher. This allows specialized control-flow handling
 * without executing instructions blindly.
 */
enum InstructionType {
    CALL_DIRECT,        // E8 rel32
    CALL_INDIRECT,      // FF /2
    JMP_INDIRECT,       // FF /4
    JMP_REL32,          // E9 rel32
    JMP_REL8,           // EB rel8
    LOOP,               // E2
    LOOPNE,             // E0
    LOOPE,              // E1
    RET,                // C2 / C3
    CONDITIONAL_JUMP,   // Jcc variants
    GENERIC             // All other instructions
};

// ==========================================================
// UTILITY FUNCTIONS
// ==========================================================

/*
 * determines whether the given opcode sequence represents
 * any form of conditional jump (short, near, or CX-based).
 */
BOOL IsConditionalJump(PBYTE bytes) {
    return
        (bytes[0] >= 0x70 && bytes[0] <= 0x7F) ||                     // Short Jcc
        (bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F) || // Near Jcc
        (bytes[0] == 0xE3) ||                                        // JCXZ
        (bytes[0] == 0x67 && bytes[1] == 0xE3) ||                    // JECXZ
        (bytes[0] == 0x66 && bytes[1] == 0xE3);                      // JRCXZ
}

/*
 * evaluates a SHORT conditional jump (0x70–0x7F) based on EFLAGS.
 * Returns TRUE if the jump condition is satisfied.
 */
bool EvaluateJccCondition(BYTE opcode, DWORD eflags) {
    bool ZF = (eflags & (1 << 6)) != 0;
    bool SF = (eflags & (1 << 7)) != 0;
    bool OF = (eflags & (1 << 11)) != 0;
    bool CF = (eflags & (1 << 0)) != 0;
    bool PF = (eflags & (1 << 2)) != 0;

    switch (opcode) {
    case 0x70: return OF;                    // JO
    case 0x71: return !OF;                   // JNO
    case 0x72: return CF;                    // JB
    case 0x73: return !CF;                   // JAE
    case 0x74: return ZF;                    // JE
    case 0x75: return !ZF;                   // JNE
    case 0x76: return CF || ZF;              // JBE
    case 0x77: return !CF && !ZF;            // JA
    case 0x78: return SF;                    // JS
    case 0x79: return !SF;                   // JNS
    case 0x7A: return PF;                    // JP
    case 0x7B: return !PF;                   // JNP
    case 0x7C: return SF != OF;              // JL
    case 0x7D: return SF == OF;              // JGE
    case 0x7E: return ZF || (SF != OF);      // JLE
    case 0x7F: return !ZF && (SF == OF);     // JG
    default:   return false;
    }
}

/*
 * same as EvaluateJccCondition, but for NEAR Jcc instructions
 * (0F 80–8F encoding).
 */
bool EvaluateJccConditionNear(BYTE subOpcode, DWORD eflags) {
    return EvaluateJccCondition(subOpcode - 0x10, eflags);
}

/*
 * performs a lightweight opcode-based classification to determine
 * whether an instruction requires custom control-flow handling.
 */
InstructionType ClassifyInstruction(PBYTE bytes) {
    BYTE opcode = bytes[0];

    if (opcode == 0xE8) return CALL_DIRECT;
    if (opcode == 0xE9) return JMP_REL32;
    if (opcode == 0xEB) return JMP_REL8;
    if (opcode == 0xE2) return LOOP;
    if (opcode == 0xE0) return LOOPNE;
    if (opcode == 0xE1) return LOOPE;
    if (opcode == 0xC2 || opcode == 0xC3) return RET;
    if (IsConditionalJump(bytes)) return CONDITIONAL_JUMP;

    // FF /2 = CALL r/m64, FF /4 = JMP r/m64
    if (opcode == 0xFF) {
        BYTE reg = (bytes[1] >> 3) & 0x07;
        if (reg == 2) return CALL_INDIRECT;
        if (reg == 4) return JMP_INDIRECT;
    }

    return GENERIC;
}

/*
 * returns a pointer to the 64-bit register specified by
 * the ModRM r/m field.
 */
const uint64_t* GetRegisterPointer(CONTEXT* ctx, BYTE rm) {
    static const uint64_t* regs[] = {
        &ctx->Rax, &ctx->Rcx, &ctx->Rdx, &ctx->Rbx,
        &ctx->Rsp, &ctx->Rbp, &ctx->Rsi, &ctx->Rdi
    };
    return regs[rm];
}

/*
 * resolves an indirect register-based target address and checks
 * whether it falls inside the shellcode memory range.
 */
BOOL IsAddressInShellcode(CONTEXT* ctx, ShellcodeContext* sc, BYTE modrm, OUT uint64_t* address) {
    BYTE rm = modrm & 0x7;
    *address = *GetRegisterPointer(ctx, rm);

    uint64_t base = (uint64_t)sc->shellcode;
    return (*address >= base && *address <= base + sc->shellcodeSize);
}

// ==========================================================
// INSTRUCTION HANDLERS
// ==========================================================

/*
 * emulates a direct CALL (E8):
 *  - pushes the return address onto the virtual stack
 *  - updates currentInstrOffset to the call target
 */
void HandleDirectCallInstruction(ShellcodeContext* sc, CONTEXT* ctx, BYTE* execBuffer, DWORD offset, DWORD size) {
    uint64_t returnAddress = (uint64_t)(sc->shellcode + sc->currentInstrOffset + size);
    ctx->Rsp -= 8;
    *(uint64_t*)(ctx->Rsp) = returnAddress;
    int32_t relOffset = *(int32_t*)(sc->shellcode + offset + 1);
    sc->currentInstrOffset += size + relOffset;
}

/*
 * handles indirect CALL/JMP targeting an address inside the shellcode.
 * For CALL, a synthetic return address is pushed manually.
 */
void HandleIndirectCallOrJumpInstruction(ShellcodeContext* sc, CONTEXT* ctx, BYTE* execBuffer, DWORD offset, DWORD size, BYTE* bytes) {
    BYTE rm = bytes[1] & 0x07;
    uint64_t targetAddr = *GetRegisterPointer(ctx, rm);

    // FF /2 -> CALL r/m64
    BYTE regOpcode = (bytes[1] >> 3) & 0x07;
    if (regOpcode == 0x02) {
        SIZE_T pushSize = 0;
        BYTE* instr = GeneratePushReturnAddressBytes(sc->currentInstrOffset + size, (uint64_t)sc->shellcode, pushSize);
        if (instr) {
            ShadowStep(execBuffer, instr, pushSize, ctx);
            free(instr);
        }
    }

    sc->currentInstrOffset = (DWORD)(targetAddr - (uint64_t)sc->shellcode);
}

/*
 * executes an indirect CALL targeting an external API.
 * execution is delegated directly to ShadowStep.
 */
void HandleIndirectCallToAPI(ShellcodeContext* sc, CONTEXT* ctx, BYTE* execBuffer, DWORD offset, DWORD size, BYTE* bytes) {
    ShadowStep(execBuffer, bytes, size, ctx);
    sc->currentInstrOffset += size;
}

/*
 * handles JMP to an external API by restoring execution flow
 * using the return address already present on the stack.
 */
void HandleIndirectJumpToAPI(ShellcodeContext* sc, CONTEXT* ctx, BYTE* execBuffer, DWORD offset, DWORD size, BYTE* bytes) {
    uint64_t returnAddr = *(uint64_t*)(ctx->Rsp);
    sc->currentInstrOffset = (DWORD)(returnAddr - (uint64_t)sc->shellcode);
    *(uint64_t*)(ctx->Rsp) = (DWORD64)(execBuffer + 0xD5 + size);
    ShadowStep(execBuffer, bytes, size, ctx);
}

/*
 * emulates LOOP instruction semantics (RCX-based loop).
 */
void HandleLoopInstruction(ShellcodeContext* sc, CONTEXT* ctx, DWORD size, BYTE relOffset) {
    ctx->Rcx--;
    if (ctx->Rcx != 0)
        sc->currentInstrOffset += size + (int8_t)relOffset;
    else
        sc->currentInstrOffset += size;
}

/*
 * Handles E9 rel32 jumps.
 */
void HandleRelativeJumpInstruction(ShellcodeContext* sc, BYTE* bytes, DWORD size) {
    int32_t relOffset = *(int32_t*)(bytes + 1);
    sc->currentInstrOffset += size + relOffset;
}

/*
 * Handles EB rel8 jumps.
 */
void HandleShortJumpInstruction(ShellcodeContext* sc, BYTE* bytes, DWORD size) {
    int8_t relOffset = *(int8_t*)(bytes + 1);
    sc->currentInstrOffset += size + relOffset;
}

/*
 * evaluates condition flags and updates control flow accordingly
 * without executing the instruction natively.
 */
void HandleConditionalJumpInstruction(ShellcodeContext* sc, CONTEXT* ctx, BYTE* bytes, DWORD size) {
    int32_t relOffset = 0;
    BOOL condition = FALSE;

    if (bytes[0] >= 0x70 && bytes[0] <= 0x7F) {
        relOffset = *(int8_t*)(bytes + 1);
        condition = EvaluateJccCondition(bytes[0], ctx->EFlags);
    }
    else if (bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F) {
        relOffset = *(int32_t*)(bytes + 2);
        condition = EvaluateJccConditionNear(bytes[1], ctx->EFlags);
    }
    else if (bytes[0] == 0xE3) { // JCXZ
        relOffset = *(int8_t*)(bytes + 1);
        condition = ((ctx->Rcx & 0xFFFF) == 0);
    }
    else if (bytes[0] == 0x67 && bytes[1] == 0xE3) { // JECXZ
        relOffset = *(int8_t*)(bytes + 2);
        condition = ((ctx->Rcx & 0xFFFFFFFF) == 0);
    }
    else if (bytes[0] == 0x66 && bytes[1] == 0xE3) { // JRCXZ
        relOffset = *(int8_t*)(bytes + 2);
        condition = (ctx->Rcx == 0);
    }

    sc->currentInstrOffset += condition ? (size + relOffset) : size;
}

/*
 * emulates RET semantics, including stack cleanup for RET imm16.
 */
void HandleRetInstruction(ShellcodeContext* sc, CONTEXT* ctx, BYTE* bytes, DWORD size) {
    uint64_t returnAddress = *(uint64_t*)(ctx->Rsp);
    ctx->Rsp += 8;
    
    // RET imm16
    if (bytes[0] == 0xC2 && size == 3) {
        uint16_t imm16 = *(uint16_t*)(bytes + 1);
        ctx->Rsp += imm16;
    }

    sc->currentInstrOffset = (DWORD)(returnAddress - (uint64_t)sc->shellcode);
}

/*
 * placeholder for LOOPE / LOOPNE handling.
 */
void HandleLoopExInstruction(BYTE* bytes) {
    printf(bytes[0] == 0xE1 ? "LOOPE\n" : "LOOPNE\n");
    printf("TODO: not implemented\n");
    exit(0);
}

/*
 * executes any non-control-flow instruction via ShadowStep and the execution buffer
 * and advances the instruction pointer normally.
 */
void HandleGenericInstruction(ShellcodeContext* sc, CONTEXT* ctx, BYTE* execBuffer, BYTE* bytes, DWORD size) {
    ShadowStep(execBuffer, bytes, size, ctx);
    sc->currentInstrOffset += size;
}

// ==========================================================
// MAIN DISPATCHER
// ==========================================================

/*
 * central instruction dispatcher. determines instruction type,
 * applies specialized handling when required, and decides whether
 * native execution should be skipped.
 * returns TRUE if execution flow was fully handled manually.
 */
BOOL HandleInstruction(
    BYTE* bytes,
    DWORD offset,
    DWORD size,
    ShellcodeContext* sc,
    CONTEXT* ctx,
    BYTE* execBuffer
) {
    InstructionType type = ClassifyInstruction(bytes);
    uint64_t address = 0;

    switch (type) {
    case CALL_DIRECT:
        HandleDirectCallInstruction(sc, ctx, execBuffer, offset, size);
        return TRUE;

    case CALL_INDIRECT:
    case JMP_INDIRECT: {
        BYTE modrm = bytes[1];
        if (IsAddressInShellcode(ctx, sc, modrm, &address)) {
            printf("[+] %s 0x%p (SHELLCODE)\n", (type == CALL_INDIRECT ? "CALL" : "JMP"), (void*)address);
            HandleIndirectCallOrJumpInstruction(sc, ctx, execBuffer, offset, size, bytes);
        }
        else {
            printf("[+] %s 0x%p (EXTERNAL)\n", (type == CALL_INDIRECT ? "CALL" : "JMP"), (void*)address);
            if (type == CALL_INDIRECT)
                HandleIndirectCallToAPI(sc, ctx, execBuffer, offset, size, bytes);
            else
                HandleIndirectJumpToAPI(sc, ctx, execBuffer, offset, size, bytes);
        }
        return FALSE;
    }

    case JMP_REL32:
        HandleRelativeJumpInstruction(sc, bytes, size);
        return TRUE;

    case JMP_REL8:
        HandleShortJumpInstruction(sc, bytes, size);
        return TRUE;

    case CONDITIONAL_JUMP:
        HandleConditionalJumpInstruction(sc, ctx, bytes, size);
        return TRUE;

    case LOOP:
        HandleLoopInstruction(sc, ctx, size, bytes[1]);
        return TRUE;

    case LOOPNE:
    case LOOPE:
        HandleLoopExInstruction(bytes);
        return TRUE;

    case RET:
        HandleRetInstruction(sc, ctx, bytes, size);
        return TRUE;

    case GENERIC:
    default:
        HandleGenericInstruction(sc, ctx, execBuffer, bytes, size);
        return FALSE;
    }
}
