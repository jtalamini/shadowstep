#pragma once
#include "core.h"

LONG WINAPI ShadowStepHandler(EXCEPTION_POINTERS* ep, ShellcodeContext* sc);

BOOL HandleInstruction(
	BYTE* bytes,
	DWORD offset,
	DWORD size,
	ShellcodeContext* sc,
	CONTEXT* ctx,
	BYTE* execBuffer
);