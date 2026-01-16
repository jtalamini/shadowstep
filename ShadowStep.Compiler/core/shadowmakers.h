#pragma once

#include <windows.h>
#include <cstdint>

SIZE_T ShadowStep(
	BYTE* execPtr,
	const BYTE* instruction,
	SIZE_T instrSize,
	CONTEXT* shellCtx
);

BYTE* GeneratePushReturnAddressBytes(
	uint64_t returnOffset, 
	uint64_t baseAddress, 
	SIZE_T& outSize
);