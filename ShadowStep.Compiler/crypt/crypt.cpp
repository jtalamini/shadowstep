#include <windows.h>
#include "crypt.h"

// apply XOR encryption

PBYTE XORInstruction(IN OUT PBYTE* buffer, SIZE_T index, SIZE_T size, PBYTE keys, SIZE_T keySize) {

    PBYTE buf = *buffer;
    BYTE b;
    BYTE k;
    BYTE e;
    SIZE_T j = index % keySize;

    for (SIZE_T i = index; i < size + index; i++) {

        b = buf[i];
        k = keys[j];
        e = b ^ k;
        // printf("%x ^ %x = %x\n", b, k, e);
        buf[i] = e;
        j += 1;
        if (j == keySize) {
            j = 0;
        }
    }
    return *buffer;
}


void RC4KeySchedule(BYTE* S, PBYTE key, SIZE_T keyLen) {
    for (int i = 0; i < 256; i++) S[i] = i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keyLen]) & 0xFF;
        BYTE tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}

void RC4GenerateKeystream(BYTE* S, BYTE* keystream, SIZE_T count, SIZE_T skip) {
    int i = 0, j = 0;
    for (SIZE_T s = 0; s < skip + count; s++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        BYTE tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        BYTE K = S[(S[i] + S[j]) & 0xFF];
        if (s >= skip) {
            keystream[s - skip] = K;
        }
    }
}

PBYTE RC4Instruction(PBYTE* buffer, SIZE_T index, SIZE_T size, PBYTE key, SIZE_T keySize) {
    BYTE S[256];
    BYTE* keystream = (BYTE*)malloc(size);
    if (!keystream) return NULL;

    RC4KeySchedule(S, key, keySize);
    RC4GenerateKeystream(S, keystream, size, index);

    for (SIZE_T i = 0; i < size; i++) {
        (*buffer)[index + i] ^= keystream[i];
    }

    free(keystream);
    return *buffer;
}

// generic encryption algorithm

void ApplyCryptInstruction(PBYTE* shellcode, SIZE_T offset, SIZE_T size, PBYTE keys, SIZE_T keySize, EncryptionType encryption) {
    if (encryption == ENCRYPTION_RC4) {
        RC4Instruction(shellcode, offset, size, keys, keySize);
    }
    else {
        XORInstruction(shellcode, offset, size, keys, keySize);
    }
}
