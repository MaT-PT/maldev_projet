#ifndef _ENCRYPT_H_
#define _ENCRYPT_H_

#include <Windows.h>
#include "injected.h"
#include "libaes.h"
#include "libproc.hpp"

EXTERN_C_START

static inline LONG EncryptPayload(IN OUT PBYTE pPayload, IN CONST SIZE_T szPayloadSize,
                                  IN CONST PCAES_KEY pKey, IN CONST PCAES_IV pIv) {
    printf("Encrypting %#llx bytes starting at %#p\n", szPayloadSize, pPayload);

    if (szPayloadSize % AES_BLOCKSZ != 0) {
        printf("Payload size must be a multiple of %d\n", AES_BLOCKSZ);
        return ERROR_INCORRECT_SIZE;
    }

    AES_SBOX sbox;
    AES_GenerateSbox(&sbox);

    AES_CTX ctx;
    AES_InitCtx(&ctx, pKey, pIv, &sbox, NULL);
    AES_Encrypt(&ctx, pPayload, szPayloadSize);

    return ERROR_SUCCESS;
}

INJECTED_CODE static __forceinline VOID DecryptPayload(IN OUT PBYTE pPayload,
                                                       IN CONST SIZE_T szPayloadSize) {
    AES_SBOX sbox, sboxInv;
    AES_GenerateSboxAndInv(&sbox, &sboxInv);

    CONST auto DEOBF(key) = Deobfuscator(aes_key);
    CONST auto DEOBF(iv) = Deobfuscator(aes_iv);

    AES_CTX ctx;
    AES_InitCtx(&ctx, (PCAES_KEY)DEOBF_BYTES(key), (PCAES_IV)DEOBF_BYTES(iv), &sbox, &sboxInv);
    AES_Decrypt(&ctx, pPayload, szPayloadSize);
}

EXTERN_C_END

#endif  // _ENCRYPT_H_
