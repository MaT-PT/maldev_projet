#include "libaes.h"
#include <Windows.h>
#include <string.h>
#include "utils.h"

/// @brief AES S-box
static BYTE sbox[256];
#define getSBoxValue(num) (sbox[num])

/// @brief AES inverse S-box
static BYTE rsbox[256];
#define getSBoxInvert(num) (rsbox[num])

#define Multiply(x, y)                                                              \
    (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^ \
     ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^ ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))))

static CONST BYTE Rcon[] = {0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

VOID AES_InitSbox(VOID) {
    AES_generateSbox(sbox);
}

VOID AES_InitSboxInv(VOID) {
    AES_generateSboxInv(rsbox);
}

static VOID CopyIv(OUT CONST PAES_IV pIvDst, IN CONST PCAES_IV pIvSrc) {
    for (DWORD i = 0; i < ARRAYSIZE((*pIvDst).qw); i++) {
        (*pIvDst).qw[i] = (*pIvSrc).qw[i];
    }
}

static VOID KeyExpansion(OUT CONST PAES_KEYEX pRoundKey, IN CONST PCAES_KEY pKey) {
    DWORD i = 0;
    AES_KEYEX_ROW tmp;  // Used for the column/row operations

    // The first round key is the key itself.
    for (; i < AES_NROWS; ++i) {
        (*pRoundKey)[i].dw = (*pKey)[i].dw;
    }

    // All other round keys are found from the previous round keys.
    for (; i < AES_NCOLS * (AES_NROUNDS + 1); ++i) {
        tmp.dw = (*pRoundKey)[i - 1].dw;

        if (i % AES_NROWS == 0) {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

            // Function RotWord()
            tmp.dw = MY_ROTR32(tmp.dw, 8);

            // SubWord() is a function that takes a four-byte input word and
            // applies the S-box to each of the four bytes to produce an output word.

            // Function Subword()
            tmp.b[0] = getSBoxValue(tmp.b[0]) ^ Rcon[i / AES_NROWS];
            tmp.b[1] = getSBoxValue(tmp.b[1]);
            tmp.b[2] = getSBoxValue(tmp.b[2]);
            tmp.b[3] = getSBoxValue(tmp.b[3]);
        }

        (*pRoundKey)[i].dw = (*pRoundKey)[i - AES_NROWS].dw ^ tmp.dw;
    }
}

VOID AES_init_ctx_iv(OUT CONST PAES_CTX pCtx, IN CONST PCAES_KEY pKey, IN CONST PCAES_IV pIv) {
    KeyExpansion(&pCtx->RoundKey, pKey);
    CopyIv(&pCtx->Iv, pIv);
}

static VOID AddRoundKey(IN CONST BYTE round, IN OUT CONST PAES_STATE pState,
                        IN CONST PCAES_KEYEX pRoundKey) {
    for (BYTE i = 0; i < 4; ++i) {
        (*pState)[i].dw ^= (*pRoundKey)[round * AES_NCOLS + i].dw;
    }
}

static VOID SubBytes(IN OUT CONST PAES_STATE pState) {
    DWORD i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*pState)[j].b[i] = getSBoxValue((*pState)[j].b[i]);
        }
    }
}

static VOID ShiftRows(IN OUT CONST PAES_STATE pState) {
    BYTE temp;

    // Rotate first row 1 columns to left
    temp = (*pState)[0].b[1];
    (*pState)[0].b[1] = (*pState)[1].b[1];
    (*pState)[1].b[1] = (*pState)[2].b[1];
    (*pState)[2].b[1] = (*pState)[3].b[1];
    (*pState)[3].b[1] = temp;

    // Rotate second row 2 columns to left
    temp = (*pState)[0].b[2];
    (*pState)[0].b[2] = (*pState)[2].b[2];
    (*pState)[2].b[2] = temp;

    temp = (*pState)[1].b[2];
    (*pState)[1].b[2] = (*pState)[3].b[2];
    (*pState)[3].b[2] = temp;

    // Rotate third row 3 columns to left
    temp = (*pState)[0].b[3];
    (*pState)[0].b[3] = (*pState)[3].b[3];
    (*pState)[3].b[3] = (*pState)[2].b[3];
    (*pState)[2].b[3] = (*pState)[1].b[3];
    (*pState)[1].b[3] = temp;
}

static BYTE xtime(IN CONST BYTE x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1B);
}

static void MixColumns(IN OUT CONST PAES_STATE pState) {
    DWORD i;
    BYTE tmp, tm, t;
    for (i = 0; i < 4; ++i) {
        t = (*pState)[i].b[0];
        tmp = (*pState)[i].b[0] ^ (*pState)[i].b[1] ^ (*pState)[i].b[2] ^ (*pState)[i].b[3];
        tm = (*pState)[i].b[0] ^ (*pState)[i].b[1];
        tm = xtime(tm);
        (*pState)[i].b[0] ^= tm ^ tmp;
        tm = (*pState)[i].b[1] ^ (*pState)[i].b[2];
        tm = xtime(tm);
        (*pState)[i].b[1] ^= tm ^ tmp;
        tm = (*pState)[i].b[2] ^ (*pState)[i].b[3];
        tm = xtime(tm);
        (*pState)[i].b[2] ^= tm ^ tmp;
        tm = (*pState)[i].b[3] ^ t;
        tm = xtime(tm);
        (*pState)[i].b[3] ^= tm ^ tmp;
    }
}

static VOID InvSubBytes(IN OUT CONST PAES_STATE pState) {
    DWORD i, j;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j) {
            (*pState)[j].b[i] = getSBoxInvert((*pState)[j].b[i]);
        }
    }
}

static void InvShiftRows(IN OUT CONST PAES_STATE pState) {
    BYTE temp;

    // Rotate first row 1 columns to right
    temp = (*pState)[3].b[1];
    (*pState)[3].b[1] = (*pState)[2].b[1];
    (*pState)[2].b[1] = (*pState)[1].b[1];
    (*pState)[1].b[1] = (*pState)[0].b[1];
    (*pState)[0].b[1] = temp;

    // Rotate second row 2 columns to right
    temp = (*pState)[0].b[2];
    (*pState)[0].b[2] = (*pState)[2].b[2];
    (*pState)[2].b[2] = temp;

    temp = (*pState)[1].b[2];
    (*pState)[1].b[2] = (*pState)[3].b[2];
    (*pState)[3].b[2] = temp;

    // Rotate third row 3 columns to right
    temp = (*pState)[0].b[3];
    (*pState)[0].b[3] = (*pState)[1].b[3];
    (*pState)[1].b[3] = (*pState)[2].b[3];
    (*pState)[2].b[3] = (*pState)[3].b[3];
    (*pState)[3].b[3] = temp;
}

static VOID InvMixColumns(IN OUT CONST PAES_STATE pState) {
    DWORD i;
    BYTE a, b, c, d, T, X;
    for (i = 0; i < 4; ++i) {
        a = (*pState)[i].b[0];
        b = (*pState)[i].b[1];
        c = (*pState)[i].b[2];
        d = (*pState)[i].b[3];

        // (*pState)[i].b[0] =
        //     Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        // (*pState)[i].b[1] =
        //     Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        // (*pState)[i].b[2] =
        //     Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        // (*pState)[i].b[3] =
        //     Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);

        T = a ^ b ^ c ^ d;
        T ^= xtime(xtime(xtime(T)));
        X = xtime(xtime(a ^ c));
        (*pState)[i].b[0] = T ^ X ^ xtime(a ^ b) ^ a;
        (*pState)[i].b[2] = T ^ X ^ xtime(c ^ d) ^ c;
        X = xtime(xtime(b ^ d));
        (*pState)[i].b[1] = T ^ X ^ xtime(b ^ c) ^ b;
        (*pState)[i].b[3] = T ^ X ^ xtime(d ^ a) ^ d;
    }
}

static VOID Cipher(IN OUT CONST PAES_STATE pState, IN CONST PCAES_KEYEX pRoundKey) {
    BYTE round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, pState, pRoundKey);

    // There will be AES_NROUNDS rounds.
    // The first AES_NROUNDS-1 rounds are identical.
    // These AES_NROUNDS rounds are executed in the loop below.
    // Last one without MixColumns()
    for (round = 1;; ++round) {
        SubBytes(pState);
        ShiftRows(pState);
        if (round == AES_NROUNDS) {
            break;
        }
        MixColumns(pState);
        AddRoundKey(round, pState, pRoundKey);
    }
    // Add round key to last round
    AddRoundKey(AES_NROUNDS, pState, pRoundKey);
}

static VOID InvCipher(IN OUT CONST PAES_STATE pState, IN CONST PCAES_KEYEX pRoundKey) {
    BYTE round = 0;

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(AES_NROUNDS, pState, pRoundKey);

    // There will be AES_NROUNDS rounds.
    // The first AES_NROUNDS-1 rounds are identical.
    // These AES_NROUNDS rounds are executed in the loop below.
    // Last one without InvMixColumn()
    for (round = (AES_NROUNDS - 1);; --round) {
        InvShiftRows(pState);
        InvSubBytes(pState);
        AddRoundKey(round, pState, pRoundKey);
        if (round == 0) {
            break;
        }
        InvMixColumns(pState);
    }
}

static VOID XorWithIv(IN OUT CONST PBYTE pBuf, IN CONST PCAES_IV pIv) {
    for (DWORD i = 0; i < ARRAYSIZE((*pIv).qw); i++) {
        ((PDWORD64)pBuf)[i] ^= (*pIv).qw[i];
    }
}

VOID AES_CBC_encrypt_buffer(IN OUT CONST PAES_CTX pCtx, IN OUT PBYTE pBuf, CONST SIZE_T length) {
    SIZE_T i;
    PCAES_IV pIv = &pCtx->Iv;
    for (i = 0; i < length; i += AES_BLOCKSZ) {
        XorWithIv(pBuf, pIv);
        Cipher((PAES_STATE)pBuf, &pCtx->RoundKey);
        pIv = (PCAES_IV)pBuf;
        pBuf += AES_BLOCKSZ;
    }
    /* store Iv in ctx for next call */
    CopyIv(&pCtx->Iv, pIv);
}

VOID AES_CBC_decrypt_buffer(IN OUT CONST PAES_CTX pCtx, IN OUT PBYTE pBuf, CONST SIZE_T length) {
    SIZE_T i;
    AES_IV storeNextIv;
    for (i = 0; i < length; i += AES_BLOCKSZ) {
        CopyIv(&storeNextIv, (PCAES_IV)pBuf);
        InvCipher((PAES_STATE)pBuf, &pCtx->RoundKey);
        XorWithIv(pBuf, &pCtx->Iv);
        CopyIv(&pCtx->Iv, &storeNextIv);
        pBuf += AES_BLOCKSZ;
    }
}

int TestSbox(VOID) {
    AES_InitSbox();
    HexDump(sbox, sizeof(sbox));

    AES_InitSboxInv();
    HexDump(rsbox, sizeof(rsbox));

    for (SIZE_T i = 0; i < sizeof(sbox); i++) {
        if (rsbox[sbox[i]] != i) {
            printf("Error: sbox[%02zX] = %02hhX; rsbox[%02hhX] = %02hhX\n", i, sbox[i], sbox[i],
                   rsbox[sbox[i]]);
            return 1;
        }
    }

    return 0;
}
