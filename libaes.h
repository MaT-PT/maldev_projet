#ifndef _LIBAES_H_
#define _LIBAES_H_

#include <Windows.h>
#include <stdint.h>
#include "utils.h"

#define AES_BLOCKSZ 16 /* AES block size in bytes (always 16 bytes/128 bits) */
#define AES_KEYSIZE 16 /* Key size in bytes (16 bytes/128 bits for AES-128) */
#define AES_NROUNDS 10 /* Number of rounds in AES-128 */
#define AES_NCOLS   4  /* Number of columns in state (always 4) */

#define AES_KEYEXSZ \
    (AES_KEYSIZE * (AES_NROUNDS + 1))       /* Key expansion size in bytes (176 for AES-128) */
#define AES_NROWS (AES_KEYSIZE / AES_NCOLS) /* Number of 32-bit words in a key (4 for AES-128) */

EXTERN_C_START

typedef union _AES_STATE_ROW {
    DWORD32 dw;
    BYTE b[AES_NCOLS];
} AES_STATE_ROW, *PAES_STATE_ROW;
typedef CONST AES_STATE_ROW* PCAES_STATE_ROW;

typedef AES_STATE_ROW AES_STATE[AES_BLOCKSZ / AES_NCOLS];
typedef AES_STATE* PAES_STATE;
typedef CONST AES_STATE* PCAES_STATE;

typedef union _AES_KEY_ROW {
    DWORD32 dw;
    BYTE b[AES_NCOLS];
} AES_KEY_ROW, *PAES_KEY_ROW;
typedef CONST AES_KEY_ROW* PCAES_KEY_ROW;

typedef AES_KEY_ROW AES_KEY[AES_NROWS];
typedef AES_KEY* PAES_KEY;
typedef CONST AES_KEY* PCAES_KEY;

typedef union _AES_KEYEX_ROW {
    DWORD32 dw;
    BYTE b[AES_NCOLS];
} AES_KEYEX_ROW, *PAES_KEYEX_ROW;
typedef CONST AES_KEYEX_ROW* PCAES_KEYEX_ROW;

typedef AES_KEYEX_ROW AES_KEYEX[AES_KEYEXSZ / AES_NCOLS];
typedef AES_KEYEX* PAES_KEYEX;
typedef CONST AES_KEYEX* PCAES_KEYEX;

typedef union _AES_IV {
    DWORD64 qw[AES_BLOCKSZ / sizeof(DWORD64)];
    BYTE b[AES_BLOCKSZ];
} AES_IV, *PAES_IV;
typedef CONST AES_IV* PCAES_IV;

typedef struct _AES_CTX {
    AES_KEYEX RoundKey;
    AES_IV Iv;
} AES_CTX, *PAES_CTX;
typedef CONST AES_CTX* PCAES_CTX;

static inline VOID AES_generateIndices(OUT BYTE pIndices[256]) {
    DWORD x = 1;
    for (SIZE_T i = 0; i < 256; i++) {
        pIndices[i] = (BYTE)x;
        // printf("t[%3d] = %02X\n", i, x);
        x ^= (x << 1) ^ ((x >> 7) * 283);
    }
}

static inline VOID AES_generateSbox(OUT BYTE pSbox[256]) {
    DWORD x;
    BYTE t[256];
    AES_generateIndices(t);

    pSbox[0] = 0x63;
    for (SIZE_T i = 0; i < 255; i++) {
        x = t[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        pSbox[t[i]] = (BYTE)(x ^ 0x63);
        // printf("pSbox[%3d] = %02X\n", t[i], pSbox[t[i]]);
    }
}

static inline VOID AES_generateSboxInv(OUT BYTE pSboxInv[256]) {
    DWORD x;
    BYTE t[256];
    AES_generateIndices(t);

    pSboxInv[0x63] = 0;
    for (SIZE_T i = 0; i < 255; i++) {
        x = t[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        pSboxInv[(x ^ 0x63) & 0xFF] = t[i];
        // printf("pSboxInv[%3d] = %02X\n", (x ^ 0x63) & 0xFF, t[i]);
    }
}

VOID AES_InitSbox(VOID);
VOID AES_InitSboxInv(VOID);

VOID AES_init_ctx_iv(OUT CONST PAES_CTX pCtx, IN CONST PCAES_KEY pKey, IN CONST PCAES_IV pIv);

// buffer size MUST be mutiple of AES_BLOCKSZ
VOID AES_CBC_encrypt_buffer(IN OUT CONST PAES_CTX pCtx, IN OUT PBYTE pBuf, CONST SIZE_T length);
VOID AES_CBC_decrypt_buffer(IN OUT CONST PAES_CTX pCtx, IN OUT PBYTE pBuf, CONST SIZE_T length);

int TestSbox(VOID);

EXTERN_C_END

#endif  // _LIBAES_H_
