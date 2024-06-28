#ifndef _LIBAES_H_
#define _LIBAES_H_

#include <Windows.h>
#include <stdint.h>
#include "injected.h"
#include "utils.h"

#define AES_BLOCKSZ 16 /* AES block size in bytes (always 16 bytes/128 bits) */
#define AES_KEYSIZE 16 /* Key size in bytes (16 bytes/128 bits for AES-128) */
#define AES_NROUNDS 10 /* Number of rounds in AES-128 */
#define AES_NCOLS   4  /* Number of columns in state (always 4) */

#define AES_KEYEXSZ \
    (AES_KEYSIZE * (AES_NROUNDS + 1))       /* Key expansion size in bytes (176 for AES-128) */
#define AES_NROWS (AES_KEYSIZE / AES_NCOLS) /* Number of 32-bit words in a key (4 for AES-128) */

EXTERN_C_START

typedef BYTE AES_SBOX[256];          // AES S-box
typedef AES_SBOX* PAES_SBOX;         // Pointer to AES S-box
typedef CONST AES_SBOX* PCAES_SBOX;  // Pointer to const AES S-box

/// @brief AES state row (4 bytes)
typedef union _AES_STATE_ROW {
    BYTE b[AES_NCOLS];  // Byte representation
    DWORD32 dw;         // 32-bit int representation
} AES_STATE_ROW, *PAES_STATE_ROW;
typedef CONST AES_STATE_ROW* PCAES_STATE_ROW;  // Pointer to const AES state row

/// @brief AES state (16 bytes, used for both state and block)
typedef union _AES_STATE {
    BYTE b[AES_BLOCKSZ];                       // Byte representation
    AES_STATE_ROW r[AES_BLOCKSZ / AES_NCOLS];  // Rows
} AES_STATE, *PAES_STATE;
typedef CONST AES_STATE* PCAES_STATE;  // Pointer to const AES state

/// @brief AES key row (4 bytes)
typedef union _AES_KEY_ROW {
    BYTE b[AES_NCOLS];  // Byte representation
    DWORD32 dw;         // 32-bit int representation
} AES_KEY_ROW, *PAES_KEY_ROW;
typedef CONST AES_KEY_ROW* PCAES_KEY_ROW;  // Pointer to const AES key row

/// @brief AES key (16 bytes)
typedef union _AES_KEY {
    BYTE b[AES_KEYSIZE];       // Byte representation
    AES_KEY_ROW r[AES_NROWS];  // Rows
} AES_KEY, *PAES_KEY;
typedef CONST AES_KEY* PCAES_KEY;  // Pointer to const AES key

/// @brief AES key expansion row (4 bytes)
typedef union _AES_KEYEX_ROW {
    BYTE b[AES_NCOLS];  // Byte representation
    DWORD32 dw;         // 32-bit int representation
} AES_KEYEX_ROW, *PAES_KEYEX_ROW;
typedef CONST AES_KEYEX_ROW* PCAES_KEYEX_ROW;  // Pointer to const AES key expansion row

/// @brief AES key expansion (176 bytes)
typedef union _AES_KEYEX {
    BYTE b[AES_KEYEXSZ];                       // Byte representation
    AES_KEYEX_ROW r[AES_KEYEXSZ / AES_NCOLS];  // Rows
} AES_KEYEX, *PAES_KEYEX;
typedef CONST AES_KEYEX* PCAES_KEYEX;  // Pointer to const AES key expansion

/// @brief AES initialization vector (16 bytes)
typedef union _AES_IV {
    BYTE b[AES_BLOCKSZ];                        // Byte representation
    DWORD64 qw[AES_BLOCKSZ / sizeof(DWORD64)];  // Two 64-bit integers (for a total of 16 bytes)
} AES_IV, *PAES_IV;
typedef CONST AES_IV* PCAES_IV;  // Pointer to const AES initialization vector

/// @brief AES context (key and IV)
typedef struct _AES_CTX {
    AES_KEYEX RoundKey;   // Expanded key
    AES_IV Iv;            // Initialization vector
    PCAES_SBOX pSbox;     // Pointer to AES S-box
    PCAES_SBOX pSboxInv;  // Pointer to AES inverse S-box
} AES_CTX, *PAES_CTX;
typedef CONST AES_CTX* PCAES_CTX;  // Pointer to const AES context

INJECTED_CODE static inline VOID AES_GenerateIndices(OUT BYTE pIndices[256]) {
    DWORD x = 1;
    for (SIZE_T i = 0; i < 256; i++) {
        pIndices[i] = (BYTE)x;
        // printf("t[%3d] = %02X\n", i, x);
        x ^= (x << 1) ^ ((x >> 7) * 283);
    }
}

INJECTED_CODE static inline VOID AES_GenerateSbox(OUT PAES_SBOX pSbox) {
    DWORD x;
    BYTE t[256];
    AES_GenerateIndices(t);

    (*pSbox)[0] = 0x63;
    for (SIZE_T i = 0; i < 255; i++) {
        x = t[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        (*pSbox)[t[i]] = (BYTE)(x ^ 0x63);
        // printf("pSbox[%3d] = %02X\n", t[i], pSbox[t[i]]);
    }
}

INJECTED_CODE static inline VOID AES_GenerateSboxInv(OUT PAES_SBOX pSboxInv) {
    DWORD x;
    BYTE t[256];
    AES_GenerateIndices(t);

    (*pSboxInv)[0x63] = 0;
    for (SIZE_T i = 0; i < 255; i++) {
        x = t[255 - i];
        x |= x << 8;
        x ^= (x >> 4) ^ (x >> 5) ^ (x >> 6) ^ (x >> 7);
        (*pSboxInv)[(x ^ 0x63) & 0xFF] = t[i];
        // printf("pSboxInv[%3d] = %02X\n", (x ^ 0x63) & 0xFF, t[i]);
    }
}

INJECTED_CODE VOID AES_InitCtx(OUT CONST PAES_CTX pCtx, IN CONST PCAES_KEY pKey,
                               IN CONST PCAES_IV pIv, IN CONST PCAES_SBOX pSbox,
                               IN CONST PCAES_SBOX pSboxInv);

// buffer size MUST be mutiple of AES_BLOCKSZ
INJECTED_CODE VOID AES_Encrypt(IN OUT CONST PAES_CTX pCtx, IN OUT PBYTE pBuf, CONST SIZE_T length);
INJECTED_CODE VOID AES_Decrypt(IN OUT CONST PAES_CTX pCtx, IN OUT PBYTE pBuf, CONST SIZE_T length);

INJECTED_CODE int AES_TestSbox(VOID);

EXTERN_C_END

#endif  // _LIBAES_H_
