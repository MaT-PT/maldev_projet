#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "libaes.h"
#include "utils.h"

int main(VOID) {
    int ret = 0;
    ret = AES_TestSbox();
    if (ret) {
        printf("Error: AES_TestSbox failed\n");
        goto exit;
    }

#pragma warning(suppress : 4295)  // Ignore warning about extra NULL terminator
    CONST AES_KEY key = {.b = "ThisIsA16ByteKey"};
#pragma warning(suppress : 4295)
    CONST AES_IV iv = {.b = "!Random16ByteIV!"};
#pragma warning(suppress : 4295)
    CONST BYTE msg[64] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit egestas.";

    BYTE buf[sizeof(msg)];
    memcpy(buf, msg, sizeof(msg));

    AES_SBOX sbox, sbox_inv;
    AES_GenerateSbox(&sbox);
    AES_GenerateSboxInv(&sbox_inv);

    AES_CTX ctx;

    AES_InitCtx(&ctx, &key, &iv, &sbox, &sbox_inv);
    AES_Encrypt(&ctx, buf, sizeof(buf));
    printf("[*] Encrypted message:\n");
    HexDump(buf, sizeof(buf));

    AES_InitCtx(&ctx, &key, &iv, &sbox, &sbox_inv);
    AES_Decrypt(&ctx, buf, sizeof(buf));
    printf("[*] Decrypted message:\n");
    HexDump(buf, sizeof(buf));

    if (memcmp(msg, buf, sizeof(msg))) {
        printf("Error: Decrypted message does not match original message\n");
        ret = 1;
        goto exit;
    }

exit:
    return ret;
}
