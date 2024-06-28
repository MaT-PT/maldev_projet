#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "libaes.h"
#include "utils.h"

int main(VOID) {
    int ret = 0;
    ret = TestSbox();
    if (ret) {
        printf("Error: TestSbox failed\n");
        goto exit;
    }

    CONST BYTE key[] = {'T', 'h', 'i', 's', 'I', 's', 'A', '1',
                        '6', 'B', 'y', 't', 'e', 'K', 'e', 'y'};
    CONST AES_IV iv = {
        .b = {'T', 'h', 'i', 's', 'I', 's', 'A', '1', '6', 'B', 'y', 't', 'e', 'I', 'V', '!'}};
    CONST BYTE msg[] = {'T', 'h', 'i', 's', ' ', 'i', 's', ' ',
                        'a', ' ', 't', 'e', 's', 't', '!', '!'};

    BYTE buf[sizeof(msg)];
    memcpy(buf, msg, sizeof(msg));

    AES_CTX ctx;

    AES_init_ctx_iv(&ctx, (PCAES_KEY)key, &iv);
    AES_CBC_encrypt_buffer(&ctx, buf, sizeof(buf));
    HexDump(buf, sizeof(buf));

    AES_init_ctx_iv(&ctx, (PCAES_KEY)key, &iv);
    AES_CBC_decrypt_buffer(&ctx, buf, sizeof(buf));
    HexDump(buf, sizeof(buf));

    if (memcmp(msg, buf, sizeof(msg))) {
        printf("Error: Decrypted message does not match original message\n");
        ret = 1;
        goto exit;
    }

exit:
    return ret;
}
