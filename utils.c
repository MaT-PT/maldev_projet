#include "utils.h"
#include <Windows.h>
#include <stdio.h>
#include <string.h>

VOID PrintError(IN CONST LPCSTR sFuncName) {
    CONST DWORD dwErrId = GetLastError();
    printf("[ERR: %d] %s: ", dwErrId, sFuncName);

    if (dwErrId) {
        LPSTR lpMsgBuf;
        CONST DWORD dwRes = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, dwErrId, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&lpMsgBuf, 0, NULL);
        if (dwRes) {
            printf("%s\n", lpMsgBuf);
            LocalFree(lpMsgBuf);
        } else {
            printf("Unknown error\n");
        }
    } else {
        printf("Something went wrong\n");
    }
}

VOID HexDump(IN CONST PCBYTE pBuf, IN CONST DWORD dwSize) {
    if (!pBuf) {
        printf("[NULL]\n");
        return;
    }
    if (!dwSize) {
        printf("[EMPTY]\n");
        return;
    }

    for (DWORD i = 0; i < dwSize; i++) {
        if (i % 16 == 0) {
            printf("[%08x] ", i);
        }
        printf("%02hhX ", pBuf[i]);
        if (i % 16 == 15) {
            printf("| ");
            for (DWORD j = i - 15; j <= i; j++) {
                if (isprint(pBuf[j])) {
                    putchar(pBuf[j]);
                } else {
                    putchar('.');
                }
                if (j % 8 == 7) {
                    putchar(' ');
                }
            }
            putchar('\n');
        } else if (i % 8 == 7) {
            putchar(' ');
        }
    }

    if (dwSize % 16) {
        for (DWORD i = dwSize % 16; i < 16; i++) {
            printf("   ");
            if (i % 8 == 7 && i != 15) {
                putchar(' ');
            }
        }
        printf("| ");
        for (DWORD i = dwSize - (dwSize % 16); i < dwSize; i++) {
            if (isprint(pBuf[i])) {
                putchar(pBuf[i]);
            } else {
                putchar('.');
            }
            if (i % 8 == 7 && i != dwSize - 1) {
                putchar(' ');
            }
        }
    }
    putchar('\n');
}
