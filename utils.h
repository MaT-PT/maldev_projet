#ifndef _UTILS_H_
#define _UTILS_H_

#include <Windows.h>
#include <stdio.h>
#include <string.h>

#define DWQUAD(x) ((x).QuadPart)
#define DWHIGH(x) ((x).HighPart)
#define DWLOW(x) ((x).LowPart)
#define DWHILO(x) DWHIGH(x), DWLOW(x)

#ifdef __cplusplus
EXTERN_C_START
#endif

typedef CONST BYTE* PCBYTE;
typedef CONST VOID* PCVOID;

VOID PrintError(IN CONST LPCSTR sFuncName);

VOID HexDump(IN CONST PCBYTE pBuf, IN CONST DWORD dwSize);

#ifdef __cplusplus
EXTERN_C_END
#endif

#endif
