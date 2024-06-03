#ifndef _UTILS_H_
#define _UTILS_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <string.h>

typedef CONST BYTE* PCBYTE;
typedef CONST VOID* PCVOID;

VOID PrintError(IN CONST LPCSTR sFuncName);

VOID HexDump(IN CONST PCBYTE pBuf, IN CONST DWORD dwSize);

#endif
