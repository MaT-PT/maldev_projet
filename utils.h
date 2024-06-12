#ifndef _UTILS_H_
#define _UTILS_H_

#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>

#define DWQUAD(x) ((x).QuadPart)
#define DWHIGH(x) ((x).HighPart)
#define DWLOW(x) ((x).LowPart)
#define DWHILO(x) DWHIGH(x), DWLOW(x)

#ifdef __cplusplus
EXTERN_C_START
#endif

typedef CONST VOID* PCVOID;
typedef CONST BYTE* PCBYTE;
typedef CONST WORD* PCWORD;
typedef CONST DWORD* PCDWORD;

typedef CONST TEB* PCTEB;
typedef CONST PEB* PCPEB;
typedef CONST PEB_LDR_DATA* PCPEB_LDR_DATA;
typedef CONST LIST_ENTRY* PCLIST_ENTRY;
typedef CONST LDR_DATA_TABLE_ENTRY* PCLDR_DATA_TABLE_ENTRY;
typedef CONST IMAGE_DOS_HEADER* PCIMAGE_DOS_HEADER;
typedef CONST IMAGE_NT_HEADERS64* PCIMAGE_NT_HEADERS64;
typedef CONST IMAGE_SECTION_HEADER* PCIMAGE_SECTION_HEADER;
typedef CONST IMAGE_DATA_DIRECTORY* PCIMAGE_DATA_DIRECTORY;
typedef CONST IMAGE_EXPORT_DIRECTORY* PCIMAGE_EXPORT_DIRECTORY;

VOID PrintError(IN CONST LPCSTR sFuncName);

VOID HexDump(IN CONST PCBYTE pBuf, IN CONST DWORD dwSize);

#ifdef __cplusplus
EXTERN_C_END
#endif

#endif
