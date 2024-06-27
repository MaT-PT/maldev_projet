#ifndef _UTILS_H_
#define _UTILS_H_

#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <winternl.h>

#define LIQUAD(x) ((x).QuadPart)      /* Large integer quad part */
#define LIHIGH(x) ((x).HighPart)      /* Large integer high 32-bit part */
#define LILOW(x)  ((x).LowPart)       /* Large integer low 32-bit part */
#define LIHILO(x) LIHIGH(x), LILOW(x) /* Large integer high and low parts, comma-separated */

#ifdef __cplusplus
#define __typeof decltype
#else  // __cplusplus
#define __typeof typeof
#endif  // __cplusplus

#define __ALIGN(x, mask) (((x) + (mask)) & ~(mask))          /* Align to `mask` (`0b11..11`) */
#define ALIGN(x, size)   __ALIGN(x, (__typeof(x))(size) - 1) /* Align to `size` (power of 2) */

EXTERN_C_START

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
typedef CONST IMAGE_FILE_HEADER* PCIMAGE_FILE_HEADER;
typedef CONST IMAGE_OPTIONAL_HEADER64* PCIMAGE_OPTIONAL_HEADER64;
typedef CONST IMAGE_SECTION_HEADER* PCIMAGE_SECTION_HEADER;
typedef CONST IMAGE_DATA_DIRECTORY* PCIMAGE_DATA_DIRECTORY;
typedef CONST IMAGE_EXPORT_DIRECTORY* PCIMAGE_EXPORT_DIRECTORY;

/**
 * @brief Print the last error code and message.
 *
 * @param sFuncName Function name
 */
VOID PrintError(IN CONST LPCSTR sFuncName);

/**
 * @brief Print a hex dump of a buffer.
 *
 * @param pBuf Buffer to dump
 * @param dwSize Buffer size
 */
VOID HexDump(IN CONST PCBYTE pBuf, IN CONST DWORD dwSize);

EXTERN_C_END

#endif  // _UTILS_H_
