#define WIN32_LEAN_AND_MEAN
#include "payload.h"
#include <Windows.h>
#include "libproc.hpp"

__declspec(code_seg("injected")) VOID inj_code_c() {
    __declspec(allocate("injected")) static CONST CHAR sUser32_name[] = "USER32.DLL";
    __declspec(allocate("injected")) static CONST CHAR sMbTitle[] = "Hello";
    __declspec(allocate("injected")) static CONST CHAR sMbText[] = "Hello, world!";

    CONST PVOID pKernel32Dll = GetDll(STRHASH(L"kernel32.dll"));
    CONST LoadLibraryA_t pLoadLibraryA =
        (LoadLibraryA_t)GetFunc(pKernel32Dll, STRHASH("LoadLibraryA"));
    CONST HMODULE pUser32Dll = pLoadLibraryA(sUser32_name);
    CONST MessageBoxA_t pMessageBoxA = (MessageBoxA_t)GetFunc(pUser32Dll, STRHASH("MessageBoxA"));
    pMessageBoxA(NULL, sMbText, sMbTitle, MB_OKCANCEL | MB_ICONINFORMATION);
}
