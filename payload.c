#define WIN32_LEAN_AND_MEAN
#include "payload.h"
#include <Windows.h>
#include "libproc.h"

__declspec(allocate("injected")) CONST WCHAR wsKernel32_name[] = L"kernel32.dll";
__declspec(allocate("injected")) CONST CHAR sLoadLibraryA_name[] = "LoadLibraryA";
__declspec(allocate("injected")) CONST CHAR sUser32_name[] = "USER32.DLL";
__declspec(allocate("injected")) CONST CHAR sMessageBoxA_name[] = "MessageBoxA";
__declspec(allocate("injected")) CONST CHAR sMbTitle[] = "Hello";
__declspec(allocate("injected")) CONST CHAR sMbText[] = "Hello, world!";

__declspec(code_seg("injected")) VOID inj_code_c() {
    PVOID pKernel32Dll = GetDll(wsKernel32_name);
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetFunc(pKernel32Dll, sLoadLibraryA_name);
    HMODULE pUser32Dll = pLoadLibraryA(sUser32_name);
    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)GetFunc(pUser32Dll, sMessageBoxA_name);
    pMessageBoxA(NULL, sMbText, sMbTitle, MB_OKCANCEL | MB_ICONINFORMATION);
}
