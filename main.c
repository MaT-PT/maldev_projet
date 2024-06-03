#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include "libproc.h"

int main() {
#ifdef DEBUG
    // ListDll();
#endif

    PVOID pKernel32Dll = GetDll(L"KERNEL32.DLL");
    LOG("KERNEL32.DLL: %p", pKernel32Dll);

#ifdef DEBUG
    // ListFunc(pKernel32Dll);
#endif

    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetFunc(pKernel32Dll, "LoadLibraryA");
    LOG("LoadLibraryA: %p", pLoadLibraryA);

    HMODULE pUser32Dll = pLoadLibraryA("USER32.DLL");
    // PVOID pUser32Dll = GetDll(L"USER32.DLL");
    LOG("USER32.DLL: %p", pUser32Dll);

#ifdef DEBUG
    // ListFunc(pUser32Dll);
#endif

    MessageBoxA_t pMessageBoxA = (MessageBoxA_t)GetFunc(pUser32Dll, "MessageBoxA");
    LOG("MessageBoxA: %p", pMessageBoxA);

    int res = pMessageBoxA(NULL, "Hello, world!", "Hello", MB_OKCANCEL | MB_ICONINFORMATION);
    LOG("User clicked: %d", res);
    return 0;
}
