#ifndef _LIBPROC_H_
#define _LIBPROC_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

#ifdef DEBUG
#define LOG(fmt, ...)                             \
    do {                                          \
        printf("[DEBUG] " fmt "\n", __VA_ARGS__); \
    } while (0)
#else
#define LOG(fmt, ...) /* [No logging] */
#endif

typedef HMODULE (*LoadLibraryA_t)(IN LPCSTR lpLibFileName);
typedef int (*MessageBoxA_t)(IN OPTIONAL HWND hWnd, IN OPTIONAL LPCSTR lpText,
                             IN OPTIONAL LPCSTR lpCaption, IN UINT uType);

#ifdef DEBUG
VOID ListDll();
VOID ListFunc(IN CONST PVOID pDllBase);
#endif

#pragma section("injected", read, execute)

__declspec(code_seg("injected")) PVOID GetDll(IN CONST PCWSTR wsDllName);
__declspec(code_seg("injected")) PVOID GetFunc(IN CONST PVOID pDllBase, IN CONST PCSTR sFuncName);

#endif
