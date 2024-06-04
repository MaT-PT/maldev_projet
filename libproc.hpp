#ifndef _LIBPROC_H_
#define _LIBPROC_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

EXTERN_C_START

#ifdef DEBUG
#define LOG(fmt, ...)                             \
    do {                                          \
        printf("[DEBUG] " fmt "\n", __VA_ARGS__); \
    } while (0)
#else
#define LOG(fmt, ...) /* [No logging] */
#endif

#define MY_ROTL64(val, n) (((val) << (n)) | ((val) >> (-(n) & 63)))

#define NT_CURRENT_TEB() ((PTEB)__readgsqword(FIELD_OFFSET(NT_TIB, Self)))

typedef HMODULE (*LoadLibraryA_t)(IN LPCSTR lpLibFileName);
typedef int (*MessageBoxA_t)(IN OPTIONAL HWND hWnd, IN OPTIONAL LPCSTR lpText,
                             IN OPTIONAL LPCSTR lpCaption, IN UINT uType);

#pragma section("injected", read, execute)

__declspec(code_seg("injected")) PVOID GetDll(IN CONST ULONGLONG ullDllNameHash);
__declspec(code_seg("injected")) PVOID GetFunc(IN CONST PVOID pDllBase,
                                               IN CONST ULONGLONG ullFuncNameHash);

EXTERN_C_END

__declspec(code_seg("injected")) constexpr DWORD my_toupper(DWORD c) {
    if (c >= 'a' && c <= 'z') {
        return c & ~0x20;
    }
    return c;
}

__declspec(code_seg("injected")) constexpr ULONGLONG my_strhash(LPCSTR sName) {
    unsigned long long int hash = 0;
    while (*sName) {
        hash = MY_ROTL64(hash, 13) + my_toupper(*sName++);
    }
    return hash;
}

__declspec(code_seg("injected")) constexpr ULONGLONG my_strhash(LPCWSTR wsName) {
    unsigned long long int hash = 0;
    while (*wsName) {
        hash = MY_ROTL64(hash, 13) + my_toupper(*wsName++);
    }
    return hash;
}

template <ULONGLONG hash>
struct Hash {
    static constexpr ULONGLONG hash = hash;
};

#define STRHASH(s) (Hash<my_strhash(s)>::hash)

#endif
