#ifndef _LIBPROC_H_
#define _LIBPROC_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <array>

#define OBF_KEY 0x42
#define OBF_ROT 3

EXTERN_C_START

#ifdef DEBUG
#define LOG(fmt, ...)                             \
    do {                                          \
        printf("[DEBUG] " fmt "\n", __VA_ARGS__); \
    } while (0)
#else
#define LOG(fmt, ...) /* [No logging] */
#endif

#define NT_CURRENT_TEB() ((PTEB)__readgsqword(FIELD_OFFSET(NT_TIB, Self)))

typedef HMODULE (*LoadLibraryA_t)(IN LPCSTR lpLibFileName);
typedef int (*MessageBoxA_t)(IN OPTIONAL HWND hWnd, IN OPTIONAL LPCSTR lpText,
                             IN OPTIONAL LPCSTR lpCaption, IN UINT uType);

#pragma section("injected", read, execute)

__declspec(code_seg("injected")) PVOID GetDll(IN CONST ULONGLONG ullDllNameHash);
__declspec(code_seg("injected")) PVOID GetFunc(IN CONST PVOID pDllBase,
                                               IN CONST ULONGLONG ullFuncNameHash);

EXTERN_C_END

#define MOD(x, n) (((x) % (n) + (n)) % (n))

#define MY_ROTL64(val, n) (((val) << MOD(n, 64)) | ((val) >> (-(n) & 63)))
#define MY_ROTR64(val, n) (((val) >> MOD(n, 64)) | ((val) << (-(n) & 63)))
#define MY_ROTL32(val, n) (((val) << MOD(n, 32)) | ((val) >> (-(n) & 31)))
#define MY_ROTR32(val, n) (((val) >> MOD(n, 32)) | ((val) << (-(n) & 31)))
#define MY_ROTL16(val, n) (((val) << MOD(n, 16)) | ((val) >> (-(n) & 15)))
#define MY_ROTR16(val, n) (((val) >> MOD(n, 16)) | ((val) << (-(n) & 15)))
#define MY_ROTL8(val, n) (((val) << MOD(n, 8)) | ((val) >> (-(n) & 7)))
#define MY_ROTR8(val, n) (((val) >> MOD(n, 8)) | ((val) << (-(n) & 7)))

__declspec(code_seg("injected")) constexpr DWORD my_toupper(DWORD c) {
    if (c >= 'a' && c <= 'z') {
        return c & ~0x20;
    }
    return c;
}

__declspec(code_seg("injected")) constexpr ULONGLONG my_strhash(LPCSTR sName) {
    ULONGLONG hash = 0;
    while (*sName) {
        hash = MY_ROTL64(hash, 13) + my_toupper(*sName++);
    }
    return hash;
}

__declspec(code_seg("injected")) constexpr ULONGLONG my_strhash(LPCWSTR wsName) {
    ULONGLONG hash = 0;
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

template <DWORD N>
__declspec(code_seg("injected")) consteval auto obfuscate(CONST CHAR (&data)[N]) {
    std::array<CHAR, N> result{};
    for (DWORD i = 0; i < N; ++i) {
        result[i] = MY_ROTL8(data[i] ^ OBF_KEY, OBF_ROT);
    }
    return result;
}

template <DWORD N>
struct Deobfuscator {
    CHAR data[N];
    __declspec(code_seg("injected")) Deobfuscator(CONST LPCSTR _data) {
        for (DWORD i = 0; i < N; ++i) {
            data[i] = MY_ROTR8(_data[i], OBF_ROT) ^ OBF_KEY;
        }
    }
};

#define OBFUSCATED(s) (Deobfuscator<sizeof(s)>(obfuscate(s).data()).data)

#endif
