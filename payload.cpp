#include "payload.h"
#include <Windows.h>
#include "libproc.hpp"

__declspec(code_seg("injected")) VOID inj_code_c() {
    __declspec(allocate("injected")) static CONST auto user32_obf = Obfuscated("USER32.DLL");
    __declspec(allocate("injected")) static CONST auto mbTitle_obf = Obfuscated("Hello");
    __declspec(allocate("injected")) static CONST auto mbText_obf = Obfuscated("Hello, world!");
    Deobfuscator user32_deobf = Deobfuscator(user32_obf);
    Deobfuscator mbTitle_deobf = Deobfuscator(mbTitle_obf);
    Deobfuscator mbText_deobf = Deobfuscator(mbText_obf);

    CONST auto pKernel32Dll = GET_DLL(kernel32.dll);
    CONST auto pLoadLibraryA = GET_FUNC(pKernel32Dll, LoadLibraryA);
    CONST auto pUser32Dll = pLoadLibraryA(user32_deobf);
    CONST auto pMessageBoxA = GET_FUNC(pUser32Dll, MessageBoxA);
    pMessageBoxA(NULL, mbText_deobf, mbTitle_deobf, MB_OKCANCEL | MB_ICONINFORMATION);
}
