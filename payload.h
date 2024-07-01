#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#include <Windows.h>
#include "injected.h"

EXTERN_C_START

/// @brief Payload C code entry point.
INJECTED_CODE VOID inj_code_c();

EXTERN_C_END

#endif  // _PAYLOAD_H_
