#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#include <Windows.h>

EXTERN_C_START

/// @brief Payload C code entry point.
__declspec(code_seg("injected")) VOID inj_code_c();

EXTERN_C_END

#ifdef PL_DEBUG
#define MSGBOX_DBG(text, title, type) pMessageBoxA(NULL, text, title, type)
#else                                 // PL_DEBUG
#define MSGBOX_DBG(text, title, type) /* [MsgBox disabled] */
#endif                                // PL_DEBUG

#endif  // _PAYLOAD_H_
