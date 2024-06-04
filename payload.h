#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#ifdef __cplusplus
EXTERN_C_START
#endif

__declspec(code_seg("injected")) VOID inj_code_c();

#ifdef __cplusplus
EXTERN_C_END
#endif

#endif
