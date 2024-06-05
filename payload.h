#ifndef _PAYLOAD_H_
#define _PAYLOAD_H_

#include <Windows.h>

#ifdef __cplusplus
EXTERN_C_START
#endif

__declspec(code_seg("injected")) VOID inj_code_c();

#ifdef __cplusplus
EXTERN_C_END
#endif

#endif
