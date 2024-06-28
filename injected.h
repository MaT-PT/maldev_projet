#ifndef _INJECTED_H_
#define _INJECTED_H_

#define __INJ_SEG "injected" /* Injected segment name */

// Create a new section for the injected code
#pragma section(__INJ_SEG, read, execute)

#define INJECTED_CODE __declspec(code_seg(__INJ_SEG)) /* Injected code */
#define INJECTED_VAR  __declspec(allocate(__INJ_SEG)) /* Injected data */

#endif  // _INJECTED_H_
