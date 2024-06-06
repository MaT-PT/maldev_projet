PUBLIC payload
PUBLIC to_c_code
PUBLIC delta2start

injected SEGMENT read execute

    payload PROC
        ; int 3
        call _next  ; push rip; jmp _next
    _next:
        pop rbp                                     ; rbp = rip
        sub rbp, _next - payload

        mov rbx, [rbp + (to_c_code - payload)]
        add rbx, rbp
        push rbp
        mov rbp, rsp
        call rbx
        mov rsp, rbp
        pop rbp

        mov rbx, [rbp + (delta2start - payload)]
        add rbx, rbp
        push rbp
        call rbx
        pop rbp
    payload ENDP

    to_c_code label QWORD
        dq 0

    delta2start label SQWORD
        dq 0

injected ENDS

END
