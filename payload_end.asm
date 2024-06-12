PUBLIC signature
PUBLIC code_size

injected SEGMENT READ EXECUTE

    signature LABEL DWORD
        dd 0BAADC0DEh

    code_size LABEL DWORD
        dd 0

injected ENDS

END
