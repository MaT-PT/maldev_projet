PUBLIC code_size
PUBLIC __payload_end

injected SEGMENT READ EXECUTE

    code_size LABEL DWORD
        dd 0

__payload_end:

injected ENDS

END
