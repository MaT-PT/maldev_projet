PUBLIC code_size
PUBLIC __payload_end

injected SEGMENT READ EXECUTE

    ; Will be replaced by the size of the payload
    code_size LABEL DWORD
        dd 0

__payload_end:

injected ENDS

END
